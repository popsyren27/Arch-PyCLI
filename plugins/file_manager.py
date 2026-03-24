import json
import logging
import shlex
import sys
from typing import Any, Dict, List

from core import file_manager as fm


def _ensure_health(context: Dict[str, Any]) -> None:
    health = context.get("health")
    if not isinstance(health, dict):
        raise RuntimeError("ERR_MISSING_HEALTH_CONTEXT")
    if health.get("status") == "CRITICAL":
        raise RuntimeError("ERR_SYSTEM_INSTABILITY")


def _fmt_list(entries: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for e in entries:
        typ = "DIR" if e.get("is_dir") else "FILE"
        lines.append(f"{typ:4}  {e.get('size',0):8}  {e.get('path')}")
    return "\n".join(lines)


def _run_command(context: Dict[str, Any], argv: List[str]) -> str:
    if not argv:
        return execute.__doc__

    cmd = argv[0]
    try:
        if cmd == "list":
            path = argv[1] if len(argv) > 1 else "."
            if path.startswith("/") or ".." in path:
                raise ValueError("ERR_INVALID_PATH")
            entries = fm.list_dir(path)
            return _fmt_list(entries)

        if cmd == "read":
            if len(argv) < 2:
                raise ValueError("read requires a path")
            path = argv[1]
            if path.startswith("/") or ".." in path:
                raise ValueError("ERR_INVALID_PATH")
            content = fm.read_file(path)
            if isinstance(content, bytes):
                return content.decode("utf-8", errors="replace")
            return content

        if cmd in ("write", "create"):
            if len(argv) < 2:
                raise ValueError(f"{cmd} requires a path")
            path = argv[1]
            if path.startswith("/") or ".." in path:
                raise ValueError("ERR_INVALID_PATH")
            # join remaining args into the content so multi-word input is preserved
            content = " ".join(argv[2:]) if len(argv) > 2 else ""
            if len(content) > 10_000_000:
                raise ValueError("ERR_CONTENT_TOO_LARGE")
            if cmd == "create":
                fm.create_file(path, content, exist_ok=True)
            else:
                fm.write_file(path, content, overwrite=True)
            return "OK"

        if cmd == "delete":
            if len(argv) < 2:
                raise ValueError("delete requires a path")
            path = argv[1]
            if path.startswith("/") or ".." in path:
                raise ValueError("ERR_INVALID_PATH")
            recursive = "--recursive" in argv or "-r" in argv
            fm.delete_file(path, recursive=recursive)
            return "OK"

        if cmd == "rename":
            if len(argv) < 3:
                raise ValueError("rename requires src and dst")
            src = argv[1]
            dst = argv[2]
            if src.startswith("/") or dst.startswith("/") or ".." in src or ".." in dst:
                raise ValueError("ERR_INVALID_PATH")
            fm.rename(src, dst, overwrite=True)
            return "OK"

        if cmd == "exists":
            if len(argv) < 2:
                raise ValueError("exists requires a path")
            path = argv[1]
            if path.startswith("/") or ".." in path:
                raise ValueError("ERR_INVALID_PATH")
            return json.dumps({"exists": fm.exists(path)})

        if cmd in ("help", "--help", "-h"):
            return execute.__doc__

        raise ValueError(f"ERR_UNKNOWN_SUBCOMMAND: {cmd}")

    except fm.FileManagerError as e:
        logging.exception("File manager error")
        raise RuntimeError(f"FM_ERROR: {e}")


def execute(context: Dict[str, Any], *args) -> str:
    """File manager plugin.

    Usage (non-interactive):
      execute(ctx, "list", [path])
      execute(ctx, "read", path)

    Interactive mode:
      execute(ctx) -> enters a `file_manager>` REPL where you may run the same subcommands
      Type `exit` or `quit` to leave the REPL.
    """

    _ensure_health(context)

    # Interactive mode: no args -> open REPL
    if not args:
        out = context.get("output_stream", sys.stdout)
        out.write("Entering file_manager REPL. Type 'help' for commands, 'exit' to quit.\n")
        out.flush()
        while True:
            try:
                out.write("file_manager> ")
                out.flush()
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                if line in ("exit", "quit"):
                    break
                try:
                    argv = shlex.split(line)
                except Exception:
                    argv = line.split()
                try:
                    res = _run_command(context, argv)
                    if res is not None:
                        out.write(str(res) + "\n")
                        out.flush()
                except Exception as e:
                    out.write(f"Error: {e}\n")
                    out.flush()
            except KeyboardInterrupt:
                out.write("\nInterrupted. Type 'exit' to leave.\n")
                out.flush()
                continue
        return "OK"

    # Non-interactive: treat args as command
    argv = list(args)
    return _run_command(context, argv)
