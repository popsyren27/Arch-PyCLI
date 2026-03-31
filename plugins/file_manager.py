"""
File Manager Plugin for Arch-PyCLI.

This plugin provides file operations using the secure storage system.

Features:
- Directory listing
- File reading and writing
- File creation and deletion
- File renaming
- Path validation
- Comprehensive error handling

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import json
import logging
import shlex
import sys
from typing import Any, Dict, List, Optional

# Import file manager from core
try:
    from core import file_manager as fm
except ImportError:
    fm = None


# =============================================================================
# CONFIGURATION
# =============================================================================

# Validation limits
MAX_CONTENT_SIZE: int = 10_000_000  # 10MB maximum content size

# Debug configuration
DEBUG_PREFIX: str = "[FILE_MANAGER_PLUGIN]"
_is_debug_mode: bool = False


def set_debug_mode(enabled: bool) -> None:
    """Enable or disable debug logging."""
    global _is_debug_mode
    _is_debug_mode = enabled


def _debug_log(message: str, *args: Any) -> None:
    """Internal debug logger that respects debug mode."""
    if _is_debug_mode:
        _logger.debug(f"{DEBUG_PREFIX} {message}", *args)


# =============================================================================
# SETUP LOGGING
# =============================================================================

_logger: logging.Logger = logging.getLogger("FILE_MANAGER_PLUGIN")
if not _logger.handlers:
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

_logger.info("[FILE_MANAGER_PLUGIN] File manager plugin initialized")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _ensure_health(context: Dict[str, Any]) -> None:
    """
    Ensure health context is valid.
    
    Args:
        context: Execution context
    
    Raises:
        RuntimeError: If health context is invalid
    """
    health: Optional[Dict[str, Any]] = context.get("health")
    
    if not isinstance(health, dict):
        _logger.error("[FILE_MANAGER_PLUGIN] Invalid health context")
        raise RuntimeError("ERR_MISSING_HEALTH_CONTEXT")
    
    if health.get("status") == "CRITICAL":
        _logger.warning("[FILE_MANAGER_PLUGIN] System in CRITICAL state")
        raise RuntimeError("ERR_SYSTEM_INSTABILITY")


def _fmt_list(entries: List[Dict[str, Any]]) -> str:
    """
    Format directory entries for display.
    
    Args:
        entries: List of entry dictionaries
    
    Returns:
        Formatted string
    """
    if not entries:
        return "(empty directory)"
    
    lines: List[str] = []
    for entry in entries:
        typ: str = "DIR" if entry.get("is_dir") else "FILE"
        size: int = entry.get("size", 0)
        path: str = entry.get("path", "")
        lines.append(f"{typ:4}  {size:8}  {path}")
    
    return "\n".join(lines)


def _validate_path(path: str) -> None:
    """
    Validate a path for security.
    
    Args:
        path: Path to validate
    
    Raises:
        ValueError: If path is invalid
    """
    if not path:
        raise ValueError("ERR_INVALID_PATH")
    
    # Check for absolute paths
    if path.startswith("/"):
        raise ValueError("ERR_INVALID_PATH: Absolute paths not allowed")
    
    # Check for path traversal
    if ".." in path:
        raise ValueError("ERR_INVALID_PATH: Path traversal not allowed")


def _run_command(context: Dict[str, Any], argv: List[str]) -> str:
    """
    Run a file manager command.
    
    Args:
        context: Execution context
        argv: Command arguments
    
    Returns:
        Command result string
    
    Raises:
        ValueError: If command is invalid
        RuntimeError: If operation fails
    """
    # Check dependencies
    if fm is None:
        raise RuntimeError("ERR_FILE_MANAGER_UNAVAILABLE")
    
    # Show help if no arguments
    if not argv:
        return execute.__doc__ or "File manager plugin"
    
    # Get command
    cmd: str = argv[0]
    
    _debug_log("Command: %s", cmd)
    
    try:
        # List command
        if cmd == "list":
            path: str = argv[1] if len(argv) > 1 else "."
            _validate_path(path)
            entries: List[Dict[str, Any]] = fm.list_dir(path)
            return _fmt_list(entries)
        
        # Read command
        if cmd == "read":
            if len(argv) < 2:
                raise ValueError("read requires a path")
            path = argv[1]
            _validate_path(path)
            content: Any = fm.read_file(path)
            if isinstance(content, bytes):
                return content.decode("utf-8", errors="replace")
            return content
        
        # Write command
        if cmd == "write":
            if len(argv) < 2:
                raise ValueError("write requires a path")
            path = argv[1]
            _validate_path(path)
            content = " ".join(argv[2:]) if len(argv) > 2 else ""
            if len(content) > MAX_CONTENT_SIZE:
                raise ValueError("ERR_CONTENT_TOO_LARGE")
            fm.write_file(path, content, overwrite=True)
            return "OK"
        
        # Create command
        if cmd == "create":
            if len(argv) < 2:
                raise ValueError("create requires a path")
            path = argv[1]
            _validate_path(path)
            content = " ".join(argv[2:]) if len(argv) > 2 else ""
            if len(content) > MAX_CONTENT_SIZE:
                raise ValueError("ERR_CONTENT_TOO_LARGE")
            fm.create_file(path, content, exist_ok=True)
            return "OK"
        
        # Delete command
        if cmd == "delete":
            if len(argv) < 2:
                raise ValueError("delete requires a path")
            path = argv[1]
            _validate_path(path)
            recursive: bool = "--recursive" in argv or "-r" in argv
            fm.delete_file(path, recursive=recursive)
            return "OK"
        
        # Rename command
        if cmd == "rename":
            if len(argv) < 3:
                raise ValueError("rename requires src and dst")
            src: str = argv[1]
            dst: str = argv[2]
            _validate_path(src)
            _validate_path(dst)
            fm.rename(src, dst, overwrite=True)
            return "OK"
        
        # Exists command
        if cmd == "exists":
            if len(argv) < 2:
                raise ValueError("exists requires a path")
            path = argv[1]
            _validate_path(path)
            exists: bool = fm.exists(path)
            return json.dumps({"exists": exists})
        
        # Help command
        if cmd in ("help", "--help", "-h"):
            return execute.__doc__ or "File manager plugin"
        
        # Unknown command
        raise ValueError(f"ERR_UNKNOWN_SUBCOMMAND: {cmd}")
    
    except fm.FileManagerError as e:
        _logger.exception("[FILE_MANAGER_PLUGIN] File manager error")
        raise RuntimeError(f"FM_ERROR: {e}")


# =============================================================================
# PLUGIN METADATA
# =============================================================================

PLUGIN_META: Dict[str, Any] = {
    "name": "file_manager",
    "description": "File operations using secure encrypted storage.",
    "version": "0.1.0",
    "author": "Arch-PyCLI Team",
    "usage": "file_manager [list|read|write|create|delete|rename|exists] [args]",
    "examples": [
        "file_manager list",
        "file_manager read myfile.txt",
        "file_manager write myfile.txt Hello World",
        "file_manager create newfile.txt Content here",
        "file_manager delete myfile.txt",
        "file_manager rename old.txt new.txt",
        "file_manager exists myfile.txt"
    ]
}


# =============================================================================
# MAIN EXECUTE FUNCTION
# =============================================================================

def execute(context: Dict[str, Any], *args: Any) -> str:
    """
    File manager plugin execution function.
    
    Provides file operations on the encrypted storage:
        - list: List directory contents
        - read: Read a file
        - write: Write content to a file
        - create: Create a new file
        - delete: Delete a file
        - rename: Rename a file
        - exists: Check if a file exists
    
    Usage (non-interactive):
        file_manager list [path]
        file_manager read path
        file_manager write path content
        file_manager create path [content]
        file_manager delete path [-r|--recursive]
        file_manager rename src dst
        file_manager exists path
    
    Interactive mode:
        execute(ctx) -> enters a `file_manager>` REPL
        Type `exit` or `quit` to leave the REPL.
    
    Args:
        context: Execution context containing health and other metadata
        *args: Command arguments
    
    Returns:
        Command result string
    
    Raises:
        RuntimeError: If health context is invalid or operations fail
        ValueError: If command arguments are invalid
    """
    # =====================================================================
    # CONTEXT VALIDATION
    # =====================================================================
    
    _ensure_health(context)
    
    # Check dependencies
    if fm is None:
        _logger.error("[FILE_MANAGER_PLUGIN] File manager not available")
        raise RuntimeError("ERR_FILE_MANAGER_UNAVAILABLE")
    
    # =====================================================================
    # INTERACTIVE MODE (no arguments)
    # =====================================================================
    
    if not args:
        return _interactive_mode(context)
    
    # =====================================================================
    # NON-INTERACTIVE MODE
    # =====================================================================
    
    # Convert args to list
    argv: List[str] = list(args)
    
    # Handle JSON arrays from network calls
    if len(argv) == 1 and argv[0].startswith("["):
        try:
            parsed: List[str] = json.loads(argv[0])
            if isinstance(parsed, list):
                argv = parsed
        except json.JSONDecodeError:
            pass
    
    _logger.info(
        "[FILE_MANAGER_PLUGIN] Executing: %s",
        argv[0] if argv else "empty"
    )
    
    return _run_command(context, argv)


def _interactive_mode(context: Dict[str, Any]) -> str:
    """
    Run file manager in interactive REPL mode.
    
    Args:
        context: Execution context
    
    Returns:
        "OK" on exit
    """
    # Get output stream
    out: Any = context.get("output_stream", sys.stdout)
    
    # Show welcome message
    out.write("Entering file_manager REPL. Type 'help' for commands, 'exit' to quit.\n")
    out.flush()
    
    _logger.info("[FILE_MANAGER_PLUGIN] Entered interactive mode")
    
    # REPL loop
    while True:
        try:
            # Show prompt
            out.write("file_manager> ")
            out.flush()
            
            # Read input
            line: str = sys.stdin.readline()
            
            if not line:
                # EOF
                break
            
            line = line.strip()
            
            if not line:
                continue
            
            # Handle exit
            if line in ("exit", "quit"):
                break
            
            # Parse command
            try:
                argv: List[str] = shlex.split(line)
            except Exception:
                argv = line.split()
            
            # Execute command
            try:
                result: str = _run_command(context, argv)
                if result is not None:
                    out.write(str(result) + "\n")
                    out.flush()
            except Exception as e:
                out.write(f"Error: {e}\n")
                out.flush()
        
        except KeyboardInterrupt:
            out.write("\nInterrupted. Type 'exit' to leave.\n")
            out.flush()
            continue
        except EOFError:
            break
        except Exception as e:
            _logger.exception("[FILE_MANAGER_PLUGIN] REPL error")
            out.write(f"Error: {e}\n")
            out.flush()
    
    _logger.info("[FILE_MANAGER_PLUGIN] Exited interactive mode")
    return "OK"


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "execute",
    "PLUGIN_META",
    "set_debug_mode",
]
