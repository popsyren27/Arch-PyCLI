import sys
import time
import logging
import threading
from typing import Dict, Any


def _sanitize(text: str) -> str:
    # Remove non-printable/control characters and normalize whitespace
    cleaned = "".join(ch for ch in text if ch.isprintable())
    return " ".join(cleaned.split())


def _type_out(text: str, delay: float = 0.05, out_stream=None) -> None:
    if out_stream is None:
        out_stream = sys.stdout
    write = getattr(out_stream, "write", None)
    flush = getattr(out_stream, "flush", None)
    if not callable(write) or not callable(flush):
        out_stream = sys.stdout
        write = out_stream.write
        flush = out_stream.flush

    for ch in text:
        try:
            write(ch)
            flush()
            time.sleep(delay)
        except Exception:
            # If writing fails mid-typing, abort typing quietly
            logging.exception("Typing stream failed; aborting typing")
            break
    try:
        write("\n")
        flush()
    except Exception:
        pass

def execute(context: Dict[str, Any], *args) -> str:
    """Echo plugin that optionally types the message to the output stream.

    Usage:
      execute(ctx, "hi") -> returns "hi"
      execute(ctx, "-t", "hi") -> types "hi" to stdout (simulated keystrokes) and returns "hi"

    Typing behavior is controlled by the first arg flag `-t` or `--type` and the
    per-call delay is taken from `context.get('type_delay', 0.05)`.
    """

    health = context.get("health")
    if not isinstance(health, dict):
        raise RuntimeError("ERR_MISSING_HEALTH_CONTEXT")
    if health.get("status") == "CRITICAL":
        raise RuntimeError("ERR_SYSTEM_INSTABILITY")

    if len(args) == 0:
        raise ValueError("ERR_EMPTY_COMMAND_ARGS")

    typing_mode = False
    args_list = list(args)
    if args_list and args_list[0] in ("-t", "--type"):
        typing_mode = True
        args_list = args_list[1:]

    message = " ".join(str(arg) for arg in args_list)
    message = _sanitize(message).strip()

    # Bounds checks to avoid resource exhaustion
    MAX_MSG = 10000
    if len(message) > MAX_MSG:
        raise ValueError("ERR_MESSAGE_TOO_LARGE")

    start_time = time.perf_counter()
    execution_latency = time.perf_counter() - start_time

    logging.info("Echo executed. Latency: %.6fs. Msg Length: %d", execution_latency, len(message))

    try:
        internal_latency = float(health.get("internal_latency", 0.1))
    except Exception:
        internal_latency = 0.1
    if internal_latency <= 0:
        internal_latency = 0.1

    if execution_latency > internal_latency * 10:
        return f"[SYSTEM_WARNING] High Latency Detected: {message}"

    if typing_mode:
        try:
            delay = float(context.get("type_delay", 0.05))
        except Exception:
            delay = 0.05
        # clamp delay
        delay = max(0.0, min(0.5, delay))

        out_stream = context.get("output_stream")

        # Perform typing in a background thread to avoid blocking
        try:
            t = threading.Thread(target=_type_out, args=(message, delay, out_stream), daemon=True)
            t.start()
        except Exception:
            logging.exception("Failed to start typing thread; falling back to immediate output")
            try:
                _type_out(message, delay=0.0, out_stream=out_stream)
            except Exception:
                pass

    return message

"""
PLUGIN METADATA (Optional for Loader)
name: echo
description: Returns the input string. If the first argument is '-t' or '--type', it simulates typing the message to the output stream with a delay.
usage: execute(ctx, "hi") -> returns "hi"
"""