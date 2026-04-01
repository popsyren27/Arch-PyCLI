"""
Echo Plugin for Arch-PyCLI.

This plugin provides text echoing functionality with optional
simulated typing animation.

Features:
- Basic text echoing
- Simulated typing animation
- Input sanitization
- Resource exhaustion protection
- Comprehensive error handling

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from typing import Any, Dict, List, Optional

# =============================================================================
# CONFIGURATION
# =============================================================================

# Resource limits
MAX_MESSAGE_LENGTH: int = 10000  # Maximum message length
MIN_TYPING_DELAY: float = 0.0  # Minimum delay between characters
MAX_TYPING_DELAY: float = 0.5  # Maximum delay between characters
DEFAULT_TYPING_DELAY: float = 0.05  # Default delay

# Debug configuration
DEBUG_PREFIX: str = "[ECHO_PLUGIN]"
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

_logger: logging.Logger = logging.getLogger("ECHO_PLUGIN")
if not _logger.handlers:
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

_logger.info("[ECHO_PLUGIN] Echo plugin initialized")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _sanitize(text: str) -> str:
    """
    Sanitize input text by removing control characters.
    
    Args:
        text: Input text to sanitize
    
    Returns:
        Sanitized text with normalized whitespace
    """
    if not text:
        return ""
    
    # Remove non-printable/control characters
    cleaned: str = "".join(
        char for char in text
        if char.isprintable() or char in "\n\t\r"
    )
    
    # Normalize whitespace
    cleaned = " ".join(cleaned.split())
    
    return cleaned


def _type_out(
    text: str,
    delay: float = DEFAULT_TYPING_DELAY,
    out_stream: Optional[Any] = None
) -> None:
    """
    Output text character by character with delay.
    
    Args:
        text: Text to type out
        delay: Delay between characters in seconds
        out_stream: Output stream (default: stdout)
    """
    # Validate output stream
    if out_stream is None:
        out_stream = sys.stdout
    
    write_func = getattr(out_stream, "write", None)
    flush_func = getattr(out_stream, "flush", None)
    
    if not callable(write_func) or not callable(flush_func):
        out_stream = sys.stdout
        write_func = out_stream.write
        flush_func = out_stream.flush
    
    # Type each character
    for char in text:
        try:
            write_func(char)
            flush_func()
            time.sleep(delay)
        except Exception:
            # Abort on write failure
            _logger.exception("[ECHO_PLUGIN] Typing stream failed; aborting")
            break
    
    # Final newline
    try:
        write_func("\n")
        flush_func()
    except Exception:
        pass


# =============================================================================
# PLUGIN METADATA
# =============================================================================

PLUGIN_META: Dict[str, Any] = {
    "name": "echo",
    "description": "Echoes text input. Supports simulated typing animation.",
    "version": "0.1.0",
    "author": "Arch-PyCLI Team",
    "usage": "echo [-t|--type] <message>",
    "examples": [
        "echo hello world",
        "echo -t hello world  # With typing animation"
    ]
}


# =============================================================================
# MAIN EXECUTE FUNCTION
# =============================================================================

def execute(context: Dict[str, Any], *args: Any) -> str:
    """
    Echo plugin execution function.
    
    Echoes the provided message back to the caller. Optionally supports
    simulated typing animation for visual effect.
    
    Args:
        context: Execution context containing health and other metadata
        *args: Command arguments (first arg can be -t or --type for typing mode)
    
    Returns:
        The echoed message string
    
    Raises:
        RuntimeError: If health context is missing or system is critical
        ValueError: If message is empty or too long
    
    Example:
        >>> result = execute({"health": health_report}, "hello")
        >>> print(result)
        hello
    """
    # =====================================================================
    # CONTEXT VALIDATION
    # =====================================================================
    
    health: Optional[Dict[str, Any]] = context.get("health")
    
    if not isinstance(health, dict):
        _logger.error("[ECHO_PLUGIN] Invalid health context type")
        raise RuntimeError("ERR_MISSING_HEALTH_CONTEXT")
    
    # Check system health
    system_status: str = health.get("status", "UNKNOWN")
    if system_status == "CRITICAL":
        _logger.warning(
            "[ECHO_PLUGIN] System in CRITICAL state, rejecting command"
        )
        raise RuntimeError("ERR_SYSTEM_INSTABILITY")
    
    # =====================================================================
    # ARGUMENT PARSING
    # =====================================================================
    
    if not args:
        _logger.warning("[ECHO_PLUGIN] No arguments provided")
        raise ValueError("ERR_EMPTY_COMMAND_ARGS")
    
    args_list: List[Any] = list(args)
    
    # Check for typing mode flag
    typing_mode: bool = False
    if args_list and args_list[0] in ("-t", "--type"):
        typing_mode = True
        args_list = args_list[1:]
    
    # Check for remaining message
    if not args_list:
        _logger.warning("[ECHO_PLUGIN] No message after flags")
        raise ValueError("ERR_EMPTY_COMMAND_ARGS")
    
    # =====================================================================
    # MESSAGE PROCESSING
    # =====================================================================
    
    # Join arguments into message
    message: str = " ".join(str(arg) for arg in args_list)
    
    # Sanitize input
    message = _sanitize(message).strip()
    
    # Validate message is not empty after sanitization
    if not message:
        _logger.warning("[ECHO_PLUGIN] Message empty after sanitization")
        raise ValueError("ERR_EMPTY_MESSAGE")
    
    # Check message length
    if len(message) > MAX_MESSAGE_LENGTH:
        _logger.warning(
            "[ECHO_PLUGIN] Message too long: %d > %d",
            len(message),
            MAX_MESSAGE_LENGTH
        )
        raise ValueError("ERR_MESSAGE_TOO_LARGE")
    
    # =====================================================================
    # LATENCY CHECK
    # =====================================================================
    
    start_time: float = time.perf_counter()
    
    # Get internal latency for comparison
    try:
        internal_latency: float = float(health.get("internal_latency", 0.1))
    except (TypeError, ValueError):
        internal_latency = 0.1
    
    # Ensure valid latency value
    if internal_latency <= 0:
        internal_latency = 0.1
    
    # Calculate execution time
    execution_latency: float = time.perf_counter() - start_time
    
    # Log execution metrics
    _logger.info(
        "[ECHO_PLUGIN] Executing: latency=%.6fs, msg_len=%d, typing=%s",
        execution_latency,
        len(message),
        typing_mode
    )
    _debug_log(
        "Message: %s...",
        message[:50] if len(message) > 50 else message
    )
    
    # Check for high latency warning
    if execution_latency > internal_latency * 10:
        _logger.warning(
            "[ECHO_PLUGIN] High latency detected: %.6fs > %.6fs",
            execution_latency,
            internal_latency * 10
        )
        return f"[SYSTEM_WARNING] High Latency Detected: {message}"
    
    # =====================================================================
    # TYPING MODE EXECUTION
    # =====================================================================
    
    typing_thread: Optional[threading.Thread] = None
    
    if typing_mode:
        # Get typing delay from context
        try:
            delay: float = float(context.get("type_delay", DEFAULT_TYPING_DELAY))
        except (TypeError, ValueError):
            delay = DEFAULT_TYPING_DELAY
        
        # Clamp delay to valid range
        delay = max(MIN_TYPING_DELAY, min(delay, MAX_TYPING_DELAY))
        
        # Get output stream from context
        out_stream: Optional[Any] = context.get("output_stream")
        
        # Run typing in background thread to avoid blocking
        try:
            typing_thread = threading.Thread(
                target=_type_out,
                args=(message, delay, out_stream),
                daemon=True,
                name="EchoTypingThread"
            )
            typing_thread.start()
            
            _debug_log(
                "Started typing thread (delay=%.3f)",
                delay
            )
            
        except Exception as e:
            _logger.exception("[ECHO_PLUGIN] Failed to start typing thread")
            # Fallback to immediate output
            try:
                _type_out(message, delay=0.0, out_stream=out_stream)
            except Exception:
                pass
    
    # =====================================================================
    # RETURN RESULT
    # =====================================================================
    
    # Wait for typing thread to complete before returning
    # This ensures the typing animation finishes before the return value is printed
    if typing_thread is not None:
        try:
            typing_thread.join()
        except Exception:
            pass
    
    _logger.debug("[ECHO_PLUGIN] Returning message: %s", message[:50])
    return message


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "execute",
    "PLUGIN_META",
    "set_debug_mode",
]