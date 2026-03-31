"""
Network Plugin for Arch-PyCLI.

This plugin provides network-related functionality including
token generation and remote command execution.

Features:
- Token generation for authentication
- Remote command execution
- Async command support
- Comprehensive input validation
- Error handling

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import logging
import socket
import sys
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

# Import security kernel for token operations
try:
    from core.security import SEC_KERNEL
except ImportError:
    SEC_KERNEL = None

# Import network node for remote commands
try:
    from core.network import NETWORK_NODE
except ImportError:
    NETWORK_NODE = None


# =============================================================================
# CONFIGURATION
# =============================================================================

# Token defaults
DEFAULT_TOKEN_TTL: int = 900  # 15 minutes in seconds

# Validation limits
MAX_TOKEN_LENGTH: int = 1024  # Maximum token string length
MAX_COMMAND_LENGTH: int = 10000  # Maximum command string length
MAX_HOST_LENGTH: int = 255  # Maximum hostname length
MIN_PORT: int = 1  # Minimum port number
MAX_PORT: int = 65535  # Maximum port number

# Debug configuration
DEBUG_PREFIX: str = "[NET_PLUGIN]"
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

_logger: logging.Logger = logging.getLogger("NET_PLUGIN")
if not _logger.handlers:
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

_logger.info("[NET_PLUGIN] Network plugin initialized")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _validate_host(host: str) -> bool:
    """
    Validate a hostname or IP address.
    
    Args:
        host: Host string to validate
    
    Returns:
        True if valid, False otherwise
    """
    if not host or len(host) > MAX_HOST_LENGTH:
        return False
    
    # Basic validation - can be improved with regex for FQDN/IP
    return True


def _validate_port(port: int) -> bool:
    """
    Validate a port number.
    
    Args:
        port: Port number to validate
    
    Returns:
        True if valid, False otherwise
    """
    return MIN_PORT <= port <= MAX_PORT


def _validate_token(token: str) -> bool:
    """
    Validate a token string.
    
    Args:
        token: Token to validate
    
    Returns:
        True if valid, False otherwise
    """
    if not token or len(token) > MAX_TOKEN_LENGTH:
        return False
    return True


def _validate_command(command: str) -> bool:
    """
    Validate a command string.
    
    Args:
        command: Command to validate
    
    Returns:
        True if valid, False otherwise
    """
    if not command or len(command) > MAX_COMMAND_LENGTH:
        return False
    return True


# =============================================================================
# PLUGIN METADATA
# =============================================================================

PLUGIN_META: Dict[str, Any] = {
    "name": "net",
    "description": "Network controller for authentication and remote commands.",
    "version": "0.1.0",
    "author": "Arch-PyCLI Team",
    "usage": "net [auth|send] [options]",
    "examples": [
        "net auth",
        "net send 127.0.0.1 9001 <token> echo hello",
        "net send -a 127.0.0.1 9001 <token> status"
    ]
}


# =============================================================================
# MAIN EXECUTE FUNCTION
# =============================================================================

def execute(context: Dict[str, Any], *args: Any) -> str:
    """
    Network plugin execution function.
    
    Provides network-related operations:
        - auth: Generate a short-lived access token
        - send: Send a command to a remote node
    
    Args:
        context: Execution context containing health and other metadata
        *args: Command arguments
    
    Returns:
        Result string (token or response)
    
    Raises:
        ValueError: If arguments are invalid or missing
    
    Example:
        >>> # Generate token
        >>> result = execute({"health": {}}, "auth")
        >>> # Send remote command
        >>> result = execute({"health": {}}, "send", "127.0.0.1", "9001", token, "echo", "hi")
    """
    # =====================================================================
    # ARGUMENT VALIDATION
    # =====================================================================
    
    if not args:
        _logger.warning("[NET_PLUGIN] No arguments provided")
        raise ValueError("ERR_USAGE: net [auth | send]")
    
    # Convert args to list
    args_list: List[str] = list(args)
    
    # Get subcommand
    subcommand: str = str(args_list[0]).lower().strip()
    
    _debug_log("Processing subcommand: %s", subcommand)
    
    # =====================================================================
    # AUTH SUBCOMMAND
    # =====================================================================
    
    if subcommand == "auth":
        return _handle_auth(context)
    
    # =====================================================================
    # SEND SUBCOMMAND
    # =====================================================================
    
    if subcommand == "send":
        return _handle_send(context, args_list[1:])
    
    # =====================================================================
    # UNKNOWN SUBCOMMAND
    # =====================================================================
    
    _logger.warning("[NET_PLUGIN] Unknown subcommand: %s", subcommand)
    raise ValueError(f"ERR_UNKNOWN_NET_SUBCOMMAND: {subcommand}")


def _handle_auth(context: Dict[str, Any]) -> str:
    """
    Handle the 'auth' subcommand.
    
    Generates a short-lived access token for network operations.
    
    Args:
        context: Execution context
    
    Returns:
        Token response string
    
    Raises:
        RuntimeError: If token generation fails
    """
    _logger.info("[NET_PLUGIN] Generating access token")
    
    # Check if security kernel is available
    if SEC_KERNEL is None:
        _logger.error("[NET_PLUGIN] Security kernel not available")
        raise RuntimeError("ERR_SEC_KERNEL_UNAVAILABLE")
    
    # Check network node availability for subject
    subject: str = "local"
    if NETWORK_NODE is not None:
        try:
            subject = str(NETWORK_NODE.node_id)
        except Exception:
            pass
    
    try:
        # Generate token with default TTL
        token: str = SEC_KERNEL.generate_short_lived_token(
            subject=subject,
            ttl=DEFAULT_TOKEN_TTL
        )
        
        _logger.info(
            "[NET_PLUGIN] Token generated for %s (ttl=%ds)",
            subject,
            DEFAULT_TOKEN_TTL
        )
        
        return f"ACCESS_TOKEN: {token}\nVALID_FOR: {DEFAULT_TOKEN_TTL} seconds"
        
    except Exception as e:
        _logger.exception("[NET_PLUGIN] Token generation failed")
        raise RuntimeError(f"ERR_TOKEN_GENERATION_FAILED: {e}")


def _handle_send(context: Dict[str, Any], args: List[str]) -> str:
    """
    Handle the 'send' subcommand.
    
    Sends a command to a remote node.
    
    Args:
        context: Execution context
        args: Arguments (ip, port, token, command...)
    
    Returns:
        Response from remote node
    
    Raises:
        ValueError: If arguments are invalid
    """
    # =====================================================================
    # PARSE ARGUMENTS
    # =====================================================================
    
    # Check for async flag
    async_mode: bool = False
    idx: int = 0
    
    if args and args[0] in ("-a", "--async"):
        async_mode = True
        idx = 1
    
    # Validate minimum arguments
    if len(args) <= idx + 3:
        _logger.warning("[NET_PLUGIN] Insufficient arguments for send")
        raise ValueError("ERR_USAGE: net send [-a] [ip] [port] [token] [command]")
    
    # Parse arguments
    try:
        target_ip: str = str(args[idx])
        target_port: int = int(args[idx + 1])
        remote_token: str = str(args[idx + 2])
        remote_command: str = " ".join(args[idx + 3:])
        
    except (ValueError, IndexError) as e:
        _logger.warning("[NET_PLUGIN] Invalid argument parsing: %s", e)
        raise ValueError("ERR_INVALID_ARGUMENTS")
    
    # =====================================================================
    # VALIDATE INPUTS
    # =====================================================================
    
    # Validate IP/hostname
    if not _validate_host(target_ip):
        _logger.warning("[NET_PLUGIN] Invalid host: %s", target_ip)
        raise ValueError("ERR_INVALID_HOST")
    
    # Validate port
    if not _validate_port(target_port):
        _logger.warning("[NET_PLUGIN] Invalid port: %d", target_port)
        raise ValueError("ERR_INVALID_PORT")
    
    # Validate token
    if not _validate_token(remote_token):
        _logger.warning("[NET_PLUGIN] Invalid token length")
        raise ValueError("ERR_INVALID_TOKEN")
    
    # Validate command
    if not _validate_command(remote_command):
        _logger.warning("[NET_PLUGIN] Invalid command length")
        raise ValueError("ERR_COMMAND_TOO_LARGE")
    
    _logger.info(
        "[NET_PLUGIN] Preparing remote command to %s:%d (async=%s)",
        target_ip,
        target_port,
        async_mode
    )
    _debug_log(
        "Command: %s (len=%d)",
        remote_command[:50],
        len(remote_command)
    )
    
    # =====================================================================
    # CHECK NETWORK NODE AVAILABILITY
    # =====================================================================
    
    if NETWORK_NODE is None:
        _logger.error("[NET_PLUGIN] Network node not available")
        return "ERR_NETWORK_NODE_UNAVAILABLE"
    
    # =====================================================================
    # EXECUTE COMMAND
    # =====================================================================
    
    if async_mode:
        return _execute_async(
            target_ip,
            target_port,
            remote_token,
            remote_command
        )
    else:
        return _execute_sync(
            target_ip,
            target_port,
            remote_token,
            remote_command
        )


def _execute_async(
    target_ip: str,
    target_port: int,
    token: str,
    command: str
) -> str:
    """
    Execute command asynchronously.
    
    Args:
        target_ip: Target IP address
        target_port: Target port
        token: Authentication token
        command: Command to execute
    
    Returns:
        Job scheduled message with job ID
    """
    job_id: str = str(uuid.uuid4())
    
    def _do_send() -> None:
        """Background task to send command."""
        try:
            response = NETWORK_NODE.send_remote_cmd(
                target_ip,
                target_port,
                token,
                command
            )
            _logger.info(
                "[NET_PLUGIN] Async send result to %s:%s -> %s",
                target_ip,
                target_port,
                response[:100]
            )
        except Exception as e:
            _logger.exception(
                "[NET_PLUGIN] Async send failed to %s:%s",
                target_ip,
                target_port
            )
    
    # Start background thread
    try:
        t: threading.Thread = threading.Thread(
            target=_do_send,
            daemon=True,
            name=f"AsyncNetSend-{job_id[:8]}"
        )
        t.start()
        
        _logger.info(
            "[NET_PLUGIN] Async job scheduled: %s",
            job_id
        )
        
        return f"JOB_SCHEDULED: {job_id}"
        
    except Exception as e:
        _logger.exception("[NET_PLUGIN] Failed to start async thread")
        return f"ERR_ASYNC_FAILED: {e}"


def _execute_sync(
    target_ip: str,
    target_port: int,
    token: str,
    command: str
) -> str:
    """
    Execute command synchronously.
    
    Args:
        target_ip: Target IP address
        target_port: Target port
        token: Authentication token
        command: Command to execute
    
    Returns:
        Response from remote node
    """
    try:
        # Execute synchronous send
        response: str = NETWORK_NODE.send_remote_cmd(
            target_ip,
            target_port,
            token,
            command
        )
        
        _logger.info(
            "[NET_PLUGIN] Remote send completed: %s",
            response[:50] if len(response) > 50 else response
        )
        
        # Limit response length
        if isinstance(response, str) and len(response) > 20000:
            _logger.warning(
                "[NET_PLUGIN] Response too large (%d bytes), truncating",
                len(response)
            )
            return "REMOTE_RESPONSE_TOO_LARGE"
        
        # Check for error responses
        if response.startswith("REMOTE_ERROR:"):
            return response
        
        if response.startswith("Node Connection Failed:"):
            return response
        
        return f"REMOTE_RESPONSE: {response}"
        
    except socket.timeout:
        _logger.warning(
            "[NET_PLUGIN] Send timeout to %s:%d",
            target_ip,
            target_port
        )
        return "REMOTE_ERROR: Connection timeout"
        
    except socket.gaierror as e:
        _logger.warning(
            "[NET_PLUGIN] DNS resolution failed for %s: %s",
            target_ip,
            e
        )
        return f"REMOTE_ERROR: DNS resolution failed - {e}"
        
    except ConnectionRefusedError:
        _logger.warning(
            "[NET_PLUGIN] Connection refused to %s:%d",
            target_ip,
            target_port
        )
        return "REMOTE_ERROR: Connection refused"
        
    except Exception as e:
        _logger.exception("[NET_PLUGIN] Remote command failed")
        return f"REMOTE_ERROR: {e}"


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "execute",
    "PLUGIN_META",
    "set_debug_mode",
]
