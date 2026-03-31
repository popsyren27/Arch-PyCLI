"""
Vault Plugin for Arch-PyCLI.

This plugin provides secure key-value storage using the secure store.

Features:
- Secure value storage
- Encrypted at rest
- Key validation
- Memory secure wiping
- Comprehensive error handling

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Dict, Optional

# Import secure store for encrypted storage
try:
    from core import secure_store as ss
except ImportError:
    ss = None

# Import security kernel for memory wiping
try:
    from core.security import SEC_KERNEL
except ImportError:
    SEC_KERNEL = None


# =============================================================================
# CONFIGURATION
# =============================================================================

# Validation limits
MAX_KEY_LENGTH: int = 128  # Maximum key name length
MAX_VALUE_LENGTH: int = 10 * 1024 * 1024  # 10MB maximum value

# Valid key characters
VALID_KEY_CHARS: set = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")

# Debug configuration
DEBUG_PREFIX: str = "[VAULT_PLUGIN]"
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

_logger: logging.Logger = logging.getLogger("VAULT_PLUGIN")
if not _logger.handlers:
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

_logger.info("[VAULT_PLUGIN] Vault plugin initialized")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _clean_key(key: str) -> str:
    """
    Clean and validate a key name.
    
    Keys are restricted to alphanumeric characters, dashes, and underscores.
    
    Args:
        key: Raw key string
    
    Returns:
        Cleaned key string
    
    Example:
        >>> _clean_key("my-key_123")
        'my-key_123'
    """
    if not key:
        return ""
    
    # Filter to valid characters
    cleaned: str = "".join(
        char for char in key
        if char in VALID_KEY_CHARS
    )
    
    # Limit length
    return cleaned[:MAX_KEY_LENGTH]


def _secure_wipe(value: Any) -> None:
    """
    Securely wipe a value from memory.
    
    Args:
        value: Value to wipe
    """
    if SEC_KERNEL is not None:
        try:
            SEC_KERNEL._wipe_memory(value)
        except Exception:
            pass


# =============================================================================
# PLUGIN METADATA
# =============================================================================

PLUGIN_META: Dict[str, Any] = {
    "name": "vault",
    "description": "Secure key-value storage backed by encrypted storage.",
    "version": "0.1.0",
    "author": "Arch-PyCLI Team",
    "usage": "vault [set|get] <key> [value]",
    "examples": [
        "vault set mykey myvalue",
        "vault get mykey"
    ]
}


# =============================================================================
# MAIN EXECUTE FUNCTION
# =============================================================================

def execute(context: Dict[str, Any], *args: Any) -> str:
    """
    Vault plugin execution function.
    
    Provides secure key-value storage operations:
        - set: Store a value securely
        - get: Retrieve a stored value
    
    Args:
        context: Execution context containing health and other metadata
        *args: Command arguments (action, key, value)
    
    Returns:
        Result string
    
    Raises:
        ValueError: If arguments are invalid or missing
        RuntimeError: If vault operations fail
    
    Example:
        >>> # Store a value
        >>> execute({}, "set", "api_key", "secret123")
        '[SECURE] Field api_key encrypted and persisted.'
        >>> # Retrieve a value
        >>> execute({}, "get", "api_key")
        'VAULT_DECRYPTED [api_key]: secret123'
    """
    # =====================================================================
    # ARGUMENT VALIDATION
    # =====================================================================
    
    if not args or len(args) < 1:
        _logger.warning("[VAULT_PLUGIN] No arguments provided")
        raise ValueError("ERR_USAGE: vault [set|get] ...")
    
    # Get action
    action: str = str(args[0]).lower().strip()
    
    _debug_log("Processing action: %s", action)
    
    # =====================================================================
    # CHECK DEPENDENCIES
    # =====================================================================
    
    if ss is None:
        _logger.error("[VAULT_PLUGIN] Secure store not available")
        raise RuntimeError("ERR_SECURE_STORE_UNAVAILABLE")
    
    # =====================================================================
    # SET ACTION
    # =====================================================================
    
    if action == "set":
        return _handle_set(args[1:])
    
    # =====================================================================
    # GET ACTION
    # =====================================================================
    
    if action == "get":
        return _handle_get(args[1:])
    
    # =====================================================================
    # UNKNOWN ACTION
    # =====================================================================
    
    _logger.warning("[VAULT_PLUGIN] Unknown action: %s", action)
    raise ValueError("ERR_UNKNOWN_VAULT_ACTION")


def _handle_set(args: tuple) -> str:
    """
    Handle the 'set' action.
    
    Stores a value securely in the vault.
    
    Args:
        args: Arguments (key, value)
    
    Returns:
        Success message
    
    Raises:
        ValueError: If arguments are invalid
    """
    # Validate argument count
    if len(args) < 2:
        _logger.warning("[VAULT_PLUGIN] Set requires key and value")
        raise ValueError("ERR_USAGE: vault set [key] [value]")
    
    # Parse arguments
    raw_key: str = str(args[0])
    raw_value: str = str(args[1])
    
    # Clean and validate key
    key: str = _clean_key(raw_key)
    
    if not key:
        _logger.warning("[VAULT_PLUGIN] Invalid key after cleaning: %s", raw_key)
        raise ValueError("ERR_INVALID_KEY")
    
    # Validate value length
    if len(raw_value) > MAX_VALUE_LENGTH:
        _logger.warning(
            "[VAULT_PLUGIN] Value too large: %d > %d",
            len(raw_value),
            MAX_VALUE_LENGTH
        )
        raise ValueError("ERR_VALUE_TOO_LARGE")
    
    _logger.info("[VAULT_PLUGIN] Storing key: %s", key)
    _debug_log("Value length: %d bytes", len(raw_value))
    
    try:
        # Encode and store value
        value_bytes: bytes = raw_value.encode('utf-8')
        
        # Store in secure store
        ss.write_encrypted(key, value_bytes, overwrite=True)
        
        # Securely wipe the value from memory
        _secure_wipe(value_bytes)
        _secure_wipe(raw_value)
        
        _logger.info("[VAULT_PLUGIN] Key stored successfully: %s", key)
        
        return f"[SECURE] Field '{key}' encrypted and persisted."
        
    except Exception as e:
        _logger.exception("[VAULT_PLUGIN] Failed to store key: %s", key)
        return f"ERR_VAULT_WRITE: {e}"


def _handle_get(args: tuple) -> str:
    """
    Handle the 'get' action.
    
    Retrieves a value from the vault.
    
    Args:
        args: Arguments (key)
    
    Returns:
        Retrieved value or error message
    
    Raises:
        ValueError: If arguments are invalid
    """
    # Validate argument count
    if len(args) < 1:
        _logger.warning("[VAULT_PLUGIN] Get requires a key")
        raise ValueError("ERR_USAGE: vault get [key]")
    
    # Parse arguments
    raw_key: str = str(args[0])
    
    # Clean and validate key
    key: str = _clean_key(raw_key)
    
    if not key:
        _logger.warning("[VAULT_PLUGIN] Invalid key after cleaning: %s", raw_key)
        raise ValueError("ERR_INVALID_KEY")
    
    _logger.info("[VAULT_PLUGIN] Retrieving key: %s", key)
    
    try:
        # Read from secure store
        blob: bytes = ss.read_encrypted(key)
        
        # Decode value
        value: str = blob.decode('utf-8')
        
        # Securely wipe the blob from memory
        _secure_wipe(blob)
        
        _logger.info("[VAULT_PLUGIN] Key retrieved successfully: %s", key)
        
        return f"VAULT_DECRYPTED [{key}]: {value}"
        
    except FileNotFoundError:
        _logger.warning("[VAULT_PLUGIN] Key not found: %s", key)
        return f"ERR_KEY_NOT_FOUND: {key}"
        
    except Exception as e:
        _logger.exception("[VAULT_PLUGIN] Failed to retrieve key: %s", key)
        return f"ERR_VAULT_READ: {e}"


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "execute",
    "PLUGIN_META",
    "set_debug_mode",
]
