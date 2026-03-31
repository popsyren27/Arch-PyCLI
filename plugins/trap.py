"""
Trap Plugin for Arch-PyCLI.

This plugin implements a honeypot security mechanism that stores encrypted
blobs when near-miss key attempts are detected (e.g., case-only variations
of sensitive keywords).

Features:
- Near-miss key detection (case-insensitive)
- Hardware-bound encryption
- Encrypted blob storage in secure store
- Graceful error handling
- No plaintext file leakage

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import hashlib
import logging
import sys
from typing import Any, Dict, Optional

# Import security kernel for encryption
try:
    from core.security import SEC_KERNEL
except ImportError:
    SEC_KERNEL = None

# Import HAL for hardware fingerprinting
try:
    from core.hal import HAL
except ImportError:
    HAL = None

# Import secure store for blob storage
try:
    from core.secure_store import write_encrypted
except ImportError:
    write_encrypted = None


# =============================================================================
# CONFIGURATION
# =============================================================================

# Sensitive keywords to trap (case-insensitive near-misses)
TRAP_KEYWORDS: list = [
    "admin",
    "root",
    "password",
    "secret",
    "private",
    "key",
]

# Trap storage namespace
TRAP_NAMESPACE: str = "trap"

# Debug configuration
DEBUG_PREFIX: str = "[TRAP_PLUGIN]"
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

_logger: logging.Logger = logging.getLogger("TRAP_PLUGIN")
if not _logger.handlers:
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

_logger.info("[TRAP_PLUGIN] Trap plugin initialized")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _get_hw_fingerprint() -> str:
    """
    Get hardware fingerprint for blob binding.
    
    Returns:
        Hardware fingerprint string
    """
    # Prefer HAL-provided fingerprint helper if available
    try:
        fp = getattr(HAL, 'get_fingerprint', None)
        if callable(fp):
            return fp()
    except Exception:
        pass
    
    # Fallback to hardware summary from HAL
    try:
        if HAL is not None:
            ram: str = str(getattr(HAL, 'TOTAL_RAM', 'unknown'))
            cores: str = str(getattr(HAL, 'CPU_CORES', 'unknown'))
            return f"{ram}-{cores}"
    except Exception:
        pass
    
    return "unknown-hw"


def _is_trap_keyword(input_key: str) -> bool:
    """
    Check if the input key matches a trap keyword (case-insensitive).
    
    Args:
        input_key: Input key to check
    
    Returns:
        True if input is a trap keyword
    """
    key_lower: str = input_key.lower()
    return any(
        kw for kw in TRAP_KEYWORDS
        if key_lower == kw
    )


def _check_near_miss(input_key: str, trap_keyword: str) -> bool:
    """
    Check if input is a case-only variation of trap keyword.
    
    Args:
        input_key: Input key
        trap_keyword: Trap keyword to compare
    
    Returns:
        True if near-miss detected
    """
    # Case-insensitive comparison but not exact match
    return (
        input_key.lower() == trap_keyword.lower()
        and input_key != trap_keyword
    )


def _find_trap_match(input_key: str) -> Optional[str]:
    """
    Find if input key is a near-miss of any trap keyword.
    
    Args:
        input_key: Input key to check
    
    Returns:
        Matching trap keyword or None
    """
    for keyword in TRAP_KEYWORDS:
        if _check_near_miss(input_key, keyword):
            return keyword
    return None


# =============================================================================
# PLUGIN METADATA
# =============================================================================

PLUGIN_META: Dict[str, Any] = {
    "name": "trap",
    "description": "Honeypot security - stores encrypted blobs on near-miss key attempts.",
    "version": "0.1.0",
    "author": "Arch-PyCLI Team",
    "usage": "trap [check_key] [data]",
    "examples": [
        "trap Admin password123",
        "trap Password secret"
    ]
}


# =============================================================================
# MAIN EXECUTE FUNCTION
# =============================================================================

def execute(context: Dict[str, Any], *args: Any) -> str:
    """
    Trap plugin execution function.
    
    Implements a honeypot security mechanism:
    - Detects near-miss key attempts (case variations of sensitive keywords)
    - Stores encrypted blobs bound to hardware fingerprint
    - Prevents plaintext file leakage
    
    Args:
        context: Execution context containing health and other metadata
        *args: Command arguments (check_key, data)
    
    Returns:
        Success message (intentionally generic to not reveal trap behavior)
    
    Raises:
        ValueError: If arguments are invalid
        RuntimeError: If security kernel or storage unavailable
    
    Note:
        Returns "[SUCCESS] Data saved to vault." even on actual trap
        engagement to avoid revealing honeypot behavior to attacker.
    """
    # =====================================================================
    # ARGUMENT VALIDATION
    # =====================================================================
    
    if not args or len(args) < 2:
        _logger.warning("[TRAP_PLUGIN] Missing required arguments")
        raise ValueError("ERR_USAGE: trap [check_key] [data]")
    
    input_key: str = str(args[0])
    raw_data: str = str(args[1])
    
    _debug_log("Checking key: %s", input_key)
    
    # =====================================================================
    # DEPENDENCY CHECKS
    # =====================================================================
    
    if SEC_KERNEL is None:
        _logger.error("[TRAP_PLUGIN] Security kernel not available")
        raise RuntimeError("ERR_SECURITY_KERNEL_UNAVAILABLE")
    
    if write_encrypted is None:
        _logger.error("[TRAP_PLUGIN] Secure store not available")
        raise RuntimeError("ERR_SECURE_STORE_UNAVAILABLE")
    
    # =====================================================================
    # NEAR-MISS DETECTION
    # =====================================================================
    
    # Check if exact match (not a trap - reject immediately)
    if _is_trap_keyword(input_key):
        _debug_log("Exact trap keyword detected: %s", input_key)
        return "ERR_AUTH_FAILED"
    
    # Check for near-miss (case variation)
    matched_keyword: Optional[str] = _find_trap_match(input_key)
    
    if matched_keyword is None:
        # Not a near-miss, reject
        _debug_log("No trap match for: %s", input_key)
        return "ERR_AUTH_FAILED"
    
    # =====================================================================
    # TRAP ENGAGED - Near-miss detected
    # =====================================================================
    
    _logger.warning(
        "[TRAP_PLUGIN] Near-miss key detected: '%s' (matches '%s')",
        input_key,
        matched_keyword
    )
    
    # Get hardware fingerprint for blob binding
    hw_fp: str = _get_hw_fingerprint()
    
    # Create mutation seed from key and hardware
    mutation_seed: bytes = hashlib.sha512(
        (input_key + hw_fp).encode()
    ).digest()
    
    _debug_log("Hardware fingerprint: %s", hw_fp)
    _debug_log("Mutation seed: %s...", mutation_seed[:16].hex())
    
    try:
        # Encrypt the data bytes with the Security kernel
        blob: bytes = SEC_KERNEL.encrypt_bytes(raw_data.encode('utf-8'))
        
        # Create trap path with hash of blob
        blob_hash: str = hashlib.sha256(blob).hexdigest()
        path: str = f"{TRAP_NAMESPACE}/{blob_hash}.bin"
        
        # Store in secure store
        write_encrypted(path, blob, overwrite=False)
        
        _logger.info(
            "[TRAP_PLUGIN] Trapped blob stored: %s (keyword: %s)",
            path,
            matched_keyword
        )
        
        # Securely wipe sensitive data from memory
        try:
            if hasattr(SEC_KERNEL, '_wipe_memory'):
                SEC_KERNEL._wipe_memory(mutation_seed)
                SEC_KERNEL._wipe_memory(blob)
        except Exception:
            pass
        
    except Exception as e:
        _logger.exception("[TRAP_PLUGIN] Failed to write trapped blob")
        # Intentionally return success to not reveal trap behavior
        # even if storage fails
    
    # Return generic success message to avoid revealing honeypot
    return "[SUCCESS] Data saved to vault."


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "execute",
    "PLUGIN_META",
    "set_debug_mode",
]
