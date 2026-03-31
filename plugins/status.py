"""
Status Plugin for Arch-PyCLI.

This plugin provides system status and health reporting functionality.

Features:
- Health status reporting
- Memory metrics
- CPU utilization
- Full system diagnostics
- Comprehensive error handling

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Dict, List, Optional

# Import HAL for hardware metrics
try:
    from core.hal import HAL
except ImportError:
    # Fallback if HAL not available
    class HALFallback:
        CPU_CORES = 1
        TOTAL_RAM = 0
    HAL = HALFallback()

# Import network for node info
try:
    from core.network import NETWORK_NODE
except ImportError:
    NETWORK_NODE = None


# =============================================================================
# CONFIGURATION
# =============================================================================

# Valid subcommands
VALID_SUBCOMMANDS: set = {"health", "memory", "cpu", "full", ""}

# Debug configuration
DEBUG_PREFIX: str = "[STATUS_PLUGIN]"
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

_logger: logging.Logger = logging.getLogger("STATUS_PLUGIN")
if not _logger.handlers:
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

_logger.info("[STATUS_PLUGIN] Status plugin initialized")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _validate_subcommand(subcommand: str) -> bool:
    """
    Validate a subcommand string.
    
    Args:
        subcommand: Subcommand to validate
    
    Returns:
        True if valid, False otherwise
    """
    return subcommand.lower() in VALID_SUBCOMMANDS


def _safe_float(value: Any, default: float = 0.0) -> float:
    """
    Safely convert a value to float.
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
    
    Returns:
        Float value or default
    """
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    """
    Safely convert a value to int.
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
    
    Returns:
        Int value or default
    """
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _format_ram(bytes_value: int) -> str:
    """
    Format RAM in bytes to human-readable string.
    
    Args:
        bytes_value: RAM in bytes
    
    Returns:
        Formatted string (e.g., "4.00 GB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


# =============================================================================
# PLUGIN METADATA
# =============================================================================

PLUGIN_META: Dict[str, Any] = {
    "name": "status",
    "description": "Reports system health and resource metrics.",
    "version": "0.1.0",
    "author": "Arch-PyCLI Team",
    "usage": "status [health|memory|cpu|full]",
    "examples": [
        "status",
        "status health",
        "status memory",
        "status full"
    ]
}


# =============================================================================
# MAIN EXECUTE FUNCTION
# =============================================================================

def execute(context: Dict[str, Any], *args: Any) -> str:
    """
    Status plugin execution function.
    
    Reports system health and resource metrics based on requested subcommand.
    
    Args:
        context: Execution context containing health and other metadata
        *args: Optional subcommand (health|memory|cpu|full)
    
    Returns:
        Formatted status string
    
    Raises:
        ValueError: If health context is missing or subcommand is invalid
    
    Example:
        >>> result = execute({"health": health_report})
        >>> print(result)
        Node ID: node_123
        Status: HEALTHY
    """
    # =====================================================================
    # CONTEXT VALIDATION
    # =====================================================================
    
    if not context or "health" not in context:
        _logger.error("[STATUS_PLUGIN] Missing health context")
        raise ValueError("ERR_MISSING_HEALTH_CONTEXT")
    
    health: Dict[str, Any] = context.get("health", {})
    
    # =====================================================================
    # ARGUMENT PARSING
    # =====================================================================
    
    # Get subcommand (default to "full")
    subcommand: str = ""
    if args:
        subcommand = str(args[0]).lower().strip()
    
    # Validate subcommand
    if not _validate_subcommand(subcommand):
        _logger.warning(
            "[STATUS_PLUGIN] Invalid subcommand: %s",
            subcommand
        )
        return f"ERR_INVALID_SUBCOMMAND: '{subcommand}'. Use: health|memory|cpu|full"
    
    _debug_log("Status request: subcommand=%s", subcommand)
    
    # =====================================================================
    # BUILD OUTPUT
    # =====================================================================
    
    output: List[str] = []
    
    # Get node ID
    node_id: str = "unknown"
    if NETWORK_NODE is not None:
        try:
            node_id = str(NETWORK_NODE.node_id)
        except Exception:
            pass
    
    # Get status
    status: str = str(health.get("status", "UNKNOWN"))
    
    # Add header (always shown)
    output.append(f"Node ID: {node_id}")
    output.append(f"Status: {status}")
    
    # Memory section
    if subcommand in ("memory", "full"):
        mem_pressure: float = _safe_float(health.get("memory_pressure"), 0.0)
        output.append(f"Memory Pressure: {mem_pressure:.1f}%")
    
    # CPU section
    if subcommand in ("cpu", "full"):
        cpu_util: float = _safe_float(health.get("cpu_utilization"), 0.0)
        output.append(f"CPU Utilization: {cpu_util:.1f}%")
    
    # Health section
    if subcommand in ("health", "full"):
        lat: float = _safe_float(health.get("internal_latency"), 0.0)
        ts: float = _safe_float(health.get("timestamp"), 0.0)
        output.append(f"Internal Latency: {lat:.6f}s")
        output.append(f"Timestamp: {ts:.2f}")
    
    # Full diagnostics section
    if subcommand == "full":
        # Add HAL information
        try:
            cores: int = _safe_int(getattr(HAL, 'CPU_CORES', 0))
            total_ram: int = _safe_int(getattr(HAL, 'TOTAL_RAM', 0))
            output.append(f"HAL CPU Cores: {cores}")
            output.append(f"HAL Total RAM: {_format_ram(total_ram)}")
        except Exception as e:
            _logger.warning("[STATUS_PLUGIN] Failed to get HAL info: %s", e)
            output.append("HAL: data unavailable")
        
        # Add cached status
        cached: bool = bool(health.get("cached", False))
        output.append(f"Report Cached: {cached}")
        
        # Add error info if present
        error: Optional[str] = health.get("error")
        if error:
            output.append(f"Health Check Error: {error}")
    
    # =====================================================================
    # LOG AND RETURN
    # =====================================================================
    
    result: str = "\n".join(output)
    
    _logger.info(
        "[STATUS_PLUGIN] Status generated: %s",
        status
    )
    _debug_log("Output lines: %d", len(output))
    
    return result


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "execute",
    "PLUGIN_META",
    "set_debug_mode",
]
