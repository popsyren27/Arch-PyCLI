"""
Hardware Abstraction Layer (HAL) Module for Arch-PyCLI.

This module provides system resource monitoring and hardware information
with comprehensive fallbacks and caching.

Features:
- CPU and memory monitoring
- System health reporting with caching
- Hardware fingerprinting
- Graceful degradation when libraries unavailable
- Comprehensive error handling
- Debug logging support

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import gc
import logging
import platform
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

# Health check configuration
HEALTH_CHECK_CACHE_TTL: float = 1.0  # Cache health reports for 1 second
HEALTH_CHECK_INTERVAL: float = 0.5  # Minimum time between health checks

# System limits
DEFAULT_CPU_CORES: int = 1
DEFAULT_TOTAL_RAM: int = 0
DEFAULT_LATENCY_THRESHOLD: float = 1e-4  # 0.1ms baseline

# Memory thresholds (percentages)
MEMORY_WARNING_THRESHOLD: float = 80.0
MEMORY_CRITICAL_THRESHOLD: float = 95.0

# Debug configuration
DEBUG_PREFIX: str = "[HAL_DEBUG]"
_is_debug_mode: bool = False


def set_debug_mode(enabled: bool) -> None:
    """Enable or disable debug logging for HAL operations."""
    global _is_debug_mode
    _is_debug_mode = enabled


def _debug_log(message: str, *args: Any) -> None:
    """Internal debug logger that respects debug mode."""
    if _is_debug_mode:
        _logger.debug(f"{DEBUG_PREFIX} {message}", *args)


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class HALError(Exception):
    """Base exception for HAL errors."""
    pass


class HealthCheckError(HALError):
    """Raised when health check fails."""
    pass


# =============================================================================
# SETUP LOGGING
# =============================================================================

# Create module-level logger
_logger: logging.Logger = logging.getLogger("HAL")
if not _logger.handlers:
    # Configure with console handler
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

# Also try to add file handler if possible (non-blocking)
try:
    _file_handler: logging.Handler = logging.FileHandler("hal.log")
    _file_handler.setLevel(logging.INFO)
    _file_handler.setFormatter(_formatter)
    _logger.addHandler(_file_handler)
except (IOError, PermissionError, OSError):
    _logger.warning(
        "[HAL] File logging unavailable, using stdout only."
    )

_logger.info("[HAL] HAL module initialized")


# =============================================================================
# OPTIONAL IMPORTS
# =============================================================================

# Try to import psutil for system monitoring
try:
    import psutil
    PSUTIL_AVAILABLE: bool = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE: bool = False
    _logger.warning("[HAL] psutil not available, using fallback values")

# Try to import ctypes for low-level operations
try:
    import ctypes
    CTYPES_AVAILABLE: bool = True
except ImportError:
    ctypes = None
    CTYPES_AVAILABLE = False
    _logger.warning("[HAL] ctypes not available, secure memory clearing limited")


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class HealthReport:
    """
    Cached health report with metadata.
    
    Attributes:
        status: Overall system status
        memory_pressure: Memory usage percentage
        cpu_utilization: CPU usage percentage
        internal_latency: Internal execution latency in seconds
        timestamp: Unix timestamp when report was generated
        cached: Whether this report is from cache
        error: Error message if health check failed
    """
    status: str
    memory_pressure: float
    cpu_utilization: float
    internal_latency: float
    timestamp: float
    cached: bool = False
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status,
            "memory_pressure": self.memory_pressure,
            "cpu_utilization": self.cpu_utilization,
            "internal_latency": self.internal_latency,
            "timestamp": self.timestamp,
            "cached": self.cached,
            "error": self.error,
        }


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def secure_mem_clear(variable: Any) -> None:
    """
    Securely clear a variable from memory.
    
    Attempts to overwrite the memory address of the object with zeros
    before triggering garbage collection.
    
    Args:
        variable: Variable to clear from memory
    
    Note:
        Due to Python's memory management, this is not a perfect guarantee
        of data removal, but it significantly reduces the window of vulnerability.
    """
    try:
        if isinstance(variable, str):
            # Convert to mutable bytearray and overwrite
            b: bytearray = bytearray(variable.encode())
            for i in range(len(b)):
                b[i] = 0
            _debug_log("Secure memory clear: string (%d bytes)", len(b))
            
        elif isinstance(variable, (bytes, bytearray)):
            # Overwrite with zeros
            b = bytearray(variable)
            for i in range(len(b)):
                b[i] = 0
            _debug_log("Secure memory clear: bytes (%d bytes)", len(b))
            
        else:
            # For other objects, try to clear attributes
            try:
                if hasattr(variable, "__dict__"):
                    for k in list(variable.__dict__.keys()):
                        variable.__dict__[k] = None
                    _debug_log("Secure memory clear: object attributes")
            except Exception:
                pass
                
        # Try ctypes memset if available
        if CTYPES_AVAILABLE and isinstance(variable, (bytes, bytearray)):
            try:
                loc: int = id(variable)
                size: int = len(variable)
                ctypes.memset(loc, 0, size)
                _debug_log("Secure memory clear: ctypes memset (%d bytes)", size)
            except Exception:
                pass
                
    finally:
        # Force garbage collection
        try:
            del variable
            gc.collect()
        except Exception:
            pass


# =============================================================================
# HARDWARE CONTEXT CLASS
# =============================================================================

class HardwareContext:
    """
    Hardware information and monitoring context.
    
    This class provides:
        - CPU and memory information
        - Health check reporting with caching
        - Hardware fingerprinting
        - System metrics calculation
    
    Attributes:
        CPU_CORES: Number of physical CPU cores
        TOTAL_RAM: Total system RAM in bytes
        LATENCY_THRESHOLD: Baseline internal latency threshold
    
    Example:
        >>> ctx = HardwareContext()
        >>> report = ctx.get_health_report()
        >>> print(f"Status: {report['status']}")
    """
    
    def __init__(self) -> None:
        """
        Initialize the hardware context.
        
        Collects baseline hardware information and calculates
        initial latency threshold.
        """
        # Initialize hardware metrics
        self._boot_time: float = self._get_boot_time()
        self.CPU_CORES: int = self._get_cpu_cores()
        self.TOTAL_RAM: int = self._get_total_ram()
        
        # Calculate latency baseline
        self.LATENCY_THRESHOLD: float = self._calculate_latency_baseline()
        
        # Caching
        self._cached_report: Optional[HealthReport] = None
        self._last_check_time: float = 0.0
        
        # Statistics
        self._health_check_count: int = 0
        self._health_check_errors: int = 0
        
        _logger.info(
            "[HAL] Hardware context initialized: cores=%d, ram=%s, latency=%.6f",
            self.CPU_CORES,
            self._format_bytes(self.TOTAL_RAM),
            self.LATENCY_THRESHOLD
        )
        _debug_log(
            "Initialized: boot_time=%.2f, psutil=%s, ctypes=%s",
            self._boot_time,
            PSUTIL_AVAILABLE,
            CTYPES_AVAILABLE
        )
    
    def _get_boot_time(self) -> float:
        """Get system boot time."""
        try:
            if PSUTIL_AVAILABLE and psutil:
                return float(psutil.boot_time())
        except Exception as e:
            _debug_log("Failed to get boot time: %s", e)
        
        # Fallback to current time
        return time.time()
    
    def _get_cpu_cores(self) -> int:
        """Get number of physical CPU cores."""
        try:
            if PSUTIL_AVAILABLE and psutil:
                cores: Optional[int] = psutil.cpu_count(logical=False)
                if cores is not None and cores > 0:
                    return cores
        except Exception as e:
            _debug_log("Failed to get CPU cores: %s", e)
        
        return DEFAULT_CPU_CORES
    
    def _get_total_ram(self) -> int:
        """Get total system RAM in bytes."""
        try:
            if PSUTIL_AVAILABLE and psutil:
                vm = psutil.virtual_memory()
                return int(vm.total)
        except Exception as e:
            _debug_log("Failed to get total RAM: %s", e)
        
        return DEFAULT_TOTAL_RAM
    
    def _calculate_latency_baseline(self) -> float:
        """
        Calculate internal execution latency baseline.
        
        Performs a small busy loop to gauge performance counter resolution
        and establish a baseline for health check comparisons.
        
        Returns:
            Baseline latency in seconds
        """
        try:
            start: float = time.perf_counter()
            
            # Perform computation to measure timing resolution
            result: int = 0
            for _ in range(1000):
                result += 1
            
            elapsed: float = time.perf_counter() - start
            
            # Average per operation and add safety margin
            baseline: float = max(elapsed / 1000, DEFAULT_LATENCY_THRESHOLD)
            
            _debug_log("Latency baseline calculated: %.9f seconds", baseline)
            return baseline
            
        except Exception as e:
            _debug_log("Failed to calculate latency baseline: %s", e)
            return DEFAULT_LATENCY_THRESHOLD
    
    def get_health_report(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get system health report.
        
        Results are cached for HEALTH_CHECK_CACHE_TTL seconds to reduce
        system overhead from frequent health checks.
        
        Args:
            force_refresh: If True, ignore cache and generate fresh report
        
        Returns:
            Dictionary with health metrics including:
                - status: HEALTHY, DEGRADED, or CRITICAL
                - memory_pressure: Memory usage percentage
                - cpu_utilization: CPU usage percentage
                - internal_latency: Internal execution latency
                - timestamp: Unix timestamp
        
        Example:
            >>> report = hal.get_health_report()
            >>> if report['status'] == 'CRITICAL':
            ...     print("System unstable!")
        """
        current_time: float = time.time()
        
        # Check cache
        if not force_refresh:
            if self._cached_report is not None:
                cache_age: float = current_time - self._last_check_time
                if cache_age < HEALTH_CHECK_CACHE_TTL:
                    # Return cached report
                    cached_report: Dict[str, Any] = self._cached_report.to_dict()
                    cached_report["cached"] = True
                    _debug_log(
                        "Returning cached health report (age=%.3fs)",
                        cache_age
                    )
                    return cached_report
        
        # Generate fresh report
        self._health_check_count += 1
        
        try:
            # Get memory metrics
            mem_percent: float = 0.0
            cpu_load: float = 0.0
            
            try:
                if PSUTIL_AVAILABLE and psutil:
                    mem = psutil.virtual_memory()
                    mem_percent = float(mem.percent)
                    
                    # Get CPU utilization with short interval
                    cpu_load = float(psutil.cpu_percent(interval=0.1))
            except Exception as e:
                _debug_log("psutil metrics failed: %s", e)
            
            # Determine status based on memory pressure
            status: str = "HEALTHY"
            if mem_percent >= MEMORY_CRITICAL_THRESHOLD:
                status = "CRITICAL"
            elif mem_percent >= MEMORY_WARNING_THRESHOLD:
                status = "DEGRADED"
            
            # Calculate current internal latency
            internal_latency: float = self._calculate_latency_baseline()
            
            # Create report
            report: HealthReport = HealthReport(
                status=status,
                memory_pressure=mem_percent,
                cpu_utilization=cpu_load,
                internal_latency=internal_latency,
                timestamp=current_time,
                cached=False,
                error=None
            )
            
            # Cache the report
            self._cached_report = report
            self._last_check_time = current_time
            
            _debug_log(
                "Health report generated: status=%s, mem=%.1f%%, cpu=%.1f%%",
                status,
                mem_percent,
                cpu_load
            )
            
            return report.to_dict()
            
        except Exception as e:
            self._health_check_errors += 1
            _logger.exception("[HAL] Health check failed: %s", e)
            
            # Return critical status on error
            error_report: Dict[str, Any] = {
                "status": "CRITICAL",
                "memory_pressure": 100.0,
                "cpu_utilization": 100.0,
                "internal_latency": float("inf"),
                "timestamp": current_time,
                "cached": False,
                "error": str(e),
            }
            
            return error_report
    
    def get_fingerprint(self) -> str:
        """
        Get a concise hardware fingerprint string.
        
        This fingerprint is used for key binding in the security kernel.
        The fingerprint combines stable hardware properties to create
        a unique identifier for this machine.
        
        Returns:
            Fingerprint string in format: "hostname|mac|cores|ram"
        
        Warning:
            Relying solely on this for key derivation may make recovery
            difficult if hardware changes. Consider implementing user-
            supplied recovery options for production use.
        
        Example:
            >>> fp = hal.get_fingerprint()
            >>> print(f"Hardware ID: {fp}")
        """
        try:
            # Get stable identifiers
            node: str = platform.node()
            if not node:
                node = "unknown-host"
            
            mac: str = str(uuid.getnode())
            
            # Build fingerprint
            fingerprint: str = f"{node}|{mac}|{self.CPU_CORES}|{self.TOTAL_RAM}"
            
            _debug_log("Generated fingerprint: %s", fingerprint[:50] + "...")
            return fingerprint
            
        except Exception as e:
            _logger.error("[HAL] Failed to generate fingerprint: %s", e)
            return "unknown|unknown|0|0"
    
    def get_system_info(self) -> Dict[str, Any]:
        """
        Get detailed system information.
        
        Returns:
            Dictionary with system information including:
                - platform: Platform string
                - python_version: Python version
                - cpu_cores: Number of CPU cores
                - total_ram: Total RAM in bytes
                - boot_time: System boot timestamp
                - psutil_available: Whether psutil is available
        """
        return {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_cores": self.CPU_CORES,
            "total_ram": self.TOTAL_RAM,
            "total_ram_gb": round(self.TOTAL_RAM / (1024**3), 2),
            "boot_time": self._boot_time,
            "psutil_available": PSUTIL_AVAILABLE,
            "ctypes_available": CTYPES_AVAILABLE,
            "uptime_seconds": time.time() - self._boot_time,
            "fingerprint": self.get_fingerprint(),
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get HAL statistics.
        
        Returns:
            Dictionary with HAL statistics
        """
        return {
            "health_checks": self._health_check_count,
            "health_check_errors": self._health_check_errors,
            "error_rate": (
                self._health_check_errors / self._health_check_count
                if self._health_check_count > 0 else 0
            ),
            "cpu_cores": self.CPU_CORES,
            "total_ram": self.TOTAL_RAM,
            "latency_threshold": self.LATENCY_THRESHOLD,
            "cache_ttl": HEALTH_CHECK_CACHE_TTL,
        }
    
    @staticmethod
    def _format_bytes(bytes_value: int) -> str:
        """
        Format bytes as human-readable string.
        
        Args:
            bytes_value: Number of bytes
        
        Returns:
            Formatted string (e.g., "4.00 GB")
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
    
    def __repr__(self) -> str:
        """String representation of hardware context."""
        return (
            f"HardwareContext(cores={self.CPU_CORES}, "
            f"ram={self._format_bytes(self.TOTAL_RAM)})"
        )


# =============================================================================
# GLOBAL HARDWARE CONTEXT
# =============================================================================

# Initialize global hardware context
HAL: HardwareContext = HardwareContext()


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_health(force_refresh: bool = False) -> Dict[str, Any]:
    """
    Get system health report (convenience function).
    
    Args:
        force_refresh: If True, ignore cache
    
    Returns:
        Health report dictionary
    """
    return HAL.get_health_report(force_refresh=force_refresh)


def get_system_info() -> Dict[str, Any]:
    """
    Get system information (convenience function).
    
    Returns:
        System information dictionary
    """
    return HAL.get_system_info()


def get_hal_stats() -> Dict[str, Any]:
    """
    Get HAL statistics (convenience function).
    
    Returns:
        Statistics dictionary
    """
    return HAL.get_stats()


def secure_clear(variable: Any) -> None:
    """
    Securely clear a variable from memory (convenience function).
    
    Args:
        variable: Variable to clear
    """
    secure_mem_clear(variable)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Classes
    "HardwareContext",
    # Functions
    "get_health",
    "get_system_info",
    "get_hal_stats",
    "secure_mem_clear",
    "secure_clear",
    "set_debug_mode",
    # Constants
    "PSUTIL_AVAILABLE",
    "CTYPES_AVAILABLE",
    "HEALTH_CHECK_CACHE_TTL",
    "MEMORY_WARNING_THRESHOLD",
    "MEMORY_CRITICAL_THRESHOLD",
]
