"""
Configuration Module for Arch-PyCLI.

This module provides centralized configuration management with:
- Environment variable overrides
- Command-line argument parsing
- Type validation and bounds checking
- Fallback chains for reliability
- Comprehensive logging and debugging

Features:
- Environment-based configuration
- Validation with sensible defaults
- Comprehensive error handling
- Debug logging support

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

# Network defaults
DEFAULT_HOST: str = "127.0.0.1"
DEFAULT_PORT: int = 8888
DEFAULT_PLUGIN_DIR: str = "plugins"

# TLS defaults
DEFAULT_NETWORK_USE_TLS: bool = False
DEFAULT_NETWORK_REQUIRE_CLIENT_CERT: bool = False
DEFAULT_NETWORK_VERIFY_SERVER: bool = True

# Validation limits
MAX_HOST_LENGTH: int = 255
MIN_PORT: int = 1
MAX_PORT: int = 65535

# Debug configuration
DEBUG_PREFIX: str = "[CONFIG_DEBUG]"
_is_debug_mode: bool = False


def set_debug_mode(enabled: bool) -> None:
    """Enable or disable debug logging for configuration."""
    global _is_debug_mode
    _is_debug_mode = enabled


def _debug_log(message: str, *args: Any) -> None:
    """Internal debug logger that respects debug mode."""
    if _is_debug_mode:
        _logger.debug(f"{DEBUG_PREFIX} {message}", *args)


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class ConfigError(Exception):
    """Base exception for configuration errors."""
    pass


class ValidationError(ConfigError):
    """Raised when configuration validation fails."""
    pass


class EnvironmentError(ConfigError):
    """Raised when environment configuration fails."""
    pass


# =============================================================================
# SETUP LOGGING
# =============================================================================

# Create module-level logger
_logger: logging.Logger = logging.getLogger("CONFIG")
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
    _file_handler: logging.Handler = logging.FileHandler("config.log")
    _file_handler.setLevel(logging.INFO)
    _file_handler.setFormatter(_formatter)
    _logger.addHandler(_file_handler)
except (IOError, PermissionError, OSError):
    _logger.warning(
        "[CONFIG] File logging unavailable, using stdout only."
    )

_logger.info("[CONFIG] Configuration module initialized")


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class PyArchConfig:
    """
    Central configuration for a Py-Arch Node.
    
    This class manages all configuration settings with support for:
        - Environment variable overrides
        - Type validation and bounds checking
        - Sensible defaults
        - Comprehensive fallbacks
    
    Attributes:
        node_id: Unique identifier for this node
        host: Host address to bind to
        port: Port number to listen on
        plugin_dir: Directory containing plugins
        fallback_local_only: If True, use only local fallbacks
        network_use_tls: Enable TLS encryption
        network_certfile: Path to TLS certificate
        network_keyfile: Path to TLS private key
        network_cafile: Path to CA certificate
        network_require_client_cert: Require client certificates
        network_verify_server: Verify server certificates
    
    Example:
        >>> config = PyArchConfig.from_env(node_id="my_node")
        >>> print(f"Node: {config.node_id} on {config.host}:{config.port}")
    """
    
    # Core configuration
    node_id: str = field(default_factory=lambda: f"node_{int(time.time())}")
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    plugin_dir: str = DEFAULT_PLUGIN_DIR
    fallback_local_only: bool = False
    
    # Network/TLS configuration
    network_use_tls: bool = DEFAULT_NETWORK_USE_TLS
    network_certfile: Optional[str] = None
    network_keyfile: Optional[str] = None
    network_cafile: Optional[str] = None
    network_require_client_cert: bool = DEFAULT_NETWORK_REQUIRE_CLIENT_CERT
    network_verify_server: bool = DEFAULT_NETWORK_VERIFY_SERVER
    
    # Internal state
    _validation_errors: List[str] = field(default_factory=list, repr=False)
    _logger: logging.Logger = field(default_factory=lambda: logging.getLogger("CONFIG"), repr=False)
    
    def __post_init__(self) -> None:
        """
        Post-initialization processing.
        
        Applies environment variable overrides and validates configuration.
        """
        # Apply environment variable overrides
        try:
            self._apply_env_overrides()
        except Exception as e:
            self._logger.warning(
                "[CONFIG] Environment override failed, using defaults: %s",
                e
            )
        
        # Validate configuration
        self._validate()
        
        _debug_log(
            "Config initialized: node_id=%s, host=%s, port=%d",
            self.node_id,
            self.host,
            self.port
        )
    
    def _validate(self) -> None:
        """
        Validate all configuration values.
        
        Raises:
            ValidationError: If any configuration value is invalid
        """
        errors: List[str] = []
        
        # Validate host
        if not self.host:
            errors.append("Host cannot be empty")
        elif len(self.host) > MAX_HOST_LENGTH:
            errors.append(f"Host exceeds maximum length ({MAX_HOST_LENGTH})")
        
        # Validate port
        if not (MIN_PORT <= self.port <= MAX_PORT):
            errors.append(f"Port must be between {MIN_PORT} and {MAX_PORT}")
        
        # Validate plugin directory
        if not self.plugin_dir:
            errors.append("Plugin directory cannot be empty")
        
        # Validate TLS configuration
        if self.network_use_tls:
            if not self.network_certfile:
                errors.append("TLS enabled but certfile not provided")
            if not self.network_keyfile:
                errors.append("TLS enabled but keyfile not provided")
        
        # Validate file paths
        if self.network_certfile and not Path(self.network_certfile).exists():
            self._logger.warning(
                "[CONFIG] Certificate file not found: %s",
                self.network_certfile
            )
        if self.network_keyfile and not Path(self.network_keyfile).exists():
            self._logger.warning(
                "[CONFIG] Key file not found: %s",
                self.network_keyfile
            )
        if self.network_cafile and not Path(self.network_cafile).exists():
            self._logger.warning(
                "[CONFIG] CA file not found: %s",
                self.network_cafile
            )
        
        if errors:
            self._validation_errors = errors
            self._logger.warning(
                "[CONFIG] Validation warnings: %s",
                errors
            )
            # Don't raise - just log warnings for non-critical errors
            # Critical errors would prevent the system from starting
    
    def _parse_bool(self, value: Optional[str]) -> bool:
        """
        Parse a boolean value from environment variable.
        
        Args:
            value: String value from environment
        
        Returns:
            Boolean interpretation of the value
        
        Truthy values: "1", "true", "yes", "on" (case-insensitive)
        All other values return False.
        """
        if value is None:
            return False
        
        return str(value).lower() in ("1", "true", "yes", "on", "enabled")
    
    def _parse_int(self, value: Optional[str], default: int) -> int:
        """
        Parse an integer value from environment variable.
        
        Args:
            value: String value from environment
            default: Default value if parsing fails
        
        Returns:
            Parsed integer or default value
        """
        if value is None:
            return default
        
        try:
            parsed: int = int(value)
            # Validate port range
            if parsed < MIN_PORT or parsed > MAX_PORT:
                self._logger.warning(
                    "[CONFIG] Port %d out of range, using default %d",
                    parsed,
                    default
                )
                return default
            return parsed
        except ValueError:
            self._logger.warning(
                "[CONFIG] Invalid integer '%s', using default %d",
                value,
                default
            )
            return default
    
    def _apply_env_overrides(self) -> None:
        """
        Read environment variables and override configuration.
        
        Supported environment variables:
            PYARCH_HOST: Listen host (default: 127.0.0.1)
            PYARCH_PORT: Listen port (default: 8888)
            PYARCH_PLUGIN_DIR: Plugin folder (default: plugins)
            PYARCH_NETWORK_USE_TLS: Enable TLS (true/1/yes)
            PYARCH_NETWORK_CERTFILE: TLS certificate path
            PYARCH_NETWORK_KEYFILE: TLS key path
            PYARCH_NETWORK_CAFILE: TLS CA bundle path
            PYARCH_NETWORK_REQUIRE_CLIENT_CERT: Require client certs
            PYARCH_NETWORK_VERIFY_SERVER: Verify server certs
        """
        env: Dict[str, Optional[str]] = {
            "PYARCH_HOST": os.environ.get("PYARCH_HOST"),
            "PYARCH_PORT": os.environ.get("PYARCH_PORT"),
            "PYARCH_PLUGIN_DIR": os.environ.get("PYARCH_PLUGIN_DIR"),
            "PYARCH_NETWORK_USE_TLS": os.environ.get("PYARCH_NETWORK_USE_TLS"),
            "PYARCH_NETWORK_CERTFILE": os.environ.get("PYARCH_NETWORK_CERTFILE"),
            "PYARCH_NETWORK_KEYFILE": os.environ.get("PYARCH_NETWORK_KEYFILE"),
            "PYARCH_NETWORK_CAFILE": os.environ.get("PYARCH_NETWORK_CAFILE"),
            "PYARCH_NETWORK_REQUIRE_CLIENT_CERT": os.environ.get("PYARCH_NETWORK_REQUIRE_CLIENT_CERT"),
            "PYARCH_NETWORK_VERIFY_SERVER": os.environ.get("PYARCH_NETWORK_VERIFY_SERVER"),
        }
        
        # Track which overrides were applied
        applied: List[str] = []
        
        # Apply host override
        if env["PYARCH_HOST"]:
            self.host = str(env["PYARCH_HOST"])[:MAX_HOST_LENGTH]
            applied.append("host")
        
        # Apply port override
        if env["PYARCH_PORT"]:
            self.port = self._parse_int(env["PYARCH_PORT"], self.port)
            applied.append("port")
        
        # Apply plugin directory override
        if env["PYARCH_PLUGIN_DIR"]:
            self.plugin_dir = str(env["PYARCH_PLUGIN_DIR"])
            applied.append("plugin_dir")
        
        # Apply TLS configuration
        self.network_use_tls = self._parse_bool(env["PYARCH_NETWORK_USE_TLS"])
        if self.network_use_tls:
            applied.append("network_use_tls")
        
        self.network_certfile = env["PYARCH_NETWORK_CERTFILE"]
        self.network_keyfile = env["PYARCH_NETWORK_KEYFILE"]
        self.network_cafile = env["PYARCH_NETWORK_CAFILE"]
        
        self.network_require_client_cert = self._parse_bool(env["PYARCH_NETWORK_REQUIRE_CLIENT_CERT"])
        self.network_verify_server = self._parse_bool(env["PYARCH_NETWORK_VERIFY_SERVER"])
        
        # Default network_verify_server to True unless explicitly disabled
        verify_env = env["PYARCH_NETWORK_VERIFY_SERVER"]
        if verify_env is not None:
            self.network_verify_server = self._parse_bool(verify_env)
        
        if applied:
            _debug_log("Applied env overrides: %s", applied)
            self._logger.info(
                "[CONFIG] Applied environment overrides: %s",
                ", ".join(applied)
            )
    
    @classmethod
    def from_env(cls, node_id: Optional[str] = None) -> "PyArchConfig":
        """
        Create configuration from environment variables with defaults.
        
        This is the preferred factory method for creating configuration
        in production environments where environment variables control settings.
        
        Args:
            node_id: Optional node identifier (auto-generated if not provided)
        
        Returns:
            New PyArchConfig instance with environment overrides applied
        
        Example:
            >>> config = PyArchConfig.from_env(node_id="production_node")
            >>> # Configuration is loaded from environment with sensible defaults
        """
        nid: str = node_id or f"node_{int(time.time())}"
        
        config: PyArchConfig = cls(node_id=nid)
        
        # Ensure plugin directory exists with fallbacks
        config._ensure_plugin_directory()
        
        _debug_log("Created config from environment: node_id=%s", nid)
        
        return config
    
    def _ensure_plugin_directory(self) -> None:
        """
        Ensure the plugin directory exists with fallbacks.
        
        This implements a fallback chain:
            1. Try configured plugin directory
            2. Try /tmp/pyarch_plugins (Unix-like systems)
            3. Fall back to current directory
        """
        try:
            if not os.path.exists(self.plugin_dir):
                # Try to create the directory
                try:
                    os.makedirs(self.plugin_dir, exist_ok=True)
                    self._logger.info(
                        "[CONFIG] Created plugin directory: %s",
                        self.plugin_dir
                    )
                    return
                except OSError as e:
                    self._logger.warning(
                        "[CONFIG] Failed to create plugin directory %s: %s",
                        self.plugin_dir,
                        e
                    )
            
            # Fallback 1: /tmp/pyarch_plugins
            if self.fallback_local_only:
                fallback_dir: str = "/tmp/pyarch_plugins"
            else:
                fallback_dir = self.plugin_dir
                if not os.path.exists(fallback_dir):
                    fallback_dir = "/tmp/pyarch_plugins"
            
            if not os.path.exists(fallback_dir):
                try:
                    os.makedirs(fallback_dir, exist_ok=True)
                    self.plugin_dir = fallback_dir
                    self._logger.warning(
                        "[CONFIG] Using fallback plugin directory: %s",
                        fallback_dir
                    )
                    return
                except OSError:
                    pass
            
            # Final fallback: current directory
            self.plugin_dir = "."
            self._logger.warning(
                "[CONFIG] Using current directory for plugins"
            )
            
        except Exception as e:
            self._logger.error(
                "[CONFIG] Failed to ensure plugin directory: %s",
                e
            )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.
        
        Returns:
            Dictionary representation of configuration
        """
        return {
            "node_id": self.node_id,
            "host": self.host,
            "port": self.port,
            "plugin_dir": self.plugin_dir,
            "fallback_local_only": self.fallback_local_only,
            "network_use_tls": self.network_use_tls,
            "network_certfile": self.network_certfile,
            "network_keyfile": self.network_keyfile,
            "network_cafile": self.network_cafile,
            "network_require_client_cert": self.network_require_client_cert,
            "network_verify_server": self.network_verify_server,
        }
    
    def update(self, **kwargs: Any) -> None:
        """
        Update configuration values with validation.
        
        Args:
            **kwargs: Configuration values to update
        
        Raises:
            ValidationError: If validation fails after update
        
        Example:
            >>> config.update(host="0.0.0.0", port=9000)
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                old_value = getattr(self, key)
                setattr(self, key, value)
                _debug_log(
                    "Updated %s: %s -> %s",
                    key,
                    old_value,
                    value
                )
            else:
                self._logger.warning(
                    "[CONFIG] Unknown configuration key: %s",
                    key
                )
        
        # Re-validate after update
        self._validate()
    
    def get_validation_errors(self) -> List[str]:
        """
        Get list of validation errors.
        
        Returns:
            List of validation error messages
        """
        return self._validation_errors.copy()
    
    def is_valid(self) -> bool:
        """
        Check if configuration is valid.
        
        Returns:
            True if no validation errors, False otherwise
        """
        return len(self._validation_errors) == 0
    
    def __repr__(self) -> str:
        """String representation of configuration."""
        return (
            f"PyArchConfig(node_id={self.node_id!r}, "
            f"host={self.host!r}, port={self.port}, "
            f"tls={self.network_use_tls})"
        )


# =============================================================================
# LOGGER SETUP FUNCTION
# =============================================================================

def setup_logger(
    node_id: str,
    level: int = logging.DEBUG,
    log_to_file: bool = True,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Set up a centralized logger for the node.
    
    This creates a logger with both console and file handlers,
    with graceful fallback if file logging fails.
    
    Args:
        node_id: Node identifier for logger naming
        level: Logging level (default: DEBUG)
        log_to_file: Whether to log to file
        log_file: Custom log file name (default: pyarch_{node_id}.log)
    
    Returns:
        Configured logger instance
    
    Example:
        >>> logger = setup_logger("my_node")
        >>> logger.info("Node started")
    """
    logger: logging.Logger = logging.getLogger(f"PyArch-{node_id}")
    logger.setLevel(level)
    
    # Clear existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers.clear()
    
    # Create formatter
    formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    
    # Console handler
    console_handler: logging.Handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler with fallback
    if log_to_file:
        file_name: str = log_file or f"pyarch_{node_id}.log"
        
        try:
            file_handler: logging.Handler = logging.FileHandler(file_name)
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.info("[CONFIG] File logging enabled: %s", file_name)
        except (IOError, PermissionError, OSError) as e:
            logger.warning(
                "[CONFIG] File logging unavailable (%s), using stdout only. "
                "This may occur in read-only filesystems.",
                e
            )
    
    _debug_log("Logger setup complete for node: %s", node_id)
    
    return logger


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_env_bool(
    key: str,
    default: bool = False,
    truthy_values: Optional[List[str]] = None
) -> bool:
    """
    Get a boolean value from environment variable.
    
    Args:
        key: Environment variable name
        default: Default value if not set
        truthy_values: List of values considered True
    
    Returns:
        Boolean value from environment
    """
    if truthy_values is None:
        truthy_values = ["1", "true", "yes", "on", "enabled"]
    
    value: Optional[str] = os.environ.get(key)
    
    if value is None:
        return default
    
    return str(value).lower() in [v.lower() for v in truthy_values]


def get_env_int(
    key: str,
    default: int,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None
) -> int:
    """
    Get an integer value from environment variable.
    
    Args:
        key: Environment variable name
        default: Default value if not set or invalid
        min_value: Minimum allowed value
        max_value: Maximum allowed value
    
    Returns:
        Integer value from environment
    """
    value: Optional[str] = os.environ.get(key)
    
    if value is None:
        return default
    
    try:
        parsed: int = int(value)
        
        if min_value is not None and parsed < min_value:
            return default
        if max_value is not None and parsed > max_value:
            return default
        
        return parsed
    except ValueError:
        return default


def get_env_str(
    key: str,
    default: str,
    max_length: Optional[int] = None
) -> str:
    """
    Get a string value from environment variable.
    
    Args:
        key: Environment variable name
        default: Default value if not set
        max_length: Maximum allowed length
    
    Returns:
        String value from environment
    """
    value: Optional[str] = os.environ.get(key)
    
    if value is None:
        return default
    
    if max_length is not None and len(value) > max_length:
        return value[:max_length]
    
    return value


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Classes
    "PyArchConfig",
    # Functions
    "setup_logger",
    "get_env_bool",
    "get_env_int",
    "get_env_str",
    "set_debug_mode",
    # Exceptions
    "ConfigError",
    "ValidationError",
    "EnvironmentError",
    # Constants
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "DEFAULT_PLUGIN_DIR",
]
