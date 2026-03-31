"""
Plugin Loader Module for Arch-PyCLI.

This module provides dynamic plugin discovery and loading with:
- Thread-safe plugin management
- Plugin signature validation
- Comprehensive error handling
- Plugin reload capability
- Command registration and dispatch

Features:
- Dynamic module loading via importlib
- Plugin signature validation
- Plugin metadata support
- Thread-safe command registration
- Comprehensive logging and debugging

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

# Plugin directory defaults
DEFAULT_PLUGIN_DIR: str = "plugins"

# Plugin limits
MAX_PLUGINS: int = 100  # Maximum number of plugins
MAX_LOAD_TIME_SECONDS: float = 30.0  # Maximum time to load a plugin
MAX_COMMAND_NAME_LENGTH: int = 64  # Maximum command name length

# Debug configuration
DEBUG_PREFIX: str = "[LOADER_DEBUG]"
_is_debug_mode: bool = False


def set_debug_mode(enabled: bool) -> None:
    """Enable or disable debug logging for loader operations."""
    global _is_debug_mode
    _is_debug_mode = enabled


def _debug_log(message: str, *args: Any) -> None:
    """Internal debug logger that respects debug mode."""
    if _is_debug_mode:
        _logger.debug(f"{DEBUG_PREFIX} {message}", *args)


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class LoaderError(Exception):
    """Base exception for loader errors."""
    pass


class PluginLoadError(LoaderError):
    """Raised when plugin loading fails."""
    pass


class PluginValidationError(LoaderError):
    """Raised when plugin validation fails."""
    pass


class CommandNotFoundError(LoaderError):
    """Raised when a command is not found."""
    pass


class CommandExecutionError(LoaderError):
    """Raised when command execution fails."""
    pass


class PluginLimitExceededError(LoaderError):
    """Raised when plugin limit is exceeded."""
    pass


# =============================================================================
# SETUP LOGGING
# =============================================================================

# Create module-level logger
_logger: logging.Logger = logging.getLogger("LOADER")
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
    _file_handler: logging.Handler = logging.FileHandler("loader.log")
    _file_handler.setLevel(logging.INFO)
    _file_handler.setFormatter(_formatter)
    _logger.addHandler(_file_handler)
except (IOError, PermissionError, OSError):
    _logger.warning(
        "[LOADER] File logging unavailable, using stdout only."
    )

_logger.info("[LOADER] Plugin loader module initialized")


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class PluginInfo:
    """
    Metadata about a loaded plugin.
    
    Attributes:
        name: Plugin name (derived from filename)
        module_name: Python module name
        file_path: Path to the plugin file
        loaded_at: Timestamp when plugin was loaded
        load_time_ms: Time taken to load plugin in milliseconds
        metadata: Optional plugin metadata dictionary
        execute_func: The plugin's execute function
    """
    name: str
    module_name: str
    file_path: str
    loaded_at: float
    load_time_ms: float
    metadata: Optional[Dict[str, Any]] = None
    execute_func: Optional[Callable] = field(default=None, repr=False)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/debugging."""
        return {
            "name": self.name,
            "module_name": self.module_name,
            "file_path": self.file_path,
            "loaded_at": self.loaded_at,
            "load_time_ms": self.load_time_ms,
            "metadata": self.metadata,
        }


# =============================================================================
# PLUGIN LOADER CLASS
# =============================================================================

class PluginLoader:
    """
    Dynamic Command Orchestrator for Arch-PyCLI.
    
    This class manages plugin discovery, loading, validation, and execution.
    
    Features:
        - Dynamic plugin discovery from directory
        - Plugin signature validation
        - Thread-safe command registration
        - Plugin reload capability
        - Command execution with context injection
    
    Thread Safety:
        All public methods are thread-safe via internal locks.
        Plugins can be loaded/reloaded while commands are being executed.
    
    Example:
        >>> loader = PluginLoader(plugin_dir="plugins")
        >>> loader.bootstrap()
        >>> result = loader.dispatch("echo", {"health": {}}, "hello")
    """
    
    def __init__(
        self,
        plugin_dir: str = DEFAULT_PLUGIN_DIR,
        max_plugins: int = MAX_PLUGINS,
        max_load_time: float = MAX_LOAD_TIME_SECONDS
    ) -> None:
        """
        Initialize the plugin loader.
        
        Args:
            plugin_dir: Directory containing plugin files
            max_plugins: Maximum number of plugins to load
            max_load_time: Maximum time to load a plugin (seconds)
        """
        self.plugin_dir: str = plugin_dir
        self.max_plugins: int = max_plugins
        self.max_load_time: float = max_load_time
        
        # Thread-safe command storage
        self.commands: Dict[str, Callable] = {}
        self._commands_lock: threading.Lock = threading.Lock()
        
        # Plugin metadata storage
        self._plugins: Dict[str, PluginInfo] = {}
        self._plugins_lock: threading.Lock = threading.Lock()
        
        # Loaded modules (for reload tracking)
        self._loaded_modules: Dict[str, Any] = {}
        self._modules_lock: threading.Lock = threading.Lock()
        
        # Ensure plugin directory exists
        self._ensure_plugin_directory()
        
        # Statistics
        self._total_loads: int = 0
        self._failed_loads: int = 0
        self._total_dispatches: int = 0
        
        _logger.info(
            "[LOADER] Plugin loader initialized (dir=%s, max_plugins=%d)",
            plugin_dir,
            max_plugins
        )
        _debug_log("Initialized with max_load_time=%.1fs", max_load_time)
    
    def _ensure_plugin_directory(self) -> None:
        """Ensure the plugin directory exists."""
        try:
            if not os.path.exists(self.plugin_dir):
                try:
                    os.makedirs(self.plugin_dir, exist_ok=True)
                    _logger.info(
                        "[LOADER] Created plugin directory: %s",
                        self.plugin_dir
                    )
                except OSError as e:
                    _logger.error(
                        "[LOADER] Failed to create plugin directory: %s",
                        e
                    )
                    raise LoaderError(f"Cannot create plugin directory: {e}") from e
        except Exception as e:
            _logger.error(
                "[LOADER] Plugin directory check failed: %s",
                e
            )
    
    # =========================================================================
    # PLUGIN VALIDATION
    # =========================================================================
    
    def validate_plugin_signature(self, func: Callable) -> bool:
        """
        Validate that a plugin function has the correct signature.
        
        The plugin must accept at least one positional parameter (context)
        to receive the execution context.
        
        Args:
            func: The plugin function to validate
        
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            sig: inspect.Signature = inspect.signature(func)
            params: List[inspect.Parameter] = list(sig.parameters.values())
            
            # Must have at least one parameter
            if not params:
                _debug_log("Plugin has no parameters")
                return False
            
            # First parameter must accept context
            first: inspect.Parameter = params[0]
            allowed_kinds: tuple = (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.VAR_POSITIONAL,
            )
            
            if first.kind not in allowed_kinds:
                _debug_log(
                    "First parameter kind not allowed: %s",
                    first.kind
                )
                return False
            
            _debug_log("Plugin signature valid")
            return True
            
        except Exception as e:
            _debug_log("Signature validation error: %s", e)
            return False
    
    def validate_command_name(self, name: str) -> bool:
        """
        Validate a command name.
        
        Command names must be alphanumeric with underscores only,
        and must not exceed MAX_COMMAND_NAME_LENGTH.
        
        Args:
            name: Command name to validate
        
        Returns:
            True if valid, False otherwise
        """
        if not name:
            return False
        
        if len(name) > MAX_COMMAND_NAME_LENGTH:
            _debug_log("Command name too long: %d", len(name))
            return False
        
        # Must be alphanumeric with underscores
        if not name.replace('_', '').isalnum():
            _debug_log("Command name contains invalid characters: %s", name)
            return False
        
        return True
    
    # =========================================================================
    # PLUGIN LOADING
    # =========================================================================
    
    def bootstrap(self) -> int:
        """
        Load all valid plugins from the plugin directory.
        
        This is the "cold boot" sequence for commands.
        
        Returns:
            Number of plugins successfully loaded
        
        Raises:
            PluginLimitExceededError: If plugin limit is exceeded
        """
        _logger.info("[LOADER] Starting plugin bootstrap")
        
        if not os.path.exists(self.plugin_dir):
            _logger.warning(
                "[LOADER] Plugin directory does not exist: %s",
                self.plugin_dir
            )
            return 0
        
        loaded_count: int = 0
        load_errors: List[str] = []
        
        try:
            for filename in os.listdir(self.plugin_dir):
                # Skip non-Python files and private modules
                if not filename.endswith(".py") or filename.startswith("__"):
                    continue
                
                # Check plugin limit
                with self._plugins_lock:
                    if len(self._plugins) >= self.max_plugins:
                        _logger.warning(
                            "[LOADER] Plugin limit reached (%d), skipping %s",
                            self.max_plugins,
                            filename
                        )
                        break
                
                try:
                    plugin_name: str = filename[:-3]  # Remove .py extension
                    
                    if self._load_plugin(plugin_name, filename):
                        loaded_count += 1
                        self._total_loads += 1
                        
                except Exception as e:
                    self._failed_loads += 1
                    error_msg: str = f"{filename}: {e}"
                    load_errors.append(error_msg)
                    _logger.error(
                        "[LOADER] Failed to load plugin '%s': %s",
                        filename,
                        e
                    )
        
        except Exception as e:
            _logger.exception("[LOADER] Bootstrap error: %s", e)
            raise PluginLoadError(f"Bootstrap failed: {e}") from e
        
        # Log summary
        _logger.info(
            "[LOADER] Bootstrap complete: %d loaded, %d failed",
            loaded_count,
            len(load_errors)
        )
        
        if load_errors:
            _logger.debug("[LOADER] Load errors: %s", load_errors)
        
        # Verify commands dictionary is populated
        with self._commands_lock:
            if not isinstance(self.commands, dict):
                raise PluginLoadError(
                    "Commands registry is not a dictionary after bootstrap"
                )
        
        _logger.info(
            "[LOADER] Commands registered: %s",
            list(self.get_command_names())
        )
        
        return loaded_count
    
    def _load_plugin(self, plugin_name: str, filename: str) -> bool:
        """
        Load a single plugin module.
        
        Args:
            plugin_name: Name of the plugin (without .py)
            filename: Full filename
        
        Returns:
            True if loaded successfully, False otherwise
        """
        file_path: str = os.path.join(self.plugin_dir, filename)
        start_time: float = time.perf_counter()
        
        _debug_log("Loading plugin: %s from %s", plugin_name, file_path)
        
        try:
            # Create module spec
            spec = importlib.util.spec_from_file_location(
                plugin_name,
                file_path
            )
            
            if spec is None or spec.loader is None:
                _logger.warning(
                    "[LOADER] Invalid module spec for '%s'",
                    plugin_name
                )
                return False
            
            # Create and load module
            module = importlib.util.module_from_spec(spec)
            
            # Track module for potential reload
            with self._modules_lock:
                self._loaded_modules[plugin_name] = module
            
            # Execute module
            spec.loader.exec_module(module)
            
            # Check for execute function
            if not hasattr(module, 'execute'):
                _logger.warning(
                    "[LOADER] Plugin '%s' has no 'execute' function",
                    plugin_name
                )
                return False
            
            execute_func: Callable = getattr(module, 'execute')
            
            # Validate signature
            if not self.validate_plugin_signature(execute_func):
                _logger.warning(
                    "[LOADER] Plugin '%s' failed signature validation",
                    plugin_name
                )
                return False
            
            # Get optional metadata
            metadata: Optional[Dict[str, Any]] = getattr(
                module,
                'PLUGIN_META',
                None
            )
            
            # Calculate load time
            load_time_ms: float = (time.perf_counter() - start_time) * 1000
            
            # Check load time limit
            if load_time_ms > self.max_load_time * 1000:
                _logger.warning(
                    "[LOADER] Plugin '%s' load time exceeded limit (%.1fms > %.1fms)",
                    plugin_name,
                    load_time_ms,
                    self.max_load_time * 1000
                )
            
            # Create plugin info
            plugin_info: PluginInfo = PluginInfo(
                name=plugin_name,
                module_name=plugin_name,
                file_path=file_path,
                loaded_at=time.time(),
                load_time_ms=load_time_ms,
                metadata=metadata,
                execute_func=execute_func
            )
            
            # Create wrapper with context validation and error handling
            def make_wrapper(
                name: str,
                fn: Callable,
                info: PluginInfo
            ) -> Callable:
                """Create a safe wrapper for plugin execution."""
                def wrapper(context: Dict[str, Any], *args: Any) -> Any:
                    try:
                        # Validate context
                        if not isinstance(context, dict):
                            _logger.warning(
                                "[LOADER] Invalid context type for '%s'",
                                name
                            )
                            raise RuntimeError("ERR_MISSING_HEALTH_CONTEXT")
                        
                        # Execute plugin
                        return fn(context, *args)
                        
                    except Exception as e:
                        _logger.exception(
                            "[LOADER] Plugin '%s' execution failed",
                            name
                        )
                        return f"Runtime Error in {name}: {e}"
                
                return wrapper
            
            # Register command with thread safety
            with self._commands_lock:
                self.commands[plugin_name] = make_wrapper(
                    plugin_name,
                    execute_func,
                    plugin_info
                )
            
            # Store plugin info with thread safety
            with self._plugins_lock:
                self._plugins[plugin_name] = plugin_info
            
            _logger.info(
                "[LOADER] Plugin '%s' loaded (%.1fms)",
                plugin_name,
                load_time_ms
            )
            _debug_log(
                "Plugin loaded: name=%s, metadata=%s",
                plugin_name,
                metadata
            )
            
            return True
            
        except Exception as e:
            _logger.error(
                "[LOADER] Error loading plugin '%s': %s",
                plugin_name,
                e
            )
            
            # Clean up on failure
            with self._modules_lock:
                if plugin_name in self._loaded_modules:
                    del self._loaded_modules[plugin_name]
            
            raise
    
    # =========================================================================
    # PLUGIN MANAGEMENT
    # =========================================================================
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """
        Reload a specific plugin.
        
        Args:
            plugin_name: Name of the plugin to reload
        
        Returns:
            True if reload successful, False otherwise
        """
        _logger.info("[LOADER] Reloading plugin: %s", plugin_name)
        
        with self._plugins_lock:
            if plugin_name not in self._plugins:
                _logger.warning(
                    "[LOADER] Plugin not found for reload: %s",
                    plugin_name
                )
                return False
            
            old_info: PluginInfo = self._plugins[plugin_name]
            filename: str = os.path.basename(old_info.file_path)
        
        # Remove old registration
        with self._commands_lock:
            if plugin_name in self.commands:
                del self.commands[plugin_name]
        
        with self._plugins_lock:
            if plugin_name in self._plugins:
                del self._plugins[plugin_name]
        
        # Remove old module
        with self._modules_lock:
            if plugin_name in self._loaded_modules:
                del self._loaded_modules[plugin_name]
        
        # Remove module from sys.modules to force reload
        if plugin_name in sys.modules:
            del sys.modules[plugin_name]
        
        # Reload plugin
        try:
            return self._load_plugin(plugin_name, filename)
        except Exception as e:
            _logger.error(
                "[LOADER] Plugin reload failed for '%s': %s",
                plugin_name,
                e
            )
            return False
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """
        Unload a specific plugin.
        
        Args:
            plugin_name: Name of the plugin to unload
        
        Returns:
            True if unload successful, False otherwise
        """
        _logger.info("[LOADER] Unloading plugin: %s", plugin_name)
        
        removed: bool = False
        
        # Remove from commands
        with self._commands_lock:
            if plugin_name in self.commands:
                del self.commands[plugin_name]
                removed = True
        
        # Remove plugin info
        with self._plugins_lock:
            if plugin_name in self._plugins:
                del self._plugins[plugin_name]
                removed = True
        
        # Remove from loaded modules
        with self._modules_lock:
            if plugin_name in self._loaded_modules:
                del self._loaded_modules[plugin_name]
        
        # Remove from sys.modules
        if plugin_name in sys.modules:
            del sys.modules[plugin_name]
        
        if removed:
            _logger.info("[LOADER] Plugin '%s' unloaded", plugin_name)
        else:
            _logger.warning(
                "[LOADER] Plugin not found for unload: %s",
                plugin_name
            )
        
        return removed
    
    def get_loaded_plugins(self) -> List[PluginInfo]:
        """
        Get list of loaded plugins.
        
        Returns:
            List of PluginInfo objects
        """
        with self._plugins_lock:
            return list(self._plugins.values())
    
    def get_command_names(self) -> List[str]:
        """
        Get list of registered command names.
        
        Returns:
            List of command names
        """
        with self._commands_lock:
            return list(self.commands.keys())
    
    # =========================================================================
    # COMMAND DISPATCH
    # =========================================================================
    
    def dispatch(
        self,
        command_name: str,
        context: Optional[Dict[str, Any]] = None,
        *args: Any
    ) -> Any:
        """
        Execute a loaded command with the given context and arguments.
        
        Thread-safe command dispatch with fallback logic.
        
        Args:
            command_name: Name of the command to execute
            context: Execution context (must include 'health' dict)
            *args: Arguments to pass to the command
        
        Returns:
            Command execution result
        
        Raises:
            CommandNotFoundError: If command is not found
            CommandExecutionError: If command execution fails
        
        Example:
            >>> result = loader.dispatch(
            ...     "echo",
            ...     {"health": health_report},
            ...     "hello", "world"
            ... )
        """
        self._total_dispatches += 1
        
        # Validate command name
        if not self.validate_command_name(command_name):
            _logger.warning(
                "[LOADER] Invalid command name: %s",
                command_name
            )
            return f"ERR_INVALID_COMMAND_NAME: {command_name}"
        
        # Provide default context if not provided
        if context is None:
            context = {"health": {}, "user": "system"}
        
        # Look up command with thread safety
        with self._commands_lock:
            if command_name not in self.commands:
                _debug_log("Command not found: %s", command_name)
                return f"Command '{command_name}' not found in /plugins."
            
            command_func: Callable = self.commands[command_name]
        
        # Execute command
        try:
            _debug_log(
                "Dispatching command: %s (args=%s)",
                command_name,
                args
            )
            
            result: Any = command_func(context, *args)
            
            _debug_log(
                "Command completed: %s (result_type=%s)",
                command_name,
                type(result).__name__
            )
            
            return result
            
        except Exception as e:
            _logger.exception(
                "[LOADER] Command execution failed: %s",
                command_name
            )
            raise CommandExecutionError(
                f"Runtime Error in {command_name}: {e}"
            ) from e
    
    # =========================================================================
    # STATISTICS
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get loader statistics.
        
        Returns:
            Dictionary with loader statistics
        """
        with self._commands_lock:
            command_count: int = len(self.commands)
        
        with self._plugins_lock:
            plugin_count: int = len(self._plugins)
        
        return {
            "total_commands": command_count,
            "total_plugins": plugin_count,
            "total_loads": self._total_loads,
            "failed_loads": self._failed_loads,
            "total_dispatches": self._total_dispatches,
            "plugin_dir": self.plugin_dir,
            "max_plugins": self.max_plugins,
            "commands": self.get_command_names(),
        }
    
    def __repr__(self) -> str:
        """String representation of the loader."""
        with self._commands_lock:
            cmd_count: int = len(self.commands)
        return (
            f"PluginLoader(plugins={cmd_count}, "
            f"dir='{self.plugin_dir}')"
        )


# =============================================================================
# GLOBAL LOADER INSTANCE
# =============================================================================

# Initialize global loader with default settings
KERNEL_LOADER: PluginLoader = PluginLoader()


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_loader_stats() -> Dict[str, Any]:
    """
    Get statistics from the global loader.
    
    Returns:
        Dictionary with loader statistics
    """
    return KERNEL_LOADER.get_stats()


def reload_all_plugins() -> int:
    """
    Reload all currently loaded plugins.
    
    Returns:
        Number of plugins successfully reloaded
    """
    plugins: List[str] = KERNEL_LOADER.get_command_names()
    reloaded: int = 0
    
    for plugin_name in plugins:
        if KERNEL_LOADER.reload_plugin(plugin_name):
            reloaded += 1
    
    _logger.info("[LOADER] Reloaded %d/%d plugins", reloaded, len(plugins))
    return reloaded


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Classes
    "PluginLoader",
    # Exceptions
    "LoaderError",
    "PluginLoadError",
    "PluginValidationError",
    "CommandNotFoundError",
    "CommandExecutionError",
    "PluginLimitExceededError",
    # Global instance
    "KERNEL_LOADER",
    # Utility functions
    "get_loader_stats",
    "reload_all_plugins",
    "set_debug_mode",
]
