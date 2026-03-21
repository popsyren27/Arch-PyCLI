import os
import importlib.util
import logging
from typing import List, Any

class PluginManager:
    """
    The 'Auto-Discovery' engine for Py-Arch OS.
    
    Philosophy: 
    - Full Modularity: The kernel doesn't know what plugins exist.
    - Autostart: Every valid python file in /plugins is loaded on boot.
    """
    def __init__(self, plugin_dir: str, logger: logging.Logger):
        self.plugin_dir = plugin_dir
        self.logger = logger
        self.loaded_plugins = []

    def discover_and_load(self, *args, **kwargs) -> List[Any]:
        """
        Scans the plugin directory and dynamically imports all modules.
        Passes provided args (like registry, node_agent) to the plugin constructors.
        """
        self.logger.info(f"Scanning for OS extensions in: {self.plugin_dir}")
        
        if not os.path.exists(self.plugin_dir):
            try:
                os.makedirs(self.plugin_dir, exist_ok=True)
            except Exception:
                self.logger.warning("Plugin directory missing and could not be created.")
                return []

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                file_path = os.path.join(self.plugin_dir, filename)
                
                try:
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        # Initialize the main class in the module
                        plugin_instance = self._initialize_plugin(module, *args, **kwargs)
                        if plugin_instance:
                            self.loaded_plugins.append(plugin_instance)
                            self.logger.info(f"Successfully integrated module: {module_name}")
                
                except Exception as e:
                    self.logger.error(f"Failed to load plugin {filename}: {e}")
        
        return self.loaded_plugins

    def _initialize_plugin(self, module: Any, *args, **kwargs) -> Any:
        """
        Detects the main class within a plugin and instantiates it.
        Injects the logger + any other OS subsystems passed in.
        """
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type):
                if attr.__module__ == module.__name__:
                    # Pass the logger and any other passed dependencies (registry, etc)
                    return attr(*args, logger=self.logger, **kwargs)
        return None

    def broadcast_event(self, event_name: str, *args, **kwargs):
        """Notifies all loaded plugins of a kernel event."""
        for plugin in self.loaded_plugins:
            method = getattr(plugin, event_name, None)
            if callable(method):
                method(*args, **kwargs)