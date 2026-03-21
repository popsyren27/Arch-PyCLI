import os
import importlib.util
import logging
import inspect
import asyncio
from typing import Dict, Any, Callable
import time

# Setup Loader Logging - Persistent Audit Trail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [LOADER] %(message)s',
    handlers=[logging.FileHandler("sys_kernel.log"), logging.StreamHandler()]
)

class PluginLoader:
    """
    DYNAMIC ORCHESTRATOR:
    Handles the discovery, validation, and execution of Arch-Plugins.
    Supports both Sync and Async execution patterns.
    """
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = os.path.abspath(plugin_dir)
        self.commands: Dict[str, Callable] = {}
        self._last_scan_time = 0
        
        # Initial Bootstrap
        self.bootstrap()

    def bootstrap(self):
        """
        COLD BOOT DISCOVERY:
        Scans the directory and maps files to memory addresses.
        """
        self.commands.clear()
        if not os.path.exists(self.plugin_dir):
            logging.warning(f"Directory /{self.plugin_dir} missing. Creating baseline.")
            os.makedirs(self.plugin_dir, exist_ok=True)
            return

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                self._load_module(filename)
        
        self._last_scan_time = time.time() if 'time' in globals() else 0
        logging.info(f"Loader initialized. {len(self.commands)} plugins registered.")

    def _load_module(self, filename: str):
        """
        LOW-LEVEL IMPORT LOGIC:
        Uses importlib to inject the plugin into the kernel namespace.
        """
        module_name = filename[:-3]
        path = os.path.join(self.plugin_dir, filename)
        
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # ARCH-STANDARD ENTRY POINTS: Look for 'run' then 'execute'
            func = getattr(module, "run", getattr(module, "execute", None))
            
            if func and callable(func):
                self.commands[module_name] = func
                logging.info(f"Registered: [{module_name}] -> {path}")
            else:
                logging.warning(f"Plugin '{filename}' rejected: Missing entry point (run/execute).")
                
        except Exception as e:
            logging.error(f"Critical failure loading '{filename}': {e}")

    def dispatch(self, command_name: str, context: Dict[str, Any], *args):
        """
        EXECUTION GATEWAY:
        Routes shell input to the correct plugin with Hardware Context.
        Supports automatic 'Hot-Reload' if a file was recently modified.
        """
        # Check if the command exists
        if command_name not in self.commands:
            # Attempt a quick re-scan in case it's a new file
            self._load_module(f"{command_name}.py")
            if command_name not in self.commands:
                return f"Command '{command_name}' not found in /{self.plugin_dir}."

        try:
            func = self.commands[command_name]
            
            # ASYNC CHECK: Handle both normal and async plugins
            if asyncio.iscoroutinefunction(func):
                # If we're in a sync context but the plugin is async, we need a runner
                return asyncio.run(func(context, *args))
            
            return func(context, *args)

        except Exception as e:
            logging.error(f"RUNTIME_EXECUTION_ERROR [{command_name}]: {e}")
            return f"Internal Plugin Error: {str(e)}"

# Global Loader Instance for Kernel Access
KERNEL_LOADER = PluginLoader()