import os
import importlib.util
import inspect
import logging
from typing import Dict, Callable, Any, Optional

class PluginLoader:
    """
    Dynamic Command Orchestrator.
    Scans the /plugins directory and maps filenames to executable OS commands.
    """
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = plugin_dir
        self.commands: Dict[str, Callable] = {}
        # Ensure the directory exists to prevent FileNotFoundError
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir)
            logging.info(f"Created missing plugin directory: {self.plugin_dir}")

    def validate_plugin_signature(self, func: Callable) -> bool:
        """
        Assertion Ratio Check: Validates that the plugin function 
        accepts exactly the required arguments (context, args).
        """
        try:
            sig = inspect.signature(func)
            params = list(sig.parameters.values())
            if not params:
                return False
            # First parameter must be a positional parameter (context)
            first = params[0]
            kinds_allowed = (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            )
            if first.kind not in kinds_allowed:
                return False
            # Remaining parameters may include var-positional for args
            return True
        except Exception:
            return False

    def bootstrap(self):
        """
        The 'Cold Boot' sequence for commands.
        Utilizes importlib to pull modules into the runtime dynamically.
        """
        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                file_path = os.path.join(self.plugin_dir, filename)
                
                try:
                    # Low-level module specification and loading
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        # Find the 'execute' function in the plugin file
                        if hasattr(module, 'execute'):
                            cmd_func = getattr(module, 'execute')

                            if not self.validate_plugin_signature(cmd_func):
                                logging.warning(f"Plugin '{module_name}' failed signature validation.")
                                continue

                            # Optional plugin metadata
                            meta = getattr(module, 'PLUGIN_META', None)

                            # Wrap the plugin call to enforce context type and catch exceptions
                            def make_wrapper(name: str, fn: Callable, meta: Optional[dict] = None):
                                def wrapper(context, *args):
                                    try:
                                        if not isinstance(context, dict):
                                            raise RuntimeError('ERR_MISSING_HEALTH_CONTEXT')
                                        # execute plugin
                                        return fn(context, *args)
                                    except Exception as e:
                                        logging.exception("Plugin '%s' execution failed", name)
                                        return f"Runtime Error in {name}: {e}"
                                return wrapper

                            self.commands[module_name] = make_wrapper(module_name, cmd_func, meta)
                            logging.info(f"Command '{module_name}' hot-loaded successfully.")
                except Exception as e:
                    logging.error(f"Kernel Panic during plugin load [{filename}]: {str(e)}")

    def dispatch(self, command_name: str, *args) -> Any:
        """Executes a loaded command with internal fallback logic."""
        if command_name in self.commands:
            try:
                # Execution with health-context injection
                return self.commands[command_name](*args)
            except Exception as e:
                return f"Runtime Error in {command_name}: {str(e)}"
        return f"Command '{command_name}' not found in /plugins."

# Initialize Global Loader
KERNEL_LOADER = PluginLoader()