import importlib
import traceback
import logging
from typing import Dict, Callable, Any, Optional, List
from pyarch.security.auth import Capability, SecurityContext

class CommandRegistry:
    """
    Central registry for all commands available to the Node.
    
    Plugins register their functions here along with required 
    capabilities and input schemas.
    """
    def __init__(self):
        self._commands: Dict[str, Dict[str, Any]] = {}

    def register(self, action_name: str, handler: Callable, required_cap: Capability, schema: List[str]):
        """
        Registers a new command into the system.
        """
        self._commands[action_name] = {
            "handler": handler,
            "required_cap": required_cap,
            "schema": schema
        }

    def get(self, action_name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a command definition by its action string.
        """
        return self._commands.get(action_name)

class SystemPlugin:
    """
    A core plugin that provides essential OS introspection tools.
    
    Design Decision: 
    Even core functionality is treated as a plugin to maintain 
    the modular architecture.
    """
    def __init__(self, registry: CommandRegistry, logger: logging.Logger):
        self.registry = registry
        self.logger = logger
        self.load()

    def load(self):
        """
        Registers standard system commands.
        """
        self.registry.register(
            action_name="system.echo",
            handler=self.cmd_echo,
            required_cap=Capability.FILE_READ,
            schema=["text"]
        )
        self.registry.register(
            action_name="system.info",
            handler=self.cmd_system_info,
            required_cap=Capability.SYSTEM_ADMIN,
            schema=[]
        )
        self.logger.info("Core SystemPlugin loaded.")

    async def cmd_echo(self, payload: Dict[str, Any], context: SecurityContext) -> Dict[str, Any]:
        """Simple echo command for connectivity testing."""
        return {"status": "success", "result": f"Node Echo: {payload['text']}"}

    async def cmd_system_info(self, payload: Dict[str, Any], context: SecurityContext) -> Dict[str, Any]:
        """Exposes node-level identity information."""
        import os
        return {
            "status": "success", 
            "result": {
                "pid": os.getpid(), 
                "identity": context.identity,
                "node_os": os.name
            }
        }

class PluginLoader:
    """
    Dynamic loader for external Py-Arch plugins.
    
    Failure Handling:
    - Wraps imports in try-except to prevent a single faulty plugin 
      from bricking the entire OS boot sequence.
    """
    def __init__(self, registry: CommandRegistry, logger: logging.Logger):
        self.registry = registry
        self.logger = logger

    def load_external_plugin(self, module_path: str):
        """
        Dynamically imports a Python module and initializes its plugin class.
        
        Expected interface: The module must have a 'PyArchPlugin' class.
        """
        try:
            # Dynamically import the module
            module = importlib.import_module(module_path)
            
            # Look for the standard PyArchPlugin entry point
            if hasattr(module, "PyArchPlugin"):
                plugin_class = getattr(module, "PyArchPlugin")
                plugin_class(self.registry, self.logger)
                self.logger.info(f"Successfully loaded plugin: {module_path}")
            else:
                self.logger.error(f"Plugin '{module_path}' missing 'PyArchPlugin' class.")
                
        except (ImportError, AttributeError) as e:
            self.logger.error(f"Plugin load failure for '{module_path}': {e}")
        except Exception as e:
            self.logger.critical(f"Critical error in plugin '{module_path}' initialization: {e}")
            self.logger.debug(traceback.format_exc())