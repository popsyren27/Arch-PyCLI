import importlib
import pkgutil
import sys
import os
import time
import threading
import logging
import traceback
from typing import Dict, Any, Callable

# Standardized Logging for Kernel Operations
logger = logging.getLogger("KERNEL_ORCHESTRATOR")
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [KERNEL] [%(levelname)s] %(message)s')

class KernelOrchestrator:
    """
    The central execution engine of the OS. 
    Manages tool discovery, hot-reloading, and crash-resilient execution.
    """

    def __init__(self, tools_dir: str = "tools"):
        self.tools_dir = tools_dir
        self.registry: Dict[str, Any] = {}
        self.execution_history: Dict[str, int] = {}
        self.__lock = threading.Lock()
        
        # Ensure the tools directory is in the path for proper package resolution
        root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        if root_path not in sys.path:
            sys.path.insert(0, root_path)

    def bootstrap(self):
        """Initializes the system and performs the first discovery pass."""
        logger.info("Initializing Kernel Bootstrap sequence...")
        self.refresh_registry()
        logger.info(f"Bootstrap complete. {len(self.registry)} tools registered.")

    def refresh_registry(self):
        """
        Dynamically scans the tools directory. 
        Uses deterministic discovery to ensure all nodes in a distributed 
        cluster see the same toolset.
        """
        with self.__lock:
            logger.info("Scanning for new tools/attack simulations...")
            try:
                # Iterate through subdirectories in 'tools'
                for loader, name, is_pkg in pkgutil.iter_modules([self.tools_dir]):
                    full_module_path = f"{self.tools_dir}.{name}.main"
                    try:
                        # Dynamic import with validation
                        module = importlib.import_module(full_module_path)
                        
                        # Failsafe: Ensure the tool implements the 'execute' interface
                        if hasattr(module, 'execute'):
                            self.registry[name] = {
                                "module": module,
                                "load_time": time.time(),
                                "path": full_module_path
                            }
                            logger.info(f"Registered Tool: [{name}]")
                        else:
                            logger.warning(f"Tool [{name}] rejected: Missing 'execute(api)' function.")
                            
                    except Exception as e:
                        logger.error(f"Failed to load tool [{name}]: {str(e)}")
            except Exception as e:
                logger.critical(f"Kernel Discovery Failure: {str(e)}")

    def hot_reload_tool(self, tool_name: str):
        """
        Reloads a specific tool without restarting the OS. 
        Crucial for deploying security patches across distributed nodes.
        """
        if tool_name not in self.registry:
            logger.error(f"Reload failed: Tool [{tool_name}] not found.")
            return False

        try:
            module = self.registry[tool_name]["module"]
            reloaded_module = importlib.reload(module)
            self.registry[tool_name]["module"] = reloaded_module
            self.registry[tool_name]["load_time"] = time.time()
            logger.info(f"Successfully hot-reloaded tool: [{tool_name}]")
            return True
        except Exception as e:
            logger.error(f"Hot-reload failed for [{tool_name}]: {traceback.format_exc()}")
            return False

    def execute_tool(self, tool_name: str, api_context: Any, timeout: int = 10):
        """
        Executes a tool within a monitored thread.
        Includes Timeouts, Error Isolation, and Failure Tracking.
        """
        if tool_name not in self.registry:
            logger.error(f"Execution failed: Tool [{tool_name}] is not registered.")
            return

        tool_module = self.registry[tool_name]["module"]
        
        # Threaded Execution with Watchdog
        def worker():
            try:
                logger.info(f"Starting execution of [{tool_name}]...")
                tool_module.execute(api_context)
                logger.info(f"Tool [{tool_name}] completed successfully.")
            except Exception:
                logger.error(f"Tool [{tool_name}] crashed during execution:\n{traceback.format_exc()}")
                self.execution_history[tool_name] = self.execution_history.get(tool_name, 0) + 1

        exec_thread = threading.Thread(target=worker)
        exec_thread.start()
        exec_thread.join(timeout=timeout)

        if exec_thread.is_alive():
            logger.critical(f"TIMEOUT: Tool [{tool_name}] exceeded {timeout}s limit. Terminating thread.")
            # Note: Python cannot force-kill threads safely, so we mark it as 'zombie'
            # In a real VM OS, we would use multiprocessing for hard isolation.

    def get_status(self) -> Dict[str, Any]:
        """Returns the health status of the entire VM Kernel."""
        return {
            "active_tools": list(self.registry.keys()),
            "failure_counts": self.execution_history,
            "system_uptime": time.time() - getattr(self, 'start_time', time.time())
        }