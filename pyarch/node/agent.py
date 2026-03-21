import asyncio
import logging
from typing import Dict, Any, Optional

from pyarch.core.config import PyArchConfig, setup_logger
from pyarch.security.auth import SecurityManager, SecurityContext
from pyarch.process.scheduler import ProcessManager
from pyarch.ipc.network import IPCManager, Message
from pyarch.plugins.base import CommandRegistry, PluginLoader, SystemPlugin

class NodeAgent:
    """
    The central brain of a Py-Arch Node.
    
    The NodeAgent is responsible for:
    - Bootstrapping all core subsystems (Security, Process, IPC).
    - Managing the Command Registry and loading plugins.
    - Routing and executing incoming messages.
    - Ensuring system-wide error handling and graceful degradation.
    """
    def __init__(self, node_id: str):
        # 1. Initialize Configuration and Logging
        self.config = PyArchConfig(node_id)
        self.logger = setup_logger(node_id)
        
        self.logger.info(f"Initializing Py-Arch Node Agent: {node_id}")

        # 2. Initialize Core Subsystems
        self.security = SecurityManager(self.logger)
        self.process_manager = ProcessManager(self.logger)
        self.command_registry = CommandRegistry()
        self.plugin_loader = PluginLoader(self.command_registry, self.logger)
        
        # 3. Load Base Functionality
        # Treat the core system commands as a plugin to maintain modularity
        SystemPlugin(self.command_registry, self.logger)
        
        # 4. Initialize Networking/IPC
        self.ipc = IPCManager(self.config, self.logger, self)

    async def execute_message(self, message: Message) -> Dict[str, Any]:
        """
        The core execution pipeline for all OS actions.
        
        Execution Flow:
        1. Authenticate the token.
        2. Resolve the command from the registry.
        3. Verify user capabilities.
        4. Validate payload schema.
        5. Dispatch to the handler (with process/thread isolation if needed).
        """
        try:
            # 1. Authentication
            context: SecurityContext = self.security.authenticate(message.auth_token)
            if context.identity == "anonymous":
                return {"status": "error", "error": "Authentication required"}

            # 2. Command Resolution
            cmd_def = self.command_registry.get(message.action)
            if not cmd_def:
                self.logger.warning(f"Rejected unknown command: {message.action}")
                return {"status": "error", "error": f"Command '{message.action}' not found"}

            # 3. Authorization
            if not self.security.verify_capability(context, cmd_def["required_cap"]):
                return {"status": "error", "error": "Access denied: Insufficient capabilities"}

            # 4. Schema Validation
            if not self.security.validate_payload(message.payload, cmd_def["schema"]):
                return {"status": "error", "error": "Invalid command parameters"}

            # 5. Execution
            self.logger.info(f"Dispatching '{message.action}' for identity: {context.identity}")
            
            # Note: In a production environment, we would check the cmd_def to decide
            # if the handler should be wrapped in run_cpu_task or run_io_task.
            # Here we await the handler directly as plugins are expected to be async.
            result = await cmd_def["handler"](message.payload, context)
            return result

        except Exception as e:
            self.logger.critical(f"Kernel Panic (Message Execution Error): {e}")
            # Ensure the error is reported back to the sender rather than silent failure
            return {
                "status": "error", 
                "error": "Internal Node Execution Failure",
                "details": str(e)
            }

    async def boot(self):
        """
        Starts the Node Agent boot sequence.
        """
        self.logger.info(f"--- Booting Py-Arch OS Node: {self.config.node_id} ---")
        
        # Future: Add logic here to scan the 'plugins/' directory and 
        # auto-load found modules via self.plugin_loader.
        
        # Start the IPC Network Server (This will block until the server stops)
        try:
            await self.ipc.start_server()
        except asyncio.CancelledError:
            self.logger.info("Boot sequence cancelled.")
        finally:
            self.shutdown()

    def shutdown(self):
        """
        Performs a clean shutdown of all OS subsystems.
        """
        self.logger.info("Py-Arch Node Agent shutting down...")
        self.process_manager.shutdown()
        self.logger.info("All subsystems halted.")