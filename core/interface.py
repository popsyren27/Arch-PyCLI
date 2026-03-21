import logging
import time
import threading
import os
from typing import Any, Dict, Optional

# Audit Log for all Userland-to-Kernel transitions
audit_logger = logging.getLogger("SYSTEM_CALL_INTERFACE")
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [SYSCALL] [%(levelname)s] %(message)s')

class SystemInterface:
    """
    The 'Gatekeeper' for the OS. 
    This is the ONLY object exposed to scripts in the /tools directory.
    """

    def __init__(self, kernel, security, network):
        # Private references to core components (Internal only)
        self.__kernel = kernel
        self.__security = security
        self.__network = network
        
        # Resource Tracking per Tool
        self.__call_counts: Dict[str, int] = {}
        self.__lock = threading.Lock()
        self.__rate_limit = 50  # Max calls per execution cycle

    def _increment_call(self, tool_name: str):
        """Enforces rate limiting to prevent DOS attacks from tools."""
        with self.__lock:
            count = self.__call_counts.get(tool_name, 0) + 1
            if count > self.__rate_limit:
                audit_logger.critical(f"RESOURCE EXHAUSTION: Tool [{tool_name}] exceeded rate limit!")
                raise PermissionError("System Call Rate Limit Exceeded.")
            self.__call_counts[tool_name] = count

    # --- AUTHORIZED SYSTEM CALLS (The API for Tools) ---

    def request_encryption(self, tool_name: str, plain_text: str, user_secret: str) -> bytes:
        """
        Proxies an encryption request to the SecurityKernel.
        The tool provides a secret, but the Kernel adds the Hardware DNA.
        """
        self._increment_call(tool_name)
        audit_logger.info(f"Tool [{tool_name}] requested hardware-bound encryption.")
        
        try:
            # Derive a key using the hardware-bound KDF
            salt = os.urandom(32)
            key = self.__security.derive_distributed_key(user_secret, salt)
            
            # Simple XOR simulation for this example; in production, use AES-GCM
            return bytes([b ^ key[i % len(key)] for i, b in enumerate(plain_text.encode())])
        except Exception as e:
            audit_logger.error(f"Encryption syscall failed for [{tool_name}]: {e}")
            return b""

    def broadcast_alert(self, tool_name: str, threat_level: str, details: str):
        """
        Allows a tool to report an 'Attack Simulation' result to the 
        entire distributed cluster via the Network Plane.
        """
        self._increment_call(tool_name)
        audit_logger.warning(f"Tool [{tool_name}] reporting cluster-wide alert: {threat_level}")
        
        # Package the alert for the Gossip Protocol
        payload = {
            "origin_tool": tool_name,
            "threat_level": threat_level,
            "details": details,
            "node_id": self.__network.node_id
        }
        
        # Async handoff to the network plane
        import asyncio
        asyncio.run_coroutine_threadsafe(
            self.__network.broadcast_security_event(payload),
            asyncio.get_event_loop()
        )

    def query_kernel_status(self, tool_name: str) -> Dict[str, Any]:
        """Allows tools to see OS health without touching the Kernel object."""
        self._increment_call(tool_name)
        status = self.__kernel.get_status()
        # Filter sensitive info before returning to userland
        return {
            "uptime": status["system_uptime"],
            "tool_registry_count": len(status["active_tools"])
        }

    def log_event(self, tool_name: str, message: str):
        """Standardized logging for all tool activities."""
        audit_logger.info(f"[USERLAND_MSG] [{tool_name}]: {message}")