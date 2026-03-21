import enum
from typing import List, Dict, Any, Optional
import logging

class Capability(enum.Enum):
    """
    Defines the granular permissions required to execute OS actions.
    
    Arch Philosophy: Capabilities are explicit and must be 
    granted to a context to allow operation.
    """
    PROCESS_SPAWN = "process:spawn"
    FILE_READ = "file:read"
    FILE_WRITE = "file:write"
    NETWORK_BIND = "network:bind"
    SYSTEM_ADMIN = "system:admin"

class SecurityContext:
    """
    Represents the authenticated identity and their associated capabilities.
    """
    def __init__(self, identity: str, capabilities: List[Capability], token: str):
        self.identity = identity
        self.capabilities = capabilities
        self.token = token

class SecurityManager:
    """
    Handles authentication, capability verification, and payload validation.
    
    Failure Handling:
    - If authentication fails, it returns an 'anonymous' context with zero 
      capabilities instead of raising an exception that could crash the node.
    - Uses 'Fail-Closed' logic: if a check is uncertain, it returns False.
    """
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
        # Mock database of authorized keys/tokens.
        # In a production distributed environment, this would interface 
        # with an SSH key agent or a centralized identity provider.
        self._authorized_keys = {
            "admin_token_123": SecurityContext("admin", list(Capability), "admin_token_123"),
            "guest_token_456": SecurityContext("guest", [Capability.FILE_READ], "guest_token_456")
        }

    def authenticate(self, auth_token: str) -> SecurityContext:
        """
        Validates a token and returns the security context.
        
        Design Decision: 
        Always returns a SecurityContext object to maintain type-safety 
        in the execution pipeline, even on failure.
        """
        try:
            if not auth_token:
                self.logger.warning("Authentication attempt with empty token.")
                return SecurityContext("anonymous", [], "")
            
            context = self._authorized_keys.get(auth_token)
            if not context:
                self.logger.warning(f"Failed authentication attempt with token: {auth_token[:4]}...")
                return SecurityContext("anonymous", [], "")
            
            return context
        except Exception as e:
            self.logger.error(f"Internal security manager error during auth: {e}")
            return SecurityContext("anonymous", [], "")

    def verify_capability(self, context: SecurityContext, required_cap: Capability) -> bool:
        """
        Checks if a context holds the required capability.
        SYSTEM_ADMIN bypasses all specific checks.
        """
        if Capability.SYSTEM_ADMIN in context.capabilities:
            return True
        
        if required_cap in context.capabilities:
            return True
            
        self.logger.error(f"Access Denied: '{context.identity}' lacks '{required_cap.value}'")
        return False

    def validate_payload(self, payload: Dict[str, Any], required_keys: List[str]) -> bool:
        """
        Performs basic input validation to ensure all required parameters 
        are present before a command is dispatched.
        """
        try:
            for key in required_keys:
                if key not in payload:
                    self.logger.error(f"Malformed payload: missing required key '{key}'")
                    return False
            return True
        except Exception as e:
            self.logger.error(f"Payload validation exception: {e}")
            return False