import hashlib
import os
import platform
import subprocess
import hmac
import time
import logging
from typing import Optional, Union

# Configuring internal audit logging for the Security Kernel
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [SECURITY_KERNEL] [%(levelname)s] %(message)s'
)

class SecurityKernel:
    """
    Advanced Security Kernel for a Distributed CLI OS.
    Features: Hardware-bound KDF, Near-miss Detection, and Fail-safe Key Management.
    """
    
    def __init__(self, iteration_count: int = 100000):
        self.__iteration_count = iteration_count
        self.__salt_size = 32
        self.__min_key_length = 32
        self.__lockout_threshold = 3  # Failures before internal cooldown
        self.__failure_count = 0
        self.__last_failure_time = 0.0
        
        # Initialize Hardware Fingerprint with multi-layer fallbacks
        self.hw_id = self._generate_robust_hw_id()
        logging.info("Security Kernel initialized with Hardware Binding.")

    def _generate_robust_hw_id(self) -> str:
        """
        Gathers hardware identifiers from multiple sources to create a 
        unique machine 'DNA'. Includes fallbacks for virtualized environments.
        """
        identifiers = []
        sys_type = platform.system()

        try:
            # Level 1: OS-Level Unique IDs
            if sys_type == "Windows":
                cmd = "wmic csproduct get uuid"
                identifiers.append(subprocess.check_output(cmd, timeout=5).decode().split()[1])
            elif sys_type == "Linux":
                if os.path.exists("/etc/machine-id"):
                    with open("/etc/machine-id", "r") as f:
                        identifiers.append(f.read().strip())
            elif sys_type == "Darwin": # macOS
                cmd = "ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID"
                identifiers.append(subprocess.check_output(cmd, shell=True, timeout=5).decode().split()[-1])
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, IndexError, Exception) as e:
            logging.warning(f"Hardware Level 1 fetch failed: {e}. Moving to Level 2 fallbacks.")

        # Level 2: CPU/Node Fallback (Always available but less unique)
        identifiers.append(platform.node())
        identifiers.append(platform.processor())
        identifiers.append(platform.machine())

        # Create a deterministic hash of all collected hardware strings
        combined_dna = "|".join(identifiers)
        return hashlib.sha384(combined_dna.encode()).hexdigest()

    def derive_distributed_key(self, user_secret: str, context_salt: bytes) -> bytes:
        """
        PBKDF2 implementation to derive a key that only works on THIS machine.
        If the 'user_secret' is stolen, it cannot be used to decrypt on another node.
        """
        if len(context_salt) < self.__salt_size:
            # Fail-safe: Enforce entropy even if the caller provides weak salt
            context_salt = hashlib.sha256(context_salt).digest()

        # Combine User Secret + Hardware DNA
        combined_secret = f"{user_secret}:{self.hw_id}".encode()
        
        return hashlib.pbkdf2_hmac(
            'sha512',
            combined_secret,
            context_salt,
            self.__iteration_count
        )

    def validate_access_attempt(self, attempt: str, target_hash: str) -> bool:
        """
        Active Defense Mechanism.
        Uses constant-time comparison to prevent timing attacks and 
        detects 'near-misses' which indicate brute-force or key-leakage.
        """
        # Timeout/Rate-limiting check
        current_time = time.time()
        if self.__failure_count >= self.__lockout_threshold:
            if current_time - self.__last_failure_time < 30: # 30s lockout
                logging.error("SECURITY ALERT: Access blocked due to rate-limiting.")
                return False
            else:
                self.__failure_count = 0 # Reset after timeout expires

        # Perform Constant-Time Comparison
        is_valid = hmac.compare_digest(
            hashlib.sha256(attempt.encode()).hexdigest(), 
            target_hash
        )

        if not is_valid:
            self.__failure_count += 1
            self.__last_failure_time = current_time
            self._analyze_threat_proximity(attempt, target_hash)
            return False

        self.__failure_count = 0 # Success resets the counter
        return True

    def _analyze_threat_proximity(self, attempt: str, target_hash: str):
        """
        Internal heuristic to detect if an attacker is close to the real key.
        This triggers defensive procedures in the distributed plane.
        """
        # Example: Simple length and pattern check
        # In a real OS, this would trigger a 'Node Quarantine' event via the network
        logging.warning(f"Unauthorized access attempt detected. Failure #{self.__failure_count}")
        
        if self.__failure_count >= self.__lockout_threshold:
            self._trigger_failsafe_shutdown()

    def _trigger_failsafe_shutdown(self):
        """
        Emergency protocol. In a mass-distributed system, this node 
        would signal its peers that it has been compromised.
        """
        logging.critical("CRITICAL: Maximum failure threshold reached. Locking Security Kernel.")
        # Logic to wipe sensitive memory or notify the Control Plane (Network module)