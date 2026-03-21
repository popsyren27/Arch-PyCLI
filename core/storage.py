import os
import json
import logging
import hashlib
import time
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# High-fidelity logging for the Storage Plane
storage_logger = logging.getLogger("STORAGE_EVFS")
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [STORAGE] [%(levelname)s] %(message)s')

class EncryptedVFS:
    """
    Encrypted Virtual File System.
    Provides hardware-bound, authenticated storage with integrity checks.
    """

    def __init__(self, vault_path: str = "data/vault.bin", security_kernel=None):
        self.vault_path = vault_path
        self.__security = security_kernel
        self.__cache: Dict[str, Any] = {}
        self.__last_sync = 0.0
        
        # Ensure the data directory exists
        os.makedirs(os.path.dirname(self.vault_path), exist_ok=True)
        
        # Reliability check: Initial integrity scan
        if os.path.exists(self.vault_path):
            storage_logger.info("Existing Vault detected. Integrity check pending access.")
        else:
            storage_logger.info("Initializing new secure storage vault.")

    def _generate_nonce(self) -> bytes:
        """Standard 96-bit nonce for AES-GCM."""
        return os.urandom(12)

    def commit_state(self, tool_id: str, data: Dict[str, Any], user_secret: str):
        """
        Performs an Atomic Encrypted Write.
        If the process crashes mid-write, the old state remains valid.
        """
        try:
            # 1. Derive the Hardware-Bound Key via Security Kernel
            salt = os.urandom(16)
            # We call the Security Kernel's KDF we built in step 1
            key = self.__security.derive_distributed_key(user_secret, salt)
            
            # 2. Serialize and Encrypt
            aesgcm = AESGCM(key[:32]) # Use first 32 bytes for AES-256
            nonce = self._generate_nonce()
            
            raw_payload = json.dumps({
                "tool": tool_id,
                "timestamp": time.time(),
                "payload": data
            }).encode()
            
            ciphertext = aesgcm.encrypt(nonce, raw_payload, tool_id.encode())
            
            # 3. Atomic Write Pattern (Write to .tmp then rename)
            tmp_path = f"{self.vault_path}.tmp"
            with open(tmp_path, "wb") as f:
                f.write(salt)      # 16 bytes
                f.write(nonce)     # 12 bytes
                f.write(ciphertext)
            
            os.replace(tmp_path, self.vault_path)
            storage_logger.info(f"Atomic commit successful for tool: [{tool_id}]")
            
        except Exception as e:
            storage_logger.critical(f"STORAGE FAILURE: Could not commit state: {e}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def access_state(self, tool_id: str, user_secret: str) -> Optional[Dict[str, Any]]:
        """
        Decrypts and validates the integrity of the stored state.
        Fails if the Hardware ID has changed or the file was tampered with.
        """
        if not os.path.exists(self.vault_path):
            return None

        try:
            with open(self.vault_path, "rb") as f:
                salt = f.read(16)
                nonce = f.read(12)
                ciphertext = f.read()

            # 1. Re-derive the key using the stored salt and CURRENT hardware ID
            key = self.__security.derive_distributed_key(user_secret, salt)
            aesgcm = AESGCM(key[:32])

            # 2. Decrypt and Verify (AES-GCM checks the Auth Tag automatically)
            # tool_id is used as 'Additional Authenticated Data' (AAD)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, tool_id.encode())
            
            return json.loads(decrypted_data.decode())

        except Exception as e:
            # This is where 'Attack Simulations' will likely fail
            storage_logger.error(f"INTEGRITY VIOLATION: Access denied to vault for [{tool_id}].")
            storage_logger.error("Reason: Potential tampering or unauthorized hardware detected.")
            return None

    def wipe_vault(self):
        """Emergency Failsafe: Securely deletes the local storage."""
        if os.path.exists(self.vault_path):
            # Overwrite with random data before deletion (Sanitization)
            size = os.path.getsize(self.vault_path)
            with open(self.vault_path, "wb") as f:
                f.write(os.urandom(size))
            os.remove(self.vault_path)
            storage_logger.warning("Failsafe triggered: Vault securely wiped.")