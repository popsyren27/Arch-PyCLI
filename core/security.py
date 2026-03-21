import time
import secrets
import hashlib
import ctypes
import os
import base64
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class SecurityKernel:
    def __init__(self):
        # Path to store the unique "Lock" for this specific Arch installation
        self.salt_file = "core/.entropy_seed"
        self._salt = self._load_or_create_salt()
        
        self._master_key = None
        self._active_tokens = {}

    def _load_or_create_salt(self) -> bytes:
        """Ensures the encryption 'Salt' persists across reboots."""
        if os.path.exists(self.salt_file):
            with open(self.salt_file, "rb") as f:
                return f.read()
        else:
            # Create a permanent unique salt for this machine
            new_salt = secrets.token_bytes(32)
            os.makedirs(os.path.dirname(self.salt_file), exist_ok=True)
            with open(self.salt_file, "wb") as f:
                f.write(new_salt)
            return new_salt

    def bootstrap_kernel(self, master_key_input: str) -> bool:
        """
        Derives the session key from your password.
        This is the method main.py was looking for.
        """
        try:
            # PBKDF2 Key Stretching
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self._salt,
                iterations=480000,
                backend=default_backend()
            )
            self._master_key = kdf.derive(master_key_input.encode())
            
            # Security: Scrub the raw password from RAM immediately
            self._wipe_memory(master_key_input)
            return True
        except Exception as e:
            logging.error(f"BOOTSTRAP_FAILURE: {e}")
            return False

    def _wipe_memory(self, data):
        """Low-level memory scavenging."""
        if isinstance(data, (str, bytes)):
            try:
                location = id(data) + 20
                size = len(data)
                ctypes.memset(location, 0, size)
            except:
                pass

    def panic_self_destruct(self, reason: str):
        """Emergency wipe of the Master Key."""
        logging.critical(f"SELF_DESTRUCT_TRIGGERED: {reason}")
        if self._master_key:
            # Target the key buffer specifically
            self._wipe_memory(self._master_key)
            self._master_key = None
        # In a real panic, we'd exit here, but we'll let main.py handle the halt.

    def validate_token(self, token: str) -> bool:
        if token in self._active_tokens:
            if time.time() < self._active_tokens[token]:
                return True
            del self._active_tokens[token]
        return False

    def encrypt_field(self, data: str) -> bytes:
        if not self._master_key: raise PermissionError("Kernel Locked")
        aesgcm = AESGCM(self._master_key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
        return nonce + ciphertext

    def decrypt_field(self, encrypted_blob: bytes) -> str:
        if not self._master_key: raise PermissionError("Kernel Locked")
        aesgcm = AESGCM(self._master_key)
        nonce = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        return aesgcm.decrypt(nonce, ciphertext, None).decode()

# Global Instance
SEC_KERNEL = SecurityKernel()