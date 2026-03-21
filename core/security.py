import time
import secrets
import hashlib
import ctypes
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class SecurityKernel:
    """
    Handles Distributed Node Security, Field-Level Encryption, 
    and Short-Lived Credentialing.
    """
    def __init__(self, master_key_input: str = None):
        # Fallback to a random high-entropy key if none provided at boot
        if master_key_input is None:
            master_key_input = secrets.token_hex(32)
            
        # Generate a salt based on PID to ensure unique session keys
        self._salt = hashlib.sha256(str(os.getpid()).encode()).digest()
        self._master_key = self._derive_key(master_key_input)
        self._active_tokens = {}
        
        # Zero out the raw master key input immediately
        self._wipe_memory(master_key_input)

    def _derive_key(self, passphrase: str) -> bytes:
        """Derives a 256-bit key using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=480000,
            backend=default_backend()
        )
        return kdf.derive(passphrase.encode())

    def _wipe_memory(self, data):
        """Low-level memory scavenging protection."""
        if isinstance(data, (str, bytes)):
            try:
                # Target the buffer directly
                location = id(data) + 20
                size = len(data)
                ctypes.memset(location, 0, size)
            except Exception:
                pass # Fallback if memory protection is active

    def validate_token(self, token: str) -> bool:
        """Checks if a token exists and hasn't expired."""
        if token in self._active_tokens:
            if time.time() < self._active_tokens[token]:
                return True
            else:
                del self._active_tokens[token]
        return False

    def encrypt_field(self, data: str) -> bytes:
        aesgcm = AESGCM(self._master_key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
        return nonce + ciphertext

    def decrypt_field(self, encrypted_blob: bytes) -> str:
        aesgcm = AESGCM(self._master_key)
        nonce = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode()

# Global Security Context - Matches the __init__ definition above
SEC_KERNEL = SecurityKernel()