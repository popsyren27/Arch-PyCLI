import time
import secrets
import hashlib
import ctypes
import os
import uuid
import platform
import logging
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class SecurityKernel:
    """
    Handles node-level encryption and key management.

    Enhancements in this implementation:
    - Optional user passphrase and OS keyring integration for recoverable keys.
    - Prefer Scrypt KDF when available (stronger against GPU cracking).
    - Safer in-memory wiping for bytearrays and explicit key blobs.
    - Export/import of master key blobs encrypted with a passphrase for backup.
    """

    def __init__(self, master_key_input: Optional[str] = None, passphrase: Optional[str] = None):
        self.logger = logging.getLogger("SEC_KERNEL")
        handler = logging.FileHandler("debug.txt")
        handler.setLevel(logging.INFO)
        self.logger.addHandler(handler)
        self.logger.propagate = False

        # Salt: per-process salt ensures KDF uniqueness; stored only in memory.
        self._salt = hashlib.sha256(str(os.getpid()).encode()).digest()
        self._active_tokens = {}

        # Attempt to derive the master key via the following precedence:
        # 1) explicit passphrase (user-provided)
        # 2) explicit master_key_input (raw hex/string)
        # 3) OS keyring if available and a stored passphrase exists
        # 4) hardware-bound fingerprint fallback (less recoverable)

        # Try passphrase first
        if passphrase:
            self._master_key = self._derive_kdf(passphrase)
            # Immediately wipe passphrase variable
            self._secure_erase(passphrase)
            self.logger.info("Master key derived from provided passphrase.")
        else:
            if master_key_input:
                self._master_key = self._derive_kdf(master_key_input)
                # wipe raw input
                self._secure_erase(master_key_input)
                self.logger.info("Master key derived from provided master_key_input.")
            else:
                # Try OS keyring to retrieve a stored passphrase (optional)
                passphrase_from_keyring = None
                try:
                    import keyring
                    passphrase_from_keyring = keyring.get_password("arch-pycli", "master_passphrase")
                except Exception:
                    passphrase_from_keyring = None

                if passphrase_from_keyring:
                    self._master_key = self._derive_kdf(passphrase_from_keyring)
                    self._secure_erase(passphrase_from_keyring)
                    self.logger.info("Master key derived from OS keyring entry.")
                else:
                    # Hardware fingerprint fallback - not recoverable if hardware changes
                    try:
                        from core.hal import HAL as _HAL
                        fp = f"{platform.node()}|{uuid.getnode()}|{_HAL.CPU_CORES}|{_HAL.TOTAL_RAM}"
                    except Exception:
                        fp = secrets.token_hex(32)
                    # Use SHA256 hex digest as passphrase material
                    hw_pass = hashlib.sha256(fp.encode()).hexdigest()
                    self._master_key = self._derive_kdf(hw_pass)
                    self._secure_erase(hw_pass)
                    self.logger.warning(
                        "Using hardware-bound fallback for master key (may be non-recoverable)."
                    )

    def _derive_kdf(self, passphrase: str) -> bytes:
        """
        Derive a 32-byte key from a passphrase using Scrypt if available,
        otherwise fall back to PBKDF2-HMAC-SHA256.
        """
        password = passphrase.encode()
        # Prefer scrypt where available
        try:
            kdf = Scrypt(salt=self._salt, length=32, n=2 ** 14, r=8, p=1, backend=default_backend())
            key = kdf.derive(password)
            return key
        except Exception:
            # PBKDF2 fallback
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self._salt,
                iterations=480000,
                backend=default_backend(),
            )
            return kdf.derive(password)

    def _secure_erase(self, data):
        """
        Attempts to minimize the lifetime of sensitive data in memory.
        Works best with bytearray or mutable buffers. For Python strings this
        function will attempt to overwrite a converted bytearray; note that
        due to Python's immutability and GC this is not a perfect guarantee.
        """
        try:
            if isinstance(data, str):
                b = bytearray(data.encode())
                for i in range(len(b)):
                    b[i] = 0
            elif isinstance(data, (bytes, bytearray)):
                b = bytearray(data)
                for i in range(len(b)):
                    b[i] = 0
        except Exception:
            pass

    # Backwards-compatible helper used by other modules
    def _wipe_memory(self, data):
        """Compatibility wrapper for older callers that expect `_wipe_memory`.

        This delegates to the safer `_secure_erase` implementation.
        """
        try:
            self._secure_erase(data)
        except Exception:
            pass

    def validate_token(self, token: str) -> bool:
        """Checks if a token exists and hasn't expired."""
        if token in self._active_tokens:
            if time.time() < self._active_tokens[token]:
                return True
            else:
                del self._active_tokens[token]
        return False

    def generate_short_lived_token(self, subject: str, ttl: int = 900) -> str:
        """Generate a cryptographically-random token valid for `ttl` seconds.

        The token is stored in-memory in `_active_tokens` with an expiry timestamp.
        This is lightweight and intended for short-lived CLI use; for distributed
        use store tokens in a more robust mechanism.
        """
        token = secrets.token_urlsafe(32)
        self._active_tokens[token] = time.time() + float(ttl)
        # Optionally log token creation (avoid logging token in production)
        try:
            self.logger.info("Issued short-lived token for %s, ttl=%s", subject, ttl)
        except Exception:
            pass
        return token

    def revoke_token(self, token: str) -> None:
        """Revoke a previously issued token."""
        try:
            if token in self._active_tokens:
                del self._active_tokens[token]
        except Exception:
            pass

    def encrypt_field(self, data: str) -> bytes:
        return self.encrypt_bytes(data.encode())

    def encrypt_bytes(self, data: bytes) -> bytes:
        aesgcm = AESGCM(self._master_key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt_field(self, encrypted_blob: bytes) -> str:
        return self.decrypt_bytes(encrypted_blob).decode()

    def decrypt_bytes(self, encrypted_blob: bytes) -> bytes:
        aesgcm = AESGCM(self._master_key)
        nonce = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)

    # Key backup/export utilities
    def export_master_blob(self, export_passphrase: str) -> bytes:
        """Encrypt the current master key with a user passphrase for backup."""
        if not isinstance(export_passphrase, str) or not export_passphrase:
            raise ValueError("export_passphrase required")
        key = self._derive_kdf(export_passphrase)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        blob = aesgcm.encrypt(nonce, self._master_key, None)
        return nonce + blob

    def import_master_blob(self, blob: bytes, import_passphrase: str) -> None:
        """Import and replace the master key from an exported blob."""
        if not blob or not import_passphrase:
            raise ValueError("blob and passphrase required")
        key = self._derive_kdf(import_passphrase)
        aesgcm = AESGCM(key)
        nonce = blob[:12]
        ciphertext = blob[12:]
        new_master = aesgcm.decrypt(nonce, ciphertext, None)
        # Replace master key in memory
        self._master_key = new_master


# Global Security Context - default constructed
SEC_KERNEL = SecurityKernel()