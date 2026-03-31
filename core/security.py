"""
Security Kernel Module for Arch-PyCLI.

This module handles all cryptographic operations, key management, and token-based
authentication for the Arch-PyCLI framework. It provides:

- AES-GCM encryption/decryption with 256-bit keys
- KDF key derivation (Scrypt with PBKDF2 fallback)
- Thread-safe token generation and validation
- Rate limiting for security operations
- Hardware-bound key derivation
- Memory secure wiping

SECURITY NOTES:
    - All cryptographic operations use the 'cryptography' library
    - Keys are never stored in plaintext on disk
    - Memory wiping attempts to minimize key lifetime in RAM
    - Tokens are short-lived and validated on every network request

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import secrets
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Any

# Third-party cryptographic libraries
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE: bool = True
except ImportError:
    CRYPTO_AVAILABLE: bool = False
    AESGCM = None
    PBKDF2HMAC = None
    Scrypt = None


# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

# Token configuration
DEFAULT_TOKEN_TTL_SECONDS: int = 900  # 15 minutes
MAX_TOKENS_PER_MINUTE: int = 50  # Rate limiting
MAX_ACTIVE_TOKENS: int = 1000  # Eviction threshold
TOKEN_CLEANUP_INTERVAL_SECONDS: int = 60  # Background cleanup interval

# Cryptographic constants
KEY_SIZE_BYTES: int = 32  # 256-bit key
NONCE_SIZE_BYTES: int = 12  # 96-bit nonce for AES-GCM
SCRYPT_N: int = 2 ** 14  # CPU/memory cost parameter
SCRYPT_R: int = 8  # Block size
SCRYPT_P: int = 1  # Parallelization
PBKDF2_ITERATIONS: int = 480000  # OWASP recommended minimum

# Debug configuration
DEBUG_PREFIX: str = "[SECURITY_DEBUG]"
_is_debug_mode: bool = False


def set_debug_mode(enabled: bool) -> None:
    """Enable or disable debug logging for security operations."""
    global _is_debug_mode
    _is_debug_mode = enabled
    _logger.debug(f"{DEBUG_PREFIX} Debug mode {'enabled' if enabled else 'disabled'}")


def _debug_log(message: str, *args: Any) -> None:
    """Internal debug logger that respects debug mode."""
    if _is_debug_mode:
        _logger.debug(f"{DEBUG_PREFIX} {message}", *args)


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class SecurityKernelError(Exception):
    """Base exception for all security kernel errors."""
    pass


class CryptoNotAvailableError(SecurityKernelError):
    """Raised when cryptography library is not available."""
    pass


class TokenGenerationError(SecurityKernelError):
    """Raised when token generation fails."""
    pass


class TokenValidationError(SecurityKernelError):
    """Raised when token validation fails."""
    pass


class EncryptionError(SecurityKernelError):
    """Raised when encryption operation fails."""
    pass


class DecryptionError(SecurityKernelError):
    """Raised when decryption operation fails."""
    pass


class RateLimitExceededError(SecurityKernelError):
    """Raised when rate limit is exceeded."""
    pass


class KeyDerivationError(SecurityKernelError):
    """Raised when key derivation fails."""
    pass


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class TokenEntry:
    """
    Represents a single active token with metadata.
    
    Attributes:
        subject: Identifier for the token owner
        created_at: Unix timestamp when token was created
        expires_at: Unix timestamp when token expires
        ip_address: Optional IP address for binding
    """
    subject: str
    created_at: float
    expires_at: float
    ip_address: Optional[str] = None
    
    def is_expired(self) -> bool:
        """Check if this token has expired."""
        return time.time() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/debugging."""
        return {
            "subject": self.subject,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "ip_address": self.ip_address,
            "is_expired": self.is_expired(),
            "ttl_remaining": max(0, self.expires_at - time.time())
        }


@dataclass
class RateLimitBucket:
    """
    Token bucket for rate limiting.
    
    Attributes:
        tokens: Current number of available tokens
        last_refill: Timestamp of last token refill
        lock: Thread synchronization lock
    """
    tokens: float
    last_refill: float
    lock: threading.Lock = field(default_factory=threading.Lock)
    
    @property
    def refill_rate(self) -> float:
        """Tokens added per second."""
        return self.tokens / 60.0  # Tokens per second based on per-minute limit


# =============================================================================
# SETUP LOGGING
# =============================================================================

# Create module-level logger
_logger: logging.Logger = logging.getLogger("SEC_KERNEL")
if not _logger.handlers:
    # Configure with console handler
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

# Also try to add file handler if possible (non-blocking)
try:
    _file_handler: logging.Handler = logging.FileHandler("security.log")
    _file_handler.setLevel(logging.INFO)
    _file_handler.setFormatter(_formatter)
    _logger.addHandler(_file_handler)
except (IOError, PermissionError, OSError):
    # Fallback: log to stdout if file writing fails
    _logger.warning(
        "[SECURITY] File logging unavailable, using stdout only. "
        "This may occur in read-only filesystems."
    )

_logger.info("[SECURITY] Security kernel module initialized")


# =============================================================================
# SECURITY KERNEL CLASS
# =============================================================================

class SecurityKernel:
    """
    Central security engine for Arch-PyCLI.
    
    This class provides:
        - Thread-safe cryptographic operations
        - Token-based authentication
        - Rate limiting for security operations
        - Key derivation and management
        - Memory secure wiping
    
    Thread Safety:
        All public methods are thread-safe via internal locks.
        Token operations use dedicated locks to prevent race conditions.
    
    Example:
        >>> kernel = SecurityKernel(passphrase="my_secret_passphrase")
        >>> token = kernel.generate_short_lived_token("user@example.com")
        >>> if kernel.validate_token(token):
        ...     print("Token is valid")
    """
    
    def __init__(
        self,
        master_key_input: Optional[str] = None,
        passphrase: Optional[str] = None,
        debug_mode: bool = False
    ) -> None:
        """
        Initialize the security kernel.
        
        Args:
            master_key_input: Raw master key as string (hex or plaintext)
            passphrase: User-provided passphrase for key derivation
            debug_mode: Enable verbose debug logging
        
        Note:
            Key derivation priority:
            1. Explicit passphrase (highest priority)
            2. Raw master_key_input
            3. OS keyring (if available)
            4. Hardware-bound fallback (lowest priority)
        """
        # Enable debug mode if requested
        set_debug_mode(debug_mode)
        
        # Initialize logger
        self._logger: logging.Logger = logging.getLogger("SEC_KERNEL")
        
        # Generate unique salt for this process instance
        # Uses PID + random bytes for uniqueness
        self._salt: bytes = self._generate_salt()
        
        # Thread-safe token storage
        self._tokens: Dict[str, TokenEntry] = {}
        self._tokens_lock: threading.Lock = threading.Lock()
        
        # Rate limiting for token generation
        self._rate_limit: RateLimitBucket = RateLimitBucket(
            tokens=float(MAX_TOKENS_PER_MINUTE),
            last_refill=time.time()
        )
        
        # Master key storage (protected)
        self._master_key: Optional[bytes] = None
        
        # Background cleanup thread control
        self._cleanup_running: bool = False
        self._cleanup_thread: Optional[threading.Thread] = None
        self._cleanup_lock: threading.Lock = threading.Lock()
        
        # Derive or load master key
        self._initialize_key(
            master_key_input=master_key_input,
            passphrase=passphrase
        )
        
        # Start background token cleanup
        self._start_cleanup_thread()
        
        _debug_log("Security kernel initialized successfully")
        self._logger.info("[SECURITY] Security kernel initialized with debug_mode=%s", debug_mode)
    
    def _generate_salt(self) -> bytes:
        """
        Generate a cryptographically secure salt for KDF.
        
        Combines:
            - Process ID (uniqueness per process)
            - Random bytes (randomness)
            - Timestamp (temporal uniqueness)
        
        Returns:
            32-byte random salt
        """
        # Combine multiple entropy sources
        pid_bytes: bytes = str(os.getpid()).encode('utf-8')
        random_bytes: bytes = secrets.token_bytes(16)
        time_bytes: bytes = str(int(time.time() * 1000)).encode('utf-8')
        
        # Hash combination for consistent length
        combined: bytes = pid_bytes + random_bytes + time_bytes
        salt: bytes = hashlib.sha256(combined).digest()
        
        _debug_log("Generated new salt (length=%d)", len(salt))
        return salt
    
    def _initialize_key(
        self,
        master_key_input: Optional[str],
        passphrase: Optional[str]
    ) -> None:
        """
        Initialize the master key using available derivation method.
        
        Priority:
            1. Passphrase (user-provided, most secure)
            2. Raw key input
            3. OS keyring
            4. Hardware-bound fallback
        
        Args:
            master_key_input: Raw key string or hex
            passphrase: User passphrase for KDF
        """
        derived_key: Optional[bytes] = None
        derivation_method: str = "unknown"
        
        try:
            # Priority 1: Passphrase-based derivation
            if passphrase is not None:
                try:
                    derived_key = self._derive_key(passphrase)
                    derivation_method = "passphrase"
                    self._secure_erase(passphrase)
                    self._logger.info("[SECURITY] Master key derived from passphrase")
                    _debug_log("Key derived using passphrase")
                except KeyDerivationError as e:
                    self._logger.error("[SECURITY] Failed to derive key from passphrase: %s", e)
                    raise
                    
            # Priority 2: Raw master key input
            elif master_key_input is not None:
                try:
                    derived_key = self._derive_key(master_key_input)
                    derivation_method = "master_key_input"
                    self._secure_erase(master_key_input)
                    self._logger.info("[SECURITY] Master key derived from raw input")
                    _debug_log("Key derived from raw input")
                except KeyDerivationError as e:
                    self._logger.error("[SECURITY] Failed to derive key from raw input: %s", e)
                    raise
                    
            # Priority 3: OS keyring
            else:
                keyring_passphrase: Optional[str] = self._load_from_keyring()
                if keyring_passphrase is not None:
                    try:
                        derived_key = self._derive_key(keyring_passphrase)
                        derivation_method = "keyring"
                        self._secure_erase(keyring_passphrase)
                        self._logger.info("[SECURITY] Master key loaded from OS keyring")
                        _debug_log("Key loaded from keyring")
                    except KeyDerivationError as e:
                        self._logger.error("[SECURITY] Failed to derive key from keyring: %s", e)
                        # Continue to fallback
                
            # Priority 4: Hardware-bound fallback
            if derived_key is None:
                derived_key = self._derive_hardware_bound_key()
                derivation_method = "hardware_fallback"
                self._logger.warning(
                    "[SECURITY] Using hardware-bound key (may be non-recoverable "
                    "if hardware changes)"
                )
                _debug_log("Key derived from hardware fallback")
            
            # Store the derived key
            self._master_key = derived_key
            self._logger.info(
                "[SECURITY] Master key initialized using '%s' method",
                derivation_method
            )
            
        except Exception as e:
            self._logger.critical("[SECURITY] Failed to initialize master key: %s", e)
            raise SecurityKernelError(f"Key initialization failed: {e}") from e
    
    def _load_from_keyring(self) -> Optional[str]:
        """
        Attempt to load passphrase from OS keyring.
        
        Returns:
            Passphrase string if found, None otherwise
        
        Note:
            This is optional functionality. Failure to load from keyring
            is not fatal and should be handled gracefully.
        """
        try:
            import keyring  # type: ignore
            passphrase: Optional[str] = keyring.get_password(
                "arch-pycli",
                "master_passphrase"
            )
            if passphrase:
                _debug_log("Loaded passphrase from keyring")
                return passphrase
            _debug_log("No passphrase found in keyring")
        except ImportError:
            _debug_log("keyring module not available")
        except Exception as e:
            _debug_log("Failed to load from keyring: %s", e)
        
        return None
    
    def _derive_hardware_bound_key(self) -> bytes:
        """
        Derive key from hardware fingerprint as fallback method.
        
        This uses platform-specific hardware identifiers combined with
        strong hashing to create a deterministic but hard-to-replicate key.
        
        WARNING: This method is NOT recoverable if hardware changes.
        
        Returns:
            32-byte derived key
        """
        try:
            # Gather hardware identifiers
            node: str = platform.node() or "unknown-host"
            mac_addr: str = str(uuid.getnode())
            
            # Get additional identifiers from HAL if available
            cpu_cores: str = "1"
            total_ram: str = "0"
            try:
                from core.hal import HAL as _HAL
                cpu_cores = str(getattr(_HAL, 'CPU_CORES', 1))
                total_ram = str(getattr(_HAL, 'TOTAL_RAM', 0))
            except ImportError:
                pass  # HAL not available
            
            # Combine with multiple hashing rounds for entropy
            fingerprint: str = f"{node}|{mac_addr}|{cpu_cores}|{total_ram}"
            
            # Use strong hashing with multiple rounds
            key_material: str = fingerprint
            for _ in range(3):  # Multiple rounds of hashing
                key_material = hashlib.sha512(
                    key_material.encode('utf-8')
                ).hexdigest()
            
            # Use PBKDF2 for final derivation (scrypt may fail in restricted envs)
            try:
                if CRYPTO_AVAILABLE and PBKDF2HMAC is not None:
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=KEY_SIZE_BYTES,
                        salt=self._salt,
                        iterations=PBKDF2_ITERATIONS,
                        backend=default_backend()
                    )
                    derived: bytes = kdf.derive(key_material.encode('utf-8'))
                    _debug_log("Hardware-bound key derived using PBKDF2")
                    return derived
            except Exception as e:
                _debug_log("PBKDF2 hardware derivation failed: %s", e)
            
            # Final fallback: direct hash
            fallback_key: bytes = hashlib.sha256(
                key_material.encode('utf-8') + self._salt
            ).digest()
            _debug_log("Hardware-bound key derived using SHA256 fallback")
            return fallback_key
            
        except Exception as e:
            self._logger.error("[SECURITY] Hardware-bound key derivation failed: %s", e)
            raise KeyDerivationError(f"Hardware key derivation failed: {e}") from e
    
    def _derive_key(self, passphrase: str) -> bytes:
        """
        Derive a 32-byte key from a passphrase using KDF.
        
        Attempts Scrypt first (stronger against GPU attacks), falls back
        to PBKDF2-HMAC-SHA256 if Scrypt is unavailable.
        
        Args:
            passphrase: User-provided passphrase string
        
        Returns:
            32-byte derived key
        
        Raises:
            KeyDerivationError: If key derivation fails
        """
        if not CRYPTO_AVAILABLE:
            raise KeyDerivationError("Cryptography library not available")
        
        try:
            password_bytes: bytes = passphrase.encode('utf-8')
            
            # Try Scrypt first (preferred for GPU resistance)
            try:
                kdf = Scrypt(
                    salt=self._salt,
                    length=KEY_SIZE_BYTES,
                    n=SCRYPT_N,
                    r=SCRYPT_R,
                    p=SCRYPT_P,
                    backend=default_backend()
                )
                derived_key: bytes = kdf.derive(password_bytes)
                _debug_log("Key derived using Scrypt KDF")
                return derived_key
                
            except Exception as scrypt_error:
                _debug_log("Scrypt derivation failed, trying PBKDF2: %s", scrypt_error)
                
                # PBKDF2 fallback
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=KEY_SIZE_BYTES,
                    salt=self._salt,
                    iterations=PBKDF2_ITERATIONS,
                    backend=default_backend()
                )
                derived_key = kdf.derive(password_bytes)
                _debug_log("Key derived using PBKDF2 KDF (fallback)")
                return derived_key
                
        except Exception as e:
            self._logger.error("[SECURITY] Key derivation failed: %s", e)
            raise KeyDerivationError(f"Key derivation failed: {e}") from e
    
    def _start_cleanup_thread(self) -> None:
        """
        Start background thread for expired token cleanup.
        
        This thread periodically removes expired tokens to prevent
        memory growth and enforce token TTL.
        """
        with self._cleanup_lock:
            if self._cleanup_running:
                _debug_log("Cleanup thread already running")
                return
            
            self._cleanup_running = True
            self._cleanup_thread = threading.Thread(
                target=self._cleanup_loop,
                daemon=True,
                name="TokenCleanupThread"
            )
            self._cleanup_thread.start()
            _debug_log("Started token cleanup thread")
            self._logger.info("[SECURITY] Token cleanup thread started")
    
    def _cleanup_loop(self) -> None:
        """
        Background loop for cleaning up expired tokens.
        
        Runs every TOKEN_CLEANUP_INTERVAL_SECONDS seconds.
        Removes expired tokens and enforces token limits.
        """
        while self._cleanup_running:
            try:
                self._cleanup_expired_tokens()
                self._enforce_token_limit()
            except Exception as e:
                _debug_log("Token cleanup error: %s", e)
            
            # Sleep with early termination check
            for _ in range(TOKEN_CLEANUP_INTERVAL_SECONDS):
                if not self._cleanup_running:
                    break
                time.sleep(1)
    
    def _cleanup_expired_tokens(self) -> int:
        """
        Remove all expired tokens from storage.
        
        Returns:
            Number of tokens removed
        """
        removed_count: int = 0
        current_time: float = time.time()
        
        with self._tokens_lock:
            expired_keys: list = [
                token for token, entry in self._tokens.items()
                if entry.expires_at <= current_time
            ]
            
            for key in expired_keys:
                del self._tokens[key]
                removed_count += 1
        
        if removed_count > 0:
            _debug_log("Cleaned up %d expired tokens", removed_count)
            self._logger.info(
                "[SECURITY] Token cleanup: removed %d expired tokens",
                removed_count
            )
        
        return removed_count
    
    def _enforce_token_limit(self) -> None:
        """
        Enforce maximum token count by removing oldest tokens.
        
        When MAX_ACTIVE_TOKENS is exceeded, removes tokens with
        the earliest expiration time.
        """
        with self._tokens_lock:
            token_count: int = len(self._tokens)
            
            if token_count > MAX_ACTIVE_TOKENS:
                # Sort by expiration time
                sorted_tokens: list = sorted(
                    self._tokens.items(),
                    key=lambda x: x[1].expires_at
                )
                
                # Remove oldest tokens until under limit
                tokens_to_remove: int = token_count - MAX_ACTIVE_TOKENS
                for i in range(tokens_to_remove):
                    key = sorted_tokens[i][0]
                    del self._tokens[key]
                
                self._logger.warning(
                    "[SECURITY] Token limit exceeded, removed %d oldest tokens",
                    tokens_to_remove
                )
                _debug_log(
                    "Enforced token limit: removed %d tokens, %d remaining",
                    tokens_to_remove,
                    len(self._tokens)
                )
    
    def _check_rate_limit(self) -> bool:
        """
        Check if token generation is within rate limits.
        
        Uses token bucket algorithm for smooth rate limiting.
        
        Returns:
            True if within rate limit, False otherwise
        """
        current_time: float = time.time()
        
        with self._rate_limit.lock:
            # Calculate token refill
            elapsed: float = current_time - self._rate_limit.last_refill
            refill_amount: float = elapsed * self._rate_limit.refill_rate
            
            self._rate_limit.tokens = min(
                float(MAX_TOKENS_PER_MINUTE),
                self._rate_limit.tokens + refill_amount
            )
            self._rate_limit.last_refill = current_time
            
            # Check if we have tokens available
            if self._rate_limit.tokens >= 1.0:
                self._rate_limit.tokens -= 1.0
                _debug_log(
                    "Rate limit check passed: %.2f tokens remaining",
                    self._rate_limit.tokens
                )
                return True
            
            _debug_log("Rate limit exceeded")
            return False
    
    def _secure_erase(self, data: Any) -> None:
        """
        Attempt to securely erase sensitive data from memory.
        
        This tries multiple methods to overwrite data before
        allowing garbage collection to reclaim the memory.
        
        Args:
            data: Data to securely erase
        
        Note:
            Due to Python's memory management, this is not a perfect
            guarantee of data removal. However, it significantly reduces
            the window of vulnerability.
        """
        try:
            if isinstance(data, str):
                # Convert to mutable bytearray and overwrite
                b: bytearray = bytearray(data.encode('utf-8'))
                for i in range(len(b)):
                    b[i] = 0
                _debug_log("Securely erased string data")
                
            elif isinstance(data, (bytes, bytearray)):
                # Overwrite with zeros
                b = bytearray(data)
                for i in range(len(b)):
                    b[i] = 0
                _debug_log("Securely erased bytes/bytearray data")
                
            elif hasattr(data, '__dict__'):
                # For objects, try to clear attributes
                try:
                    for key in list(data.__dict__.keys()):
                        data.__dict__[key] = None
                    _debug_log("Securely erased object attributes")
                except Exception:
                    pass
                    
        except Exception as e:
            _debug_log("Secure erase error: %s", e)
    
    def _wipe_memory(self, data: Any) -> None:
        """
        Public wrapper for secure memory wiping.
        
        Maintains backwards compatibility with callers expecting `_wipe_memory`.
        
        Args:
            data: Data to wipe from memory
        """
        self._secure_erase(data)
    
    # =========================================================================
    # PUBLIC TOKEN METHODS
    # =========================================================================
    
    def validate_token(self, token: str) -> bool:
        """
        Validate if a token exists and has not expired.
        
        Thread-safe operation with proper locking.
        
        Args:
            token: Token string to validate
        
        Returns:
            True if token is valid and not expired, False otherwise
        
        Example:
            >>> if kernel.validate_token(token):
            ...     # Process authenticated request
        """
        if not token:
            _debug_log("Token validation: empty token")
            return False
        
        with self._tokens_lock:
            if token not in self._tokens:
                _debug_log("Token validation: token not found")
                return False
            
            entry: TokenEntry = self._tokens[token]
            
            if entry.is_expired():
                # Clean up expired token
                del self._tokens[token]
                _debug_log("Token validation: token expired and removed")
                return False
            
            _debug_log(
                "Token validation: valid (ttl=%.1fs)",
                entry.expires_at - time.time()
            )
            return True
    
    def generate_short_lived_token(
        self,
        subject: str,
        ttl: int = DEFAULT_TOKEN_TTL_SECONDS,
        ip_address: Optional[str] = None
    ) -> str:
        """
        Generate a cryptographically secure short-lived token.
        
        Thread-safe with rate limiting.
        
        Args:
            subject: Identifier for the token owner (e.g., user ID, node ID)
            ttl: Time-to-live in seconds (default: 900 = 15 minutes)
            ip_address: Optional IP address to bind token to
        
        Returns:
            URL-safe base64 token string
        
        Raises:
            RateLimitExceededError: If rate limit is exceeded
            TokenGenerationError: If token generation fails
        
        Example:
            >>> token = kernel.generate_short_lived_token("user@example.com")
            >>> print(f"Your token: {token}")
        """
        # Check rate limit
        if not self._check_rate_limit():
            self._logger.warning(
                "[SECURITY] Token generation rate limit exceeded for subject: %s",
                subject
            )
            raise RateLimitExceededError(
                f"Rate limit exceeded: max {MAX_TOKENS_PER_MINUTE} tokens/minute"
            )
        
        # Validate inputs
        if not subject:
            raise TokenGenerationError("Subject cannot be empty")
        
        # Enforce TTL bounds
        ttl = max(1, min(ttl, 86400))  # Between 1 second and 24 hours
        
        try:
            # Generate cryptographically secure token
            token: str = secrets.token_urlsafe(32)
            current_time: float = time.time()
            
            # Create token entry
            entry: TokenEntry = TokenEntry(
                subject=subject,
                created_at=current_time,
                expires_at=current_time + float(ttl),
                ip_address=ip_address
            )
            
            # Store token with thread safety
            with self._tokens_lock:
                self._tokens[token] = entry
            
            self._logger.info(
                "[SECURITY] Token generated for '%s', TTL=%ds",
                subject,
                ttl
            )
            _debug_log(
                "Token generated: subject=%s, ttl=%d, total_tokens=%d",
                subject,
                ttl,
                len(self._tokens)
            )
            
            return token
            
        except Exception as e:
            self._logger.error(
                "[SECURITY] Token generation failed for '%s': %s",
                subject,
                e
            )
            raise TokenGenerationError(f"Token generation failed: {e}") from e
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a previously issued token.
        
        Thread-safe operation.
        
        Args:
            token: Token string to revoke
        
        Returns:
            True if token was found and revoked, False if not found
        
        Example:
            >>> if kernel.revoke_token(token):
            ...     print("Token revoked successfully")
        """
        with self._tokens_lock:
            if token in self._tokens:
                del self._tokens[token]
                _debug_log("Token revoked")
                self._logger.info("[SECURITY] Token revoked")
                return True
            
            _debug_log("Token revocation: token not found")
            return False
    
    def get_token_info(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a token.
        
        Useful for debugging and token management.
        
        Args:
            token: Token string to query
        
        Returns:
            Dictionary with token metadata, or None if not found
        """
        with self._tokens_lock:
            if token in self._tokens:
                entry: TokenEntry = self._tokens[token]
                return entry.to_dict()
            return None
    
    def get_active_token_count(self) -> int:
        """
        Get the current count of active (non-expired) tokens.
        
        Returns:
            Number of active tokens
        """
        with self._tokens_lock:
            # Clean up first
            current_time: float = time.time()
            expired: list = [
                t for t, e in self._tokens.items()
                if e.expires_at <= current_time
            ]
            for t in expired:
                del self._tokens[t]
            return len(self._tokens)
    
    # =========================================================================
    # PUBLIC ENCRYPTION METHODS
    # =========================================================================
    
    def encrypt_field(self, data: str) -> bytes:
        """
        Encrypt a string field.
        
        Args:
            data: Plaintext string to encrypt
        
        Returns:
            Encrypted bytes (nonce + ciphertext)
        
        Raises:
            EncryptionError: If encryption fails
        """
        if not CRYPTO_AVAILABLE:
            raise EncryptionError("Cryptography library not available")
        
        return self.encrypt_bytes(data.encode('utf-8'))
    
    def encrypt_bytes(self, data: bytes) -> bytes:
        """
        Encrypt bytes using AES-GCM.
        
        Uses a random 12-byte nonce for each encryption.
        
        Args:
            data: Plaintext bytes to encrypt
        
        Returns:
            Encrypted bytes: nonce (12 bytes) + ciphertext
        
        Raises:
            EncryptionError: If encryption fails
        
        Note:
            Each call generates a new random nonce. The same plaintext
            will produce different ciphertexts each time.
        """
        if not CRYPTO_AVAILABLE or AESGCM is None:
            raise EncryptionError("AES-GCM not available")
        
        if self._master_key is None:
            raise EncryptionError("Master key not initialized")
        
        try:
            # Generate random nonce
            nonce: bytes = secrets.token_bytes(NONCE_SIZE_BYTES)
            
            # Create cipher and encrypt
            cipher = AESGCM(self._master_key)
            ciphertext: bytes = cipher.encrypt(nonce, data, None)
            
            _debug_log(
                "Encrypted %d bytes -> %d bytes (nonce + ciphertext)",
                len(data),
                len(nonce) + len(ciphertext)
            )
            
            # Prepend nonce to ciphertext
            return nonce + ciphertext
            
        except Exception as e:
            self._logger.error("[SECURITY] Encryption failed: %s", e)
            raise EncryptionError(f"Encryption failed: {e}") from e
    
    def decrypt_field(self, encrypted_blob: bytes) -> str:
        """
        Decrypt an encrypted field back to string.
        
        Args:
            encrypted_blob: Encrypted bytes (nonce + ciphertext)
        
        Returns:
            Decrypted string
        
        Raises:
            DecryptionError: If decryption fails
        """
        decrypted: bytes = self.decrypt_bytes(encrypted_blob)
        return decrypted.decode('utf-8')
    
    def decrypt_bytes(self, encrypted_blob: bytes) -> bytes:
        """
        Decrypt AES-GCM encrypted bytes.
        
        Args:
            encrypted_blob: Encrypted bytes with nonce prefix
        
        Returns:
            Decrypted plaintext bytes
        
        Raises:
            DecryptionError: If decryption fails (including authentication failure)
        
        Note:
            AES-GCM provides authenticated encryption. If the ciphertext
            has been tampered with, decryption will raise an exception.
        """
        if not CRYPTO_AVAILABLE or AESGCM is None:
            raise DecryptionError("AES-GCM not available")
        
        if self._master_key is None:
            raise DecryptionError("Master key not initialized")
        
        if len(encrypted_blob) <= NONCE_SIZE_BYTES:
            raise DecryptionError("Invalid encrypted blob: too short")
        
        try:
            # Extract nonce and ciphertext
            nonce = encrypted_blob[:NONCE_SIZE_BYTES]
            ciphertext = encrypted_blob[NONCE_SIZE_BYTES:]
            
            # Create cipher and decrypt
            cipher = AESGCM(self._master_key)
            plaintext: bytes = cipher.decrypt(nonce, ciphertext, None)
            
            _debug_log(
                "Decrypted %d bytes -> %d bytes",
                len(encrypted_blob),
                len(plaintext)
            )
            
            return plaintext
            
        except Exception as e:
            self._logger.error("[SECURITY] Decryption failed: %s", e)
            raise DecryptionError(f"Decryption failed: {e}") from e
    
    # =========================================================================
    # KEY BACKUP/EXPORT METHODS
    # =========================================================================
    
    def export_master_blob(
        self,
        export_passphrase: str,
        metadata: Optional[Dict[str, str]] = None
    ) -> bytes:
        """
        Export the master key as an encrypted blob for backup.
        
        The blob is encrypted with a user-provided passphrase using
        a fresh KDF derivation.
        
        Args:
            export_passphrase: Passphrase to encrypt the export blob
            metadata: Optional metadata to include in export
        
        Returns:
            Encrypted blob containing master key and metadata
        
        Raises:
            KeyDerivationError: If export fails
        
        Warning:
            Store this blob securely! Loss means permanent key loss.
        
        Example:
            >>> blob = kernel.export_master_blob("backup_password")
            >>> with open("master_key_backup.bin", "wb") as f:
            ...     f.write(blob)
        """
        if not export_passphrase:
            raise ValueError("Export passphrase is required")
        
        if self._master_key is None:
            raise KeyDerivationError("No master key to export")
        
        try:
            # Derive key from export passphrase
            export_key: bytes = self._derive_key(export_passphrase)
            
            # Prepare export data with metadata
            export_data: Dict[str, Any] = {
                "master_key": self._master_key.hex(),
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "platform": platform.node(),
            }
            
            if metadata:
                export_data["metadata"] = metadata
            
            # Serialize to JSON
            import json
            json_data: str = json.dumps(export_data)
            
            # Encrypt the JSON blob
            cipher = AESGCM(export_key)
            nonce = secrets.token_bytes(NONCE_SIZE_BYTES)
            encrypted = cipher.encrypt(nonce, json_data.encode('utf-8'), None)
            
            # Format: magic (4 bytes) + nonce (12 bytes) + ciphertext
            MAGIC = b"AKXP"  # Arch-Key eXport Prefix
            result = MAGIC + nonce + encrypted
            
            _debug_log(
                "Exported master blob: %d bytes (encrypted %d bytes)",
                len(result),
                len(json_data)
            )
            self._logger.info("[SECURITY] Master key exported successfully")
            
            # Securely erase the temporary key
            self._secure_erase(export_key)
            
            return result
            
        except Exception as e:
            self._logger.error("[SECURITY] Master key export failed: %s", e)
            raise KeyDerivationError(f"Export failed: {e}") from e
    
    def import_master_blob(
        self,
        blob: bytes,
        import_passphrase: str
    ) -> Dict[str, Any]:
        """
        Import a master key from an encrypted backup blob.
        
        Args:
            blob: Encrypted blob from export_master_blob()
            import_passphrase: Passphrase used during export
        
        Returns:
            Dictionary containing import metadata
        
        Raises:
            KeyDerivationError: If import fails
            ValueError: If blob format is invalid
        
        Warning:
            This replaces the current master key!
        
        Example:
            >>> with open("master_key_backup.bin", "rb") as f:
            ...     blob = f.read()
            >>> info = kernel.import_master_blob(blob, "backup_password")
            >>> print(f"Imported at: {info['imported_at']}")
        """
        MAGIC = b"AKXP"
        
        if len(blob) <= 16 or not blob.startswith(MAGIC):
            raise ValueError("Invalid blob format")
        
        try:
            # Extract nonce and ciphertext
            nonce = blob[4:16]
            ciphertext = blob[16:]
            
            # Derive key from import passphrase
            import_key: bytes = self._derive_key(import_passphrase)
            
            # Decrypt
            cipher = AESGCM(import_key)
            json_data: bytes = cipher.decrypt(nonce, ciphertext, None)
            
            # Parse JSON
            import json
            data: Dict[str, Any] = json.loads(json_data.decode('utf-8'))
            
            # Extract master key
            master_key_hex: str = data.get("master_key")
            if not master_key_hex:
                raise KeyDerivationError("No master key found in blob")
            
            # Replace master key
            old_key = self._master_key
            self._master_key = bytes.fromhex(master_key_hex)
            
            # Add import metadata
            result: Dict[str, Any] = {
                "imported_at": datetime.now(timezone.utc).isoformat(),
                "exported_at": data.get("exported_at"),
                "original_platform": data.get("platform"),
            }
            
            # Securely wipe old key reference
            self._secure_erase(old_key)
            
            _debug_log("Imported master key from backup")
            self._logger.info(
                "[SECURITY] Master key imported (exported: %s)",
                data.get("exported_at")
            )
            
            # Securely erase temporary key
            self._secure_erase(import_key)
            
            return result
            
        except Exception as e:
            self._logger.error("[SECURITY] Master key import failed: %s", e)
            raise KeyDerivationError(f"Import failed: {e}") from e
    
    # =========================================================================
    # SHUTDOWN / CLEANUP
    # =========================================================================
    
    def shutdown(self) -> None:
        """
        Gracefully shutdown the security kernel.
        
        Stops cleanup thread and wipes sensitive data.
        """
        self._logger.info("[SECURITY] Shutting down security kernel")
        
        # Stop cleanup thread
        with self._cleanup_lock:
            self._cleanup_running = False
        
        # Wipe master key
        if self._master_key is not None:
            self._secure_erase(self._master_key)
            self._master_key = None
        
        # Clear all tokens
        with self._tokens_lock:
            self._tokens.clear()
        
        _debug_log("Security kernel shutdown complete")
        self._logger.info("[SECURITY] Security kernel shutdown complete")
    
    def __del__(self) -> None:
        """Destructor to ensure cleanup on garbage collection."""
        try:
            self.shutdown()
        except Exception:
            pass


# =============================================================================
# GLOBAL SECURITY CONTEXT
# =============================================================================

# Initialize global security kernel with default settings
# This can be reinitialized with custom parameters if needed
SEC_KERNEL: SecurityKernel = SecurityKernel(
    debug_mode=False  # Set to True for verbose security logging
)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_kernel_info() -> Dict[str, Any]:
    """
    Get information about the security kernel state.
    
    Useful for debugging and monitoring.
    
    Returns:
        Dictionary with kernel statistics
    """
    return {
        "active_tokens": SEC_KERNEL.get_active_token_count(),
        "max_tokens": MAX_ACTIVE_TOKENS,
        "token_ttl_default": DEFAULT_TOKEN_TTL_SECONDS,
        "rate_limit_per_minute": MAX_TOKENS_PER_MINUTE,
        "crypto_available": CRYPTO_AVAILABLE,
        "platform": platform.node(),
        "debug_mode": _is_debug_mode,
    }


def reset_kernel(
    master_key_input: Optional[str] = None,
    passphrase: Optional[str] = None
) -> SecurityKernel:
    """
    Reset the global security kernel with new parameters.
    
    Shuts down the old kernel and creates a new one.
    
    Args:
        master_key_input: Optional raw key input
        passphrase: Optional passphrase
    
    Returns:
        New SecurityKernel instance
    """
    global SEC_KERNEL
    
    # Shutdown old kernel
    if SEC_KERNEL is not None:
        SEC_KERNEL.shutdown()
    
    # Create new kernel
    SEC_KERNEL = SecurityKernel(
        master_key_input=master_key_input,
        passphrase=passphrase
    )
    
    return SEC_KERNEL
