"""
Secure Storage Module for Arch-PyCLI.

This module provides encrypted file storage with atomic write operations,
thread-safe access, and comprehensive error handling.

Features:
- AES-GCM encrypted file storage
- Atomic write operations (prevents corruption)
- Thread-safe file access with locking
- Streaming support for large files
- Path traversal prevention
- Automatic cleanup of temporary files
- Comprehensive logging and debugging

SECURITY NOTES:
    - All files are encrypted at rest using AES-GCM
    - Path traversal attacks are prevented
    - Temporary files are securely cleaned up
    - File permissions are set to 0o600

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import json
import logging
import os
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterator, List, Union

# Import security kernel for encryption
try:
    from core.security import SEC_KERNEL
except ImportError:
    # Fallback if security module not available
    SEC_KERNEL = None


# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

# Storage paths
_REPO_ROOT: Path = Path(__file__).resolve().parents[1]
_STORAGE_ROOT: Path = _REPO_ROOT / ".vault"

# File format constants
FILE_FORMAT_MAGIC: bytes = b"ARCHPV1"  # File format identifier
FILE_FORMAT_VERSION: int = 1  # Current format version

# Size limits
MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB default limit
DEFAULT_CHUNK_SIZE: int = 65536  # 64KB chunks for streaming
MIN_CHUNK_SIZE: int = 1024  # 1KB minimum
MAX_CHUNK_SIZE: int = 1024 * 1024  # 1MB maximum

# Threading
_FILE_LOCKS: Dict[str, threading.Lock] = {}
_FILE_LOCKS_LOCK: threading.Lock = threading.Lock()  # Lock for accessing _FILE_LOCKS

# Debug configuration
DEBUG_PREFIX: str = "[SECURE_STORE_DEBUG]"
_is_debug_mode: bool = False


def set_debug_mode(enabled: bool) -> None:
    """Enable or disable debug logging for storage operations."""
    global _is_debug_mode
    _is_debug_mode = enabled


def _debug_log(message: str, *args: Any) -> None:
    """Internal debug logger that respects debug mode."""
    if _is_debug_mode:
        _logger.debug(f"{DEBUG_PREFIX} {message}", *args)


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class SecureStoreError(Exception):
    """Base exception for all secure store errors."""
    pass


class StoragePathError(SecureStoreError):
    """Raised when storage path validation fails."""
    pass


class FileCorruptError(SecureStoreError):
    """Raised when file format is corrupted."""
    pass


class StorageLimitError(SecureStoreError):
    """Raised when storage limits are exceeded."""
    pass


class StorageUnavailableError(SecureStoreError):
    """Raised when storage is unavailable."""
    pass


# =============================================================================
# SETUP LOGGING
# =============================================================================

# Create module-level logger
_logger: logging.Logger = logging.getLogger("SECURE_STORE")
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
    _file_handler: logging.Handler = logging.FileHandler("secure_store.log")
    _file_handler.setLevel(logging.INFO)
    _file_handler.setFormatter(_formatter)
    _logger.addHandler(_file_handler)
except (IOError, PermissionError, OSError):
    _logger.warning(
        "[SECURE_STORE] File logging unavailable, using stdout only."
    )

# Ensure storage root exists
try:
    _STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
    _logger.info("[SECURE_STORE] Storage initialized at: %s", _STORAGE_ROOT)
except Exception as e:
    _logger.error("[SECURE_STORE] Failed to create storage root: %s", e)

_logger.info("[SECURE_STORE] Secure store module initialized")


# =============================================================================
# LOCK MANAGEMENT
# =============================================================================

def _get_file_lock(path: str) -> threading.Lock:
    """
    Get or create a lock for the given file path.
    
    Thread-safe method to obtain a lock for exclusive file access.
    
    Args:
        path: Resolved file path
    
    Returns:
        threading.Lock for the given path
    """
    with _FILE_LOCKS_LOCK:
        if path not in _FILE_LOCKS:
            _FILE_LOCKS[path] = threading.Lock()
        return _FILE_LOCKS[path]


def _cleanup_stale_locks() -> int:
    """
    Remove locks for paths that no longer exist.
    
    Returns:
        Number of locks removed
    """
    removed: int = 0
    with _FILE_LOCKS_LOCK:
        stale_keys: List[str] = [
            key for key in _FILE_LOCKS.keys()
            if not os.path.exists(key)
        ]
        for key in stale_keys:
            del _FILE_LOCKS[key]
            removed += 1
    
    if removed > 0:
        _debug_log("Cleaned up %d stale locks", removed)
    
    return removed


# =============================================================================
# PATH VALIDATION
# =============================================================================

def _resolve_storage_path(path: Union[str, Path]) -> Path:
    """
    Resolve a relative path to a storage path with validation.
    
    This prevents path traversal attacks by ensuring the resolved
    path stays within the storage root.
    
    Args:
        path: Relative path within storage
    
    Returns:
        Resolved Path object
    
    Raises:
        StoragePathError: If path escapes storage root
    
    Example:
        >>> path = _resolve_storage_path("documents/file.txt")
        >>> # Returns: /repo/.vault/documents/file.txt
    """
    try:
        # Convert to Path object
        p: Path = Path(path)
        
        # Reject absolute paths
        if p.is_absolute():
            raise StoragePathError("Absolute paths not allowed in secure store")
        
        # Resolve relative to storage root
        resolved: Path = (_STORAGE_ROOT / p).resolve()
        
        # Verify path stays within storage root
        try:
            resolved.relative_to(_STORAGE_ROOT)
        except ValueError:
            raise StoragePathError(
                f"Path escapes secure storage: {path}"
            )
        
        _debug_log("Resolved path: %s -> %s", path, resolved)
        return resolved
        
    except StoragePathError:
        raise
    except Exception as e:
        raise StoragePathError(f"Invalid path '{path}': {e}") from e


# =============================================================================
# ATOMIC WRITE OPERATIONS
# =============================================================================

def _atomic_write(target: Path, write_func: callable) -> None:
    """
    Atomically write to a file using a temporary file.
    
    This ensures that:
    1. The write either completes fully or not at all
    2. If the process crashes, the original file remains intact
    3. The temp file has restrictive permissions (0o600)
    
    Args:
        target: Target file path
        write_func: Function that writes to the file handle
    
    Raises:
        SecureStoreError: If write operation fails
    """
    target = Path(target)
    
    try:
        # Ensure parent directory exists
        target.parent.mkdir(parents=True, exist_ok=True)
        
        # Create temporary file in same directory (required for atomic rename)
        fd: int
        tmp_path: str
        fd, tmp_path = tempfile.mkstemp(
            dir=str(target.parent),
            prefix=".tmp_"
        )
        tmp_path_obj: Path = Path(tmp_path)
        
        try:
            # Open file descriptor for writing
            with os.fdopen(fd, "wb") as fh:
                # Execute the write function
                write_func(fh)
            
            # Set restrictive permissions
            try:
                tmp_path_obj.chmod(0o600)
            except Exception:
                pass  # May fail on Windows
            
            # Atomic rename (on POSIX systems, this is atomic)
            os.replace(str(tmp_path_obj), str(target))
            
            # Set permissions on target
            try:
                target.chmod(0o600)
            except Exception:
                pass
            
            _debug_log("Atomic write completed: %s", target)
            
        except Exception as e:
            # Clean up temp file on error
            try:
                tmp_path_obj.unlink()
            except Exception:
                pass
            raise SecureStoreError(f"Atomic write failed: {e}") from e
            
    except SecureStoreError:
        raise
    except Exception as e:
        raise SecureStoreError(f"Atomic write failed: {e}") from e


# =============================================================================
# FILE FORMAT HANDLING
# =============================================================================

def _write_header(fh: BinaryIO, metadata: Dict[str, Any], chunk_size: int) -> None:
    """
    Write the file format header.
    
    Format:
        - Magic: 7 bytes (FILE_FORMAT_MAGIC)
        - Version: 4 bytes (big-endian unsigned int)
        - Metadata length: 4 bytes (big-endian unsigned int)
        - Metadata: JSON bytes
        - Chunk size: 4 bytes (big-endian unsigned int)
    
    Args:
        fh: File handle
        metadata: Metadata dictionary
        chunk_size: Chunk size used for encryption
    """
    # Magic bytes
    fh.write(FILE_FORMAT_MAGIC)
    
    # Version
    fh.write(struct.pack(">I", FILE_FORMAT_VERSION))
    
    # Metadata
    meta_bytes: bytes = json.dumps(metadata).encode("utf-8")
    fh.write(struct.pack(">I", len(meta_bytes)))
    fh.write(meta_bytes)
    
    # Chunk size
    fh.write(struct.pack(">I", chunk_size))
    
    _debug_log(
        "Wrote header: magic=%s, version=%d, meta_len=%d, chunk_size=%d",
        FILE_FORMAT_MAGIC,
        FILE_FORMAT_VERSION,
        len(meta_bytes),
        chunk_size
    )


def _read_header(fh: BinaryIO) -> Dict[str, Any]:
    """
    Read and validate the file format header.
    
    Args:
        fh: File handle
    
    Returns:
        Dictionary with metadata and chunk_size
    
    Raises:
        FileCorruptError: If header is invalid or corrupted
    """
    try:
        # Magic bytes
        magic: bytes = fh.read(7)
        if magic != FILE_FORMAT_MAGIC:
            # Try to handle old format (single blob)
            fh.seek(0)
            return {"version": 0, "chunked": False, "chunk_size": None}
        
        # Version
        version_bytes: bytes = fh.read(4)
        if len(version_bytes) < 4:
            raise FileCorruptError("Incomplete version field")
        version: int = struct.unpack(">I", version_bytes)[0]
        
        if version != FILE_FORMAT_VERSION:
            _logger.warning(
                "[SECURE_STORE] File version mismatch: expected %d, got %d",
                FILE_FORMAT_VERSION,
                version
            )
        
        # Metadata length
        meta_len_bytes: bytes = fh.read(4)
        if len(meta_len_bytes) < 4:
            raise FileCorruptError("Incomplete metadata length field")
        meta_len: int = struct.unpack(">I", meta_len_bytes)[0]
        
        if meta_len < 0 or meta_len > 1024 * 1024:  # Sanity check
            raise FileCorruptError(f"Invalid metadata length: {meta_len}")
        
        # Metadata
        meta_bytes: bytes = fh.read(meta_len)
        if len(meta_bytes) < meta_len:
            raise FileCorruptError("Truncated metadata")
        
        try:
            metadata = json.loads(meta_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise FileCorruptError(f"Invalid metadata JSON: {e}") from e
        
        # Chunk size
        chunk_size_bytes: bytes = fh.read(4)
        if len(chunk_size_bytes) < 4:
            raise FileCorruptError("Incomplete chunk size field")
        chunk_size: int = struct.unpack(">I", chunk_size_bytes)[0]
        
        _debug_log(
            "Read header: version=%d, meta_len=%d, chunk_size=%d",
            version,
            meta_len,
            chunk_size
        )
        
        return {
            "version": version,
            "chunked": True,
            "chunk_size": chunk_size,
            **metadata
        }
        
    except FileCorruptError:
        raise
    except Exception as e:
        raise FileCorruptError(f"Failed to read header: {e}") from e


# =============================================================================
# CORE WRITE OPERATIONS
# =============================================================================

def write_encrypted(
    path: Union[str, Path],
    data: bytes,
    overwrite: bool = True,
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> None:
    """
    Write data encrypted to a file.
    
    The file is encrypted using AES-GCM with chunked encryption
    for efficient handling of large files.
    
    Args:
        path: Storage-relative path
        data: Raw bytes to encrypt and write
        overwrite: If False, raise error if file exists
        chunk_size: Size of encryption chunks (must be between MIN_CHUNK_SIZE and MAX_CHUNK_SIZE)
    
    Raises:
        SecureStoreError: If write fails
        StoragePathError: If path is invalid
        StorageLimitError: If data exceeds size limits
    
    Example:
        >>> write_encrypted("secrets/api_key.txt", b"my-secret-key")
        >>> # File is now encrypted at .vault/secrets/api_key.txt
    """
    # Validate path
    p: Path = _resolve_storage_path(path)
    
    # Check file existence
    if p.exists() and not overwrite:
        raise SecureStoreError(f"File already exists: {path}")
    
    # Validate chunk size
    chunk_size = max(MIN_CHUNK_SIZE, min(chunk_size, MAX_CHUNK_SIZE))
    
    # Check size limit
    if len(data) > MAX_FILE_SIZE:
        raise StorageLimitError(
            f"Data size ({len(data)}) exceeds limit ({MAX_FILE_SIZE})"
        )
    
    # Check if security kernel is available
    if SEC_KERNEL is None:
        raise SecureStoreError("Security kernel not available")
    
    _debug_log(
        "Writing encrypted file: path=%s, size=%d, chunks=%d",
        path,
        len(data),
        chunk_size
    )
    
    # Define write operation
    def _write(fh: BinaryIO) -> None:
        # Write header
        metadata: Dict[str, Any] = {
            "version": FILE_FORMAT_VERSION,
            "created_at": time.time(),
            "original_size": len(data),
        }
        _write_header(fh, metadata, chunk_size)
        
        # Encrypt and write chunks
        offset: int = 0
        total: int = len(data)
        chunk_num: int = 0
        
        while offset < total:
            chunk: bytes = data[offset:offset + chunk_size]
            
            # Encrypt chunk
            encrypted_chunk: bytes = SEC_KERNEL.encrypt_bytes(chunk)
            
            # Write record: length (4 bytes) + encrypted data
            fh.write(struct.pack(">I", len(encrypted_chunk)))
            fh.write(encrypted_chunk)
            
            offset += len(chunk)
            chunk_num += 1
            
            _debug_log(
                "Encrypted chunk %d: %d bytes -> %d bytes",
                chunk_num,
                len(chunk),
                len(encrypted_chunk)
            )
    
    # Atomic write
    _atomic_write(p, _write)
    
    _logger.info(
        "[SECURE_STORE] Wrote encrypted file: %s (%d bytes in %d chunks)",
        path,
        len(data),
        (len(data) + chunk_size - 1) // chunk_size
    )


def write_encrypted_file(
    path: Union[str, Path],
    src_path: Union[str, Path],
    overwrite: bool = True,
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> None:
    """
    Stream-encrypt a source file into secure storage.
    
    This method avoids loading the entire source file into memory
    by streaming it in chunks.
    
    Args:
        path: Destination path in secure storage
        src_path: Source file path (can be Path object or string)
        overwrite: If False, raise error if destination exists
        chunk_size: Size of encryption chunks
    
    Raises:
        SecureStoreError: If write fails
        FileNotFoundError: If source file doesn't exist
        StorageLimitError: If source file is too large
    """
    # Validate paths
    p: Path = _resolve_storage_path(path)
    src: Path = Path(src_path)
    
    if not src.exists():
        raise FileNotFoundError(f"Source file not found: {src_path}")
    
    if not src.is_file():
        raise SecureStoreError(f"Source is not a file: {src_path}")
    
    # Check file size
    src_size: int = src.stat().st_size
    if src_size > MAX_FILE_SIZE:
        raise StorageLimitError(
            f"Source file size ({src_size}) exceeds limit ({MAX_FILE_SIZE})"
        )
    
    # Validate chunk size
    chunk_size = max(MIN_CHUNK_SIZE, min(chunk_size, MAX_CHUNK_SIZE))
    
    if SEC_KERNEL is None:
        raise SecureStoreError("Security kernel not available")
    
    _debug_log(
        "Stream-encrypting file: %s -> %s, size=%d",
        src_path,
        path,
        src_size
    )
    
    def _write(fh: BinaryIO) -> None:
        # Write header
        metadata: Dict[str, Any] = {
            "version": FILE_FORMAT_VERSION,
            "created_at": time.time(),
            "source": str(src_path),
            "original_size": src_size,
            "streamed": True,
        }
        _write_header(fh, metadata, chunk_size)
        
        # Stream and encrypt
        bytes_processed: int = 0
        chunk_num: int = 0
        
        with open(src, "rb") as src_fh:
            while True:
                chunk = src_fh.read(chunk_size)
                if not chunk:
                    break
                
                # Encrypt chunk
                encrypted_chunk: bytes = SEC_KERNEL.encrypt_bytes(chunk)
                
                # Write record
                fh.write(struct.pack(">I", len(encrypted_chunk)))
                fh.write(encrypted_chunk)
                
                bytes_processed += len(chunk)
                chunk_num += 1
                
                _debug_log(
                    "Encrypted chunk %d: %d bytes -> %d bytes",
                    chunk_num,
                    len(chunk),
                    len(encrypted_chunk)
                )
    
    _atomic_write(p, _write)
    
    _logger.info(
        "[SECURE_STORE] Streamed encrypted: %s -> %s (%d bytes)",
        src_path,
        path,
        src_size
    )


# =============================================================================
# CORE READ OPERATIONS
# =============================================================================

def read_encrypted(path: Union[str, Path]) -> bytes:
    """
    Read and decrypt a stored file.
    
    For large files, consider using stream_decrypt() instead.
    
    Args:
        path: Storage-relative path to the encrypted file
    
    Returns:
        Decrypted bytes
    
    Raises:
        SecureStoreError: If read fails
        FileNotFoundError: If file doesn't exist
    
    Example:
        >>> data = read_encrypted("secrets/api_key.txt")
        >>> print(data.decode())
    """
    p: Path = _resolve_storage_path(path)
    
    if not p.exists():
        raise FileNotFoundError(f"Encrypted file not found: {path}")
    
    if SEC_KERNEL is None:
        raise SecureStoreError("Security kernel not available")
    
    _debug_log("Reading encrypted file: %s", path)
    
    # Collect all decrypted chunks
    output: bytearray = bytearray()
    for chunk in stream_decrypt(p):
        output.extend(chunk)
    
    _logger.info(
        "[SECURE_STORE] Read encrypted file: %s (%d bytes)",
        path,
        len(output)
    )
    
    return bytes(output)


def stream_decrypt(path: Union[str, Path]) -> Iterator[bytes]:
    """
    Generator that yields decrypted chunks from an encrypted file.
    
    This is memory-efficient for large files as it only keeps
    one chunk in memory at a time.
    
    Args:
        path: Storage-relative path OR absolute Path object
    
    Yields:
        Decrypted bytes chunks
    
    Raises:
        SecureStoreError: If decryption fails
        FileNotFoundError: If file doesn't exist
        FileCorruptError: If file format is corrupted
    
    Example:
        >>> for chunk in stream_decrypt("large_file.bin"):
        ...     process(chunk)
    """
    # Handle absolute paths
    if isinstance(path, Path) and path.is_absolute():
        p: Path = path
        try:
            p.relative_to(_STORAGE_ROOT)
        except ValueError:
            raise FileNotFoundError(f"Path outside storage: {path}")
    else:
        p = _resolve_storage_path(path)
    
    if not p.exists():
        raise FileNotFoundError(f"Encrypted file not found: {path}")
    
    if SEC_KERNEL is None:
        raise SecureStoreError("Security kernel not available")
    
    _debug_log("Streaming decrypt: %s", path)
    
    try:
        with open(p, "rb") as fh:
            # Read and validate header
            header: Dict[str, Any] = _read_header(fh)
            
            # Handle old format (version 0)
            if not header.get("chunked", True):
                _logger.info(
                    "[SECURE_STORE] Reading legacy format file: %s",
                    path
                )
                blob: bytes = fh.read()
                try:
                    decrypted: bytes = SEC_KERNEL.decrypt_bytes(blob)
                    yield decrypted
                except Exception as e:
                    raise SecureStoreError(f"Decryption failed: {e}") from e
                return
            
            chunk_size: int = header.get("chunk_size", DEFAULT_CHUNK_SIZE)
            
            # Read encrypted chunks
            chunk_num: int = 0
            while True:
                # Read record length
                len_bytes: bytes = fh.read(4)
                if not len_bytes:
                    # EOF
                    break
                
                if len(len_bytes) < 4:
                    raise FileCorruptError("Truncated record length")
                
                rec_len: int = struct.unpack(">I", len_bytes)[0]
                
                if rec_len < 0 or rec_len > MAX_FILE_SIZE:
                    raise FileCorruptError(f"Invalid record length: {rec_len}")
                
                # Read encrypted data
                encrypted_data: bytes = fh.read(rec_len)
                if len(encrypted_data) < rec_len:
                    raise FileCorruptError(
                        f"Truncated record: expected {rec_len}, got {len(encrypted_data)}"
                    )
                
                # Decrypt
                try:
                    decrypted_chunk: bytes = SEC_KERNEL.decrypt_bytes(encrypted_data)
                    chunk_num += 1
                    
                    _debug_log(
                        "Decrypted chunk %d: %d bytes -> %d bytes",
                        chunk_num,
                        len(encrypted_data),
                        len(decrypted_chunk)
                    )
                    
                    yield decrypted_chunk
                    
                except Exception as e:
                    _logger.error(
                        "[SECURE_STORE] Decryption failed for chunk %d: %s",
                        chunk_num,
                        e
                    )
                    raise SecureStoreError(
                        f"Decryption failed for chunk {chunk_num}: {e}"
                    ) from e
    
    except FileNotFoundError:
        raise
    except FileCorruptError:
        raise
    except SecureStoreError:
        raise
    except Exception as e:
        raise SecureStoreError(f"Stream decryption failed: {e}") from e


# =============================================================================
# FILE OPERATIONS
# =============================================================================

def delete(path: Union[str, Path], recursive: bool = False) -> None:
    """
    Delete a file or directory from secure storage.
    
    Args:
        path: Storage-relative path
        recursive: If True, delete directories recursively
    
    Raises:
        SecureStoreError: If deletion fails
        IsADirectoryError: If path is a directory and recursive=False
    """
    p: Path = _resolve_storage_path(path)
    
    if not p.exists():
        # Already deleted, nothing to do
        _debug_log("Path already deleted: %s", path)
        return
    
    # Get lock for this path
    lock: threading.Lock = _get_file_lock(str(p))
    
    with lock:
        try:
            if p.is_dir():
                if not recursive:
                    raise IsADirectoryError(f"Cannot delete directory without recursive: {path}")
                
                # Delete contents in reverse order (files before dirs)
                for child in sorted(p.rglob("*"), reverse=True):
                    if child.is_file():
                        try:
                            child.unlink()
                            _debug_log("Deleted file: %s", child)
                        except Exception as e:
                            _logger.warning(
                                "[SECURE_STORE] Failed to delete file %s: %s",
                                child,
                                e
                            )
                    elif child.is_dir():
                        try:
                            child.rmdir()
                            _debug_log("Deleted directory: %s", child)
                        except Exception as e:
                            _logger.warning(
                                "[SECURE_STORE] Failed to remove directory %s: %s",
                                child,
                                e
                            )
                
                # Delete the directory itself
                try:
                    p.rmdir()
                except Exception as e:
                    raise SecureStoreError(f"Failed to delete directory: {e}") from e
                
            else:
                # Delete file
                p.unlink()
                _debug_log("Deleted file: %s", path)
            
            _logger.info("[SECURE_STORE] Deleted: %s (recursive=%s)", path, recursive)
            
        except (IsADirectoryError, SecureStoreError):
            raise
        except Exception as e:
            raise SecureStoreError(f"Delete failed: {e}") from e


def exists(path: Union[str, Path]) -> bool:
    """
    Check if a path exists in secure storage.
    
    Args:
        path: Storage-relative path
    
    Returns:
        True if path exists, False otherwise
    """
    try:
        p: Path = _resolve_storage_path(path)
        return p.exists()
    except StoragePathError:
        return False


def list_dir(path: Union[str, Path] = ".") -> List[Dict[str, Any]]:
    """
    List contents of a directory in secure storage.
    
    Args:
        path: Storage-relative directory path (default: root)
    
    Returns:
        List of dictionaries with entry information
    
    Raises:
        SecureStoreError: If listing fails
        NotADirectoryError: If path is not a directory
    
    Example:
        >>> entries = list_dir("documents")
        >>> for e in entries:
        ...     print(f"{e['type']} {e['name']} ({e['size']} bytes)")
    """
    p: Path = _resolve_storage_path(path)
    
    if not p.exists():
        raise FileNotFoundError(f"Directory not found: {path}")
    
    if not p.is_dir():
        raise NotADirectoryError(f"Not a directory: {path}")
    
    entries: List[Dict[str, Any]] = []
    
    try:
        for child in sorted(p.iterdir()):
            try:
                stat_info = child.stat()
                
                entry: Dict[str, Any] = {
                    "name": child.name,
                    "path": str(child.relative_to(_STORAGE_ROOT)),
                    "is_dir": child.is_dir(),
                    "is_file": child.is_file(),
                    "size": stat_info.st_size if child.is_file() else 0,
                    "mtime": int(stat_info.st_mtime),
                    "ctime": int(stat_info.st_ctime),
                }
                
                entries.append(entry)
                
            except Exception as e:
                _logger.warning(
                    "[SECURE_STORE] Failed to stat %s: %s",
                    child,
                    e
                )
        
        _debug_log("Listed directory %s: %d entries", path, len(entries))
        return entries
        
    except Exception as e:
        raise SecureStoreError(f"List directory failed: {e}") from e


def rename(
    src: Union[str, Path],
    dst: Union[str, Path],
    overwrite: bool = False
) -> None:
    """
    Rename a file or directory within secure storage.
    
    Args:
        src: Source path
        dst: Destination path
        overwrite: If True, overwrite existing destination
    
    Raises:
        SecureStoreError: If rename fails
        FileNotFoundError: If source doesn't exist
        FileExistsError: If destination exists and overwrite=False
    """
    s: Path = _resolve_storage_path(src)
    d: Path = _resolve_storage_path(dst)
    
    if not s.exists():
        raise FileNotFoundError(f"Source not found: {src}")
    
    if d.exists() and not overwrite:
        raise FileExistsError(f"Destination exists: {dst}")
    
    # Get locks for both paths
    src_lock: threading.Lock = _get_file_lock(str(s))
    dst_lock: threading.Lock = _get_file_lock(str(d))
    
    # Acquire locks in consistent order to prevent deadlock
    locks: List[threading.Lock] = sorted(
        [src_lock, dst_lock],
        key=id
    )
    
    with locks[0]:
        with locks[1]:
            try:
                # Handle overwrite
                if d.exists():
                    if d.is_dir():
                        if s.is_dir():
                            # Both are directories, can overwrite
                            pass
                        else:
                            raise SecureStoreError("Cannot overwrite directory with file")
                    else:
                        # Delete existing file
                        if overwrite:
                            if d.is_dir():
                                delete(d, recursive=True)
                            else:
                                d.unlink()
                        else:
                            raise FileExistsError(f"Destination exists: {dst}")
                
                # Ensure destination parent exists
                d.parent.mkdir(parents=True, exist_ok=True)
                
                # Atomic rename
                s.replace(d)
                
                _logger.info("[SECURE_STORE] Renamed: %s -> %s", src, dst)
                
            except Exception as e:
                raise SecureStoreError(f"Rename failed: {e}") from e


def get_info(path: Union[str, Path]) -> Dict[str, Any]:
    """
    Get detailed information about a stored file.
    
    Args:
        path: Storage-relative path
    
    Returns:
        Dictionary with file information
    
    Raises:
        SecureStoreError: If info retrieval fails
        FileNotFoundError: If file doesn't exist
    """
    p: Path = _resolve_storage_path(path)
    
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    stat_info = p.stat()
    
    info: Dict[str, Any] = {
        "path": str(p.relative_to(_STORAGE_ROOT)),
        "name": p.name,
        "is_dir": p.is_dir(),
        "is_file": p.is_file(),
        "size": stat_info.st_size,
        "mtime": int(stat_info.st_mtime),
        "ctime": int(stat_info.st_ctime),
        "atime": int(stat_info.st_atime),
    }
    
    # Try to read header for encrypted file info
    if p.is_file():
        try:
            with open(p, "rb") as fh:
                header: Dict[str, Any] = _read_header(fh)
                info["encrypted"] = True
                info["format_version"] = header.get("version", 0)
                info["chunk_size"] = header.get("chunk_size")
                info["original_size"] = header.get("original_size")
        except Exception:
            info["encrypted"] = False
    
    return info


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_storage_stats() -> Dict[str, Any]:
    """
    Get statistics about secure storage usage.
    
    Returns:
        Dictionary with storage statistics
    """
    total_size: int = 0
    file_count: int = 0
    dir_count: int = 0
    
    if _STORAGE_ROOT.exists():
        for item in _STORAGE_ROOT.rglob("*"):
            if item.is_file():
                try:
                    total_size += item.stat().st_size
                    file_count += 1
                except Exception:
                    pass
            elif item.is_dir():
                dir_count += 1
    
    return {
        "storage_root": str(_STORAGE_ROOT),
        "total_files": file_count,
        "total_directories": dir_count,
        "total_size_bytes": total_size,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "max_file_size_bytes": MAX_FILE_SIZE,
        "chunk_size_bytes": DEFAULT_CHUNK_SIZE,
    }


def cleanup_temp_files() -> int:
    """
    Clean up any stray temporary files.
    
    Returns:
        Number of temp files removed
    """
    removed: int = 0
    
    if _STORAGE_ROOT.exists():
        for item in _STORAGE_ROOT.rglob(".tmp_*"):
            try:
                item.unlink()
                removed += 1
                _debug_log("Removed temp file: %s", item)
            except Exception as e:
                _logger.warning(
                    "[SECURE_STORE] Failed to remove temp file %s: %s",
                    item,
                    e
                )
    
    if removed > 0:
        _logger.info("[SECURE_STORE] Cleaned up %d temp files", removed)
    
    return removed


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Exceptions
    "SecureStoreError",
    "StoragePathError",
    "FileCorruptError",
    "StorageLimitError",
    "StorageUnavailableError",
    # Core operations
    "write_encrypted",
    "write_encrypted_file",
    "read_encrypted",
    "stream_decrypt",
    # File operations
    "delete",
    "exists",
    "list_dir",
    "rename",
    "get_info",
    # Utilities
    "get_storage_stats",
    "cleanup_temp_files",
    "set_debug_mode",
]
