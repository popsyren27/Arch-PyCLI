"""
File Manager Module for Arch-PyCLI.

This module provides a compatibility wrapper around secure_store for file operations.

Note:
    This module is maintained for backwards compatibility.
    New code should use core.secure_store directly.

Features:
- File operations (read, write, list, delete, rename)
- Path validation
- Thread-safe operations
- Comprehensive error handling

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Union

# Import secure store
try:
    from core import secure_store as _ss
    _SS_AVAILABLE: bool = True
except ImportError:
    _ss = None
    _SS_AVAILABLE: bool = False


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class FileManagerError(Exception):
    """Base exception for file manager errors."""
    pass


# =============================================================================
# CONFIGURATION
# =============================================================================

# Repository root
_REPO_ROOT: Path = Path(__file__).resolve().parents[1]
_STORAGE_ROOT: Path = _REPO_ROOT / ".vault"

# Thread locks for file operations
_FILE_LOCKS: Dict[str, threading.Lock] = {}
_LOCKS_LOCK: threading.Lock = threading.Lock()


# =============================================================================
# SETUP LOGGING
# =============================================================================

_logger: logging.Logger = logging.getLogger("FILE_MANAGER")
if not _logger.handlers:
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

_logger.info("[FILE_MANAGER] File manager module initialized")


# =============================================================================
# LOCK MANAGEMENT
# =============================================================================

def _get_lock(path: str) -> threading.Lock:
    """
    Get or create a lock for the given path.
    
    Args:
        path: File path
    
    Returns:
        threading.Lock for the path
    """
    with _LOCKS_LOCK:
        if path not in _FILE_LOCKS:
            _FILE_LOCKS[path] = threading.Lock()
        return _FILE_LOCKS[path]


# =============================================================================
# PATH VALIDATION
# =============================================================================

def _validate_path(path: Union[str, Path]) -> Path:
    """
    Validate a path for security.
    
    Args:
        path: Path to validate
    
    Returns:
        Validated Path object
    
    Raises:
        FileManagerError: If path is invalid
    """
    if not _SS_AVAILABLE:
        raise FileManagerError("Secure store not available")
    
    p: Path = Path(path)
    
    if p.is_absolute():
        raise FileManagerError("Absolute paths not allowed")
    
    try:
        resolved: Path = (_STORAGE_ROOT / p).resolve()
        resolved.relative_to(_STORAGE_ROOT)
        return resolved
    except ValueError:
        raise FileManagerError(f"Path outside storage: {path}")


# =============================================================================
# FILE OPERATIONS
# =============================================================================

def list_dir(path: Union[str, Path] = ".") -> List[Dict[str, Any]]:
    """
    List directory contents.
    
    Args:
        path: Directory path (default: root)
    
    Returns:
        List of entry dictionaries
    
    Raises:
        FileManagerError: If operation fails
    """
    if not _SS_AVAILABLE:
        raise FileManagerError("Secure store not available")
    
    try:
        return _ss.list_dir(path)
    except Exception as e:
        _logger.exception("[FILE_MANAGER] list_dir failed")
        raise FileManagerError(str(e))


def read_file(
    path: Union[str, Path],
    mode: str = "r",
    encoding: Optional[str] = "utf-8"
) -> Union[str, bytes]:
    """
    Read a file from secure storage.
    
    Args:
        path: File path
        mode: Read mode ('r' for text, 'b' for binary)
        encoding: Text encoding (default: utf-8)
    
    Returns:
        File contents as string or bytes
    
    Raises:
        FileManagerError: If operation fails
    """
    if not _SS_AVAILABLE:
        raise FileManagerError("Secure store not available")
    
    try:
        data: bytes = _ss.read_encrypted(path)
        
        if "b" in mode:
            return data
        
        return data.decode(encoding or "utf-8")
        
    except FileNotFoundError:
        raise FileManagerError(f"File not found: {path}")
    except Exception as e:
        _logger.exception("[FILE_MANAGER] read_file failed")
        raise FileManagerError(str(e))


def read_stream(path: Union[str, Path]) -> Iterable[bytes]:
    """
    Read file as a stream of decrypted chunks.
    
    Args:
        path: File path
    
    Yields:
        Decrypted bytes chunks
    
    Raises:
        FileManagerError: If operation fails
    """
    if not _SS_AVAILABLE:
        raise FileManagerError("Secure store not available")
    
    try:
        for part in _ss.stream_decrypt(path):
            yield part
    except Exception as e:
        _logger.exception("[FILE_MANAGER] read_stream failed")
        raise FileManagerError(str(e))


def write_file(
    path: Union[str, Path],
    content: Union[str, bytes],
    overwrite: bool = True,
    create_parents: bool = True,
    encoding: Optional[str] = "utf-8"
) -> None:
    """
    Write content to a file in secure storage.
    
    Args:
        path: File path
        content: Content to write (string or bytes)
        overwrite: Overwrite if exists (default: True)
        create_parents: Create parent directories (default: True)
        encoding: Text encoding (default: utf-8)
    
    Raises:
        FileManagerError: If operation fails
    """
    if not _SS_AVAILABLE:
        raise FileManagerError("Secure store not available")
    
    try:
        if isinstance(content, str):
            data: bytes = content.encode(encoding or "utf-8")
        else:
            data = content
        
        _ss.write_encrypted(path, data, overwrite=overwrite)
        
    except Exception as e:
        _logger.exception("[FILE_MANAGER] write_file failed")
        raise FileManagerError(str(e))


def create_file(
    path: Union[str, Path],
    content: Union[str, bytes] = "",
    exist_ok: bool = False
) -> None:
    """
    Create a new file.
    
    Args:
        path: File path
        content: Initial content (default: empty)
        exist_ok: Don't error if exists (default: False)
    
    Raises:
        FileManagerError: If operation fails
    """
    if not _SS_AVAILABLE:
        raise FileManagerError("Secure store not available")
    
    try:
        if _ss.exists(path) and not exist_ok:
            raise FileManagerError(f"File already exists: {path}")
        
        write_file(path, content, overwrite=True, create_parents=True)
        
    except Exception as e:
        _logger.exception("[FILE_MANAGER] create_file failed")
        raise FileManagerError(str(e))


def delete_file(path: Union[str, Path], recursive: bool = False) -> None:
    """
    Delete a file.
    
    Args:
        path: File path
        recursive: Delete directories recursively (default: False)
    
    Raises:
        FileManagerError: If operation fails
    """
    if not _SS_AVAILABLE:
        raise FileManagerError("Secure store not available")
    
    try:
        _ss.delete(path, recursive=recursive)
    except Exception as e:
        _logger.exception("[FILE_MANAGER] delete_file failed")
        raise FileManagerError(str(e))


def rename(
    src: Union[str, Path],
    dst: Union[str, Path],
    overwrite: bool = False
) -> None:
    """
    Rename a file.
    
    Args:
        src: Source path
        dst: Destination path
        overwrite: Overwrite destination if exists (default: False)
    
    Raises:
        FileManagerError: If operation fails
    """
    if not _SS_AVAILABLE:
        raise FileManagerError("Secure store not available")
    
    try:
        _ss.rename(src, dst, overwrite=overwrite)
    except Exception as e:
        _logger.exception("[FILE_MANAGER] rename failed")
        raise FileManagerError(str(e))


def modify_file(
    path: Union[str, Path],
    transform: Callable[[str], str],
    encoding: Optional[str] = "utf-8"
) -> None:
    """
    Modify a file by applying a transform function.
    
    Args:
        path: File path
        transform: Function that takes old content and returns new content
        encoding: Text encoding (default: utf-8)
    
    Raises:
        FileManagerError: If operation fails
    """
    if not _SS_AVAILABLE:
        raise FileManagerError("Secure store not available")
    
    try:
        content: str = read_file(path, mode="r", encoding=encoding)
        new_content: str = transform(content)
        write_file(path, new_content, overwrite=True, encoding=encoding)
    except Exception as e:
        _logger.exception("[FILE_MANAGER] modify_file failed")
        raise FileManagerError(str(e))


def exists(path: Union[str, Path]) -> bool:
    """
    Check if a path exists.
    
    Args:
        path: Path to check
    
    Returns:
        True if exists, False otherwise
    """
    if not _SS_AVAILABLE:
        return False
    
    try:
        return _ss.exists(path)
    except Exception:
        return False


def get_info(path: Union[str, Path]) -> Dict[str, Any]:
    """
    Get information about a file.
    
    Args:
        path: File path
    
    Returns:
        Dictionary with file information
    
    Raises:
        FileManagerError: If operation fails
    """
    if not _SS_AVAILABLE:
        raise FileManagerError("Secure store not available")
    
    try:
        return _ss.get_info(path)
    except Exception as e:
        _logger.exception("[FILE_MANAGER] get_info failed")
        raise FileManagerError(str(e))


def get_stats() -> Dict[str, Any]:
    """
    Get storage statistics.
    
    Returns:
        Dictionary with storage statistics
    """
    if not _SS_AVAILABLE:
        return {
            "available": False,
            "error": "Secure store not available"
        }
    
    try:
        return _ss.get_storage_stats()
    except Exception as e:
        return {
            "available": True,
            "error": str(e)
        }


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "FileManagerError",
    "list_dir",
    "read_file",
    "read_stream",
    "write_file",
    "create_file",
    "delete_file",
    "rename",
    "modify_file",
    "exists",
    "get_info",
    "get_stats",
]
