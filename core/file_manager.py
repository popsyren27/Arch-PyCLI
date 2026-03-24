from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
import threading
import contextlib
import io
import tempfile
from typing import Callable, Dict, List, Optional, Union, Iterable

import logging
from core import secure_store as ss
import logging


class FileManagerError(Exception):
    pass


# Repository root
_REPO_ROOT = Path(__file__).resolve().parents[1]
# Storage root for files managed by the file manager (encrypted at rest)
_STORAGE_ROOT = _REPO_ROOT / ".vault"
_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

# in-process locks to avoid concurrent writes on same path
_FILE_LOCKS: Dict[str, threading.Lock] = {}

_logger = logging.getLogger("file_manager")
if not _logger.handlers:
    h = logging.FileHandler("debug.txt")
    h.setLevel(logging.INFO)
    _logger.addHandler(h)
    _logger.propagate = False


def _ensure_within_storage(p: Path) -> Path:
    p = p.resolve()
    try:
        p.relative_to(_STORAGE_ROOT)
    except Exception:
        raise FileManagerError(f"Path outside storage root: {p}")
    return p


def list_dir(path: Union[str, Path] = ".") -> List[Dict[str, Union[str, bool, int]]]:
    # delegate to secure store listing
    try:
        return ss.list_dir(path)
    except Exception as e:
        raise FileManagerError(str(e))


def read_stream(path: Union[str, Path]):
    """Yield decrypted chunks (bytes) for the stored file at `path`.

    This is a thin wrapper around `secure_store.stream_decrypt` which yields
    plaintext chunks as produced by the store.
    """
    try:
        for part in ss.stream_decrypt(path):
            yield part
    except Exception as e:
        raise FileManagerError(str(e))


def read_file(path: Union[str, Path], mode: str = "r", encoding: Optional[str] = "utf-8") -> Union[str, bytes]:
    try:
        data = ss.read_encrypted(path)
    except Exception as e:
        raise FileManagerError(str(e))
    if "w" in mode and isinstance(path, (str, Path)):
        # if caller requested write mode, provide bytes for them to write
        return data
    if "b" in mode:
        return data
    try:
        return data.decode(encoding or "utf-8")
    except Exception as e:
        raise FileManagerError(f"Decoding error: {e}")


@contextlib.contextmanager
def write_stream(path: Union[str, Path], overwrite: bool = True):
    """Context manager that yields a binary file-like object to write into.

    On exit the temporary file will be encrypted into the secure store at
    `path`. This avoids building large files in memory.
    """
    p = Path(path)
    key = str(p.resolve())
    lock = _FILE_LOCKS.setdefault(key, threading.Lock())
    tmp = None
    try:
        lock.acquire()
        tmp_f = tempfile.NamedTemporaryFile(delete=False)
        tmp = Path(tmp_f.name)
        _logger.info("Opened temp file %s for write_stream -> %s", tmp, path)
        try:
            yield tmp_f
        finally:
            try:
                tmp_f.flush()
                tmp_f.close()
            except Exception:
                pass
        # stream into secure store
        ss.write_encrypted_file(path, tmp, overwrite=overwrite)
    except Exception as e:
        _logger.exception("write_stream failed: %s", e)
        raise FileManagerError(str(e))
    finally:
        try:
            if tmp and tmp.exists():
                tmp.unlink()
        except Exception:
            pass
        try:
            lock.release()
        except Exception:
            pass


def write_from_iterable(path: Union[str, Path], iterable: Iterable[bytes], overwrite: bool = True) -> None:
    """Write encrypted file from an iterable of bytes (or strings)."""
    with write_stream(path, overwrite=overwrite) as fh:
        for chunk in iterable:
            if isinstance(chunk, str):
                chunk = chunk.encode()
            fh.write(chunk)


def write_file(
    path: Union[str, Path],
    content: Union[str, bytes],
    overwrite: bool = True,
    create_parents: bool = True,
    encoding: Optional[str] = "utf-8",
) -> None:
    """Write `content` to `path` in encrypted storage.

    If `content` is a `Path` or string pointing to an existing local file,
    the implementation will stream the source file into the secure store to
    avoid loading large files into memory.
    """
    logger = logging.getLogger("file_manager")
    try:
        # If content is a path to an existing file, stream from disk
        if isinstance(content, (str, Path)) and Path(content).exists():
            src = Path(content)
            ss.write_encrypted_file(path, src, overwrite=overwrite)
            return

        # If content is a file-like object, stream into temp then encrypt
        if hasattr(content, "read"):
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                try:
                    # copy in chunks
                    while True:
                        chunk = content.read(65536)
                        if not chunk:
                            break
                        if isinstance(chunk, str):
                            chunk = chunk.encode(encoding or "utf-8")
                        tmp.write(chunk)
                    tmp.flush()
                finally:
                    tmp_path = Path(tmp.name)
            try:
                ss.write_encrypted_file(path, tmp_path, overwrite=overwrite)
            finally:
                try:
                    tmp_path.unlink()
                except Exception:
                    pass
            return

        # If content is an iterable of chunks (but not a string/bytes), write from iterable
        if isinstance(content, Iterable) and not isinstance(content, (str, bytes)):
            write_from_iterable(path, content, overwrite=overwrite)
            return

        if isinstance(content, str):
            data = content.encode(encoding or "utf-8")
        else:
            data = content

        ss.write_encrypted(path, data, overwrite=overwrite)
    except Exception as e:
        logger.exception("write_file failed: %s", e)
        raise FileManagerError(str(e))


def create_file(path: Union[str, Path], content: Union[str, bytes] = "", exist_ok: bool = False) -> None:
    try:
        if ss.exists(path) and not exist_ok:
            raise FileManagerError(f"File already exists: {path}")
        # ensure parent exists in storage by creating a zero-byte placeholder
        if isinstance(path, (str, Path)):
            p = Path(path)
            parent = p.parent
            if str(parent) not in (".", "") and not ss.exists(parent):
                # create an empty directory marker
                (ss._STORAGE_ROOT / parent).mkdir(parents=True, exist_ok=True)
        write_file(path, content, overwrite=True, create_parents=True)
    except Exception as e:
        raise FileManagerError(str(e))


def delete_file(path: Union[str, Path], recursive: bool = False) -> None:
    try:
        ss.delete(path, recursive=recursive)
    except Exception as e:
        raise FileManagerError(str(e))


def rename(src: Union[str, Path], dst: Union[str, Path], overwrite: bool = False) -> None:
    try:
        ss.rename(src, dst, overwrite=overwrite)
    except Exception as e:
        raise FileManagerError(str(e))


def modify_file(path: Union[str, Path], transform: Callable[[str], str], encoding: Optional[str] = "utf-8") -> None:
    text = read_file(path, mode="r", encoding=encoding)
    new_text = transform(text)
    write_file(path, new_text, overwrite=True, create_parents=False, encoding=encoding)


def exists(path: Union[str, Path]) -> bool:
    try:
        return ss.exists(path)
    except Exception:
        return False


__all__ = [
    "FileManagerError",
    "list_dir",
    "read_file",
    "write_file",
    "create_file",
    "delete_file",
    "rename",
    "modify_file",
    "exists",
]
