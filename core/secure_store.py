from __future__ import annotations

import os
import json
import tempfile
import struct
import logging
from pathlib import Path
from typing import List, Dict, Union, BinaryIO

from core.security import SEC_KERNEL


# Storage root (hidden folder inside project root)
_REPO_ROOT = Path(__file__).resolve().parents[1]
_STORAGE_ROOT = _REPO_ROOT / ".vault"
_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

# Setup debug logger
logger = logging.getLogger("secure_store")
if not logger.handlers:
    h = logging.FileHandler("debug.txt")
    h.setLevel(logging.INFO)
    logger.addHandler(h)
    logger.propagate = False


def _resolve_storage_path(p: Union[str, Path]) -> Path:
    p = Path(p)
    if p.is_absolute():
        raise ValueError("Absolute paths not allowed in secure store")
    resolved = (_STORAGE_ROOT / p).resolve()
    try:
        resolved.relative_to(_STORAGE_ROOT)
    except Exception:
        raise ValueError("Path escapes secure storage")
    return resolved


def _atomic_write(target: Path, write_func):
    """Write atomically to target using a temp file in same directory."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent))
    tmp_path = Path(tmp)
    try:
        with os.fdopen(fd, "wb") as fh:
            write_func(fh)
        # Set restrictive permissions where supported
        try:
            tmp_path.chmod(0o600)
        except Exception:
            pass
        os.replace(str(tmp_path), str(target))
        try:
            target.chmod(0o600)
        except Exception:
            pass
    except Exception as e:
        try:
            tmp_path.unlink()
        except Exception:
            pass
        logger.exception("Atomic write failed: %s", e)
        raise


def write_encrypted(path: Union[str, Path], data: bytes, overwrite: bool = True, chunk_size: int = 65536) -> None:
    """Write data encrypted to `path`. Supports chunked streaming for large payloads.

    File format:
      - magic: 7 bytes b'ARCHPV1' (format id)
      - metadata_len: 4-byte BE unsigned int
      - metadata: JSON bytes (contains version, chunk_size)
      - sequence of records: [record_len:4BE][record_blob]
        where record_blob is AES-GCM nonce + ciphertext for that chunk
    """
    p = _resolve_storage_path(path)
    if p.exists() and not overwrite:
        raise FileExistsError(p)

    metadata = {"version": 1, "chunked": True, "chunk_size": chunk_size}

    def _write(fh: BinaryIO):
        # header
        fh.write(b"ARCHPV1")
        meta_bytes = json.dumps(metadata).encode("utf-8")
        fh.write(struct.pack(">I", len(meta_bytes)))
        fh.write(meta_bytes)

        # write encrypted chunks
        offset = 0
        total = len(data)
        while offset < total:
            chunk = data[offset : offset + chunk_size]
            blob = SEC_KERNEL.encrypt_bytes(chunk)
            fh.write(struct.pack(">I", len(blob)))
            fh.write(blob)
            offset += len(chunk)

    _atomic_write(p, _write)


def write_encrypted_file(path: Union[str, Path], src_path: Union[str, Path], overwrite: bool = True, chunk_size: int = 65536) -> None:
    """Stream-encrypt a file at `src_path` into the secure store `path`."""
    p = _resolve_storage_path(path)
    if p.exists() and not overwrite:
        raise FileExistsError(p)

    metadata = {"version": 1, "chunked": True, "chunk_size": chunk_size}

    def _write(fh: BinaryIO):
        fh.write(b"ARCHPV1")
        meta_bytes = json.dumps(metadata).encode("utf-8")
        fh.write(struct.pack(">I", len(meta_bytes)))
        fh.write(meta_bytes)

        with open(src_path, "rb") as src:
            while True:
                chunk = src.read(chunk_size)
                if not chunk:
                    break
                blob = SEC_KERNEL.encrypt_bytes(chunk)
                fh.write(struct.pack(">I", len(blob)))
                fh.write(blob)

    _atomic_write(p, _write)


def read_encrypted(path: Union[str, Path]) -> bytes:
    """Read and decrypt a stored file fully into memory. For large files, use the
    `stream_decrypt` generator instead.
    """
    p = _resolve_storage_path(path)
    if not p.exists():
        raise FileNotFoundError(p)
    out = bytearray()
    for part in stream_decrypt(p):
        out.extend(part)
    return bytes(out)


def stream_decrypt(p: Union[str, Path]):
    """Generator that yields decrypted chunks from stored encrypted file."""
    # Allow passing either a storage-relative path or an absolute Path already
    if isinstance(p, Path) and p.is_absolute():
        try:
            p.relative_to(_STORAGE_ROOT)
        except Exception:
            raise FileNotFoundError(p)
    else:
        p = _resolve_storage_path(p)
    if not p.exists():
        raise FileNotFoundError(p)
    with open(p, "rb") as fh:
        magic = fh.read(7)
        if magic != b"ARCHPV1":
            # old format: try single-blob decrypt
            fh.seek(0)
            blob = fh.read()
            yield SEC_KERNEL.decrypt_bytes(blob)
            return

        meta_len_bytes = fh.read(4)
        if len(meta_len_bytes) < 4:
            raise ValueError("Corrupt metadata length")
        meta_len = struct.unpack(">I", meta_len_bytes)[0]
        meta = json.loads(fh.read(meta_len).decode("utf-8"))

        while True:
            lenb = fh.read(4)
            if not lenb:
                break
            if len(lenb) < 4:
                raise ValueError("Corrupt record length")
            rec_len = struct.unpack(">I", lenb)[0]
            blob = fh.read(rec_len)
            if len(blob) < rec_len:
                raise ValueError("Truncated record")
            try:
                data = SEC_KERNEL.decrypt_bytes(blob)
            except Exception as e:
                logger.exception("Decryption failed for a chunk: %s", e)
                raise
            yield data


def delete(path: Union[str, Path], recursive: bool = False) -> None:
    p = _resolve_storage_path(path)
    if not p.exists():
        raise FileNotFoundError(p)
    if p.is_dir():
        if not recursive:
            raise IsADirectoryError(p)
        for child in sorted(p.rglob("*"), reverse=True):
            if child.is_file():
                try:
                    child.unlink()
                except Exception:
                    logger.exception("Failed to unlink %s", child)
            else:
                try:
                    child.rmdir()
                except Exception:
                    logger.exception("Failed to rmdir %s", child)
        try:
            p.rmdir()
        except Exception:
            logger.exception("Failed to rmdir %s", p)
    else:
        p.unlink()


def exists(path: Union[str, Path]) -> bool:
    try:
        p = _resolve_storage_path(path)
    except Exception:
        return False
    return p.exists()


def list_dir(path: Union[str, Path] = ".") -> List[Dict[str, Union[str, bool, int]]]:
    p = _resolve_storage_path(path)
    if not p.exists():
        raise FileNotFoundError(p)
    if not p.is_dir():
        raise NotADirectoryError(p)
    entries = []
    for child in sorted(p.iterdir()):
        stat = child.stat()
        entries.append({
            "name": child.name,
            "path": str(child.relative_to(_STORAGE_ROOT)),
            "is_dir": child.is_dir(),
            "size": stat.st_size,
            "mtime": int(stat.st_mtime),
        })
    return entries


def rename(src: Union[str, Path], dst: Union[str, Path], overwrite: bool = False) -> None:
    s = _resolve_storage_path(src)
    d = _resolve_storage_path(dst)
    if not s.exists():
        raise FileNotFoundError(s)
    if d.exists():
        if not overwrite:
            raise FileExistsError(d)
        if d.is_dir() and s.is_dir():
            delete(d, recursive=True)
        elif d.is_file():
            d.unlink()
    d.parent.mkdir(parents=True, exist_ok=True)
    s.replace(d)


__all__ = [
    "write_encrypted",
    "write_encrypted_file",
    "read_encrypted",
    "stream_decrypt",
    "delete",
    "exists",
    "list_dir",
    "rename",
]
