import logging
from typing import Dict, Any
from core import secure_store as ss
from core.security import SEC_KERNEL


def _clean_key(k: str) -> str:
    # Restrict key names: alphanumeric, dashes and underscores only
    safe = "".join(ch for ch in k if ch.isalnum() or ch in ('-', '_'))
    return safe[:128]


def execute(context: Dict[str, Any], *args) -> str:
    """
    Secure Vault Plugin backed by `core.secure_store`.
    Usage:
      vault set [key] [value]
      vault get [key]
    """
    if not args or len(args) < 1:
        raise ValueError("ERR_USAGE: vault [set|get] ...")

    action = str(args[0]).lower()

    if action == "set":
        if len(args) != 3:
            raise ValueError("ERR_USAGE: vault set [key] [value]")
        key = _clean_key(str(args[1]))
        raw_value = str(args[2])

        if not key:
            raise ValueError("ERR_INVALID_KEY")

        try:
            # secure_store will encrypt the bytes; write under the key name
            ss.write_encrypted(key, raw_value.encode('utf-8'), overwrite=True)
            try:
                SEC_KERNEL._wipe_memory(raw_value)
            except Exception:
                pass
            return f"[SECURE] Field '{key}' encrypted and persisted."
        except Exception as e:
            logging.exception("Failed to set vault field")
            return f"ERR_VAULT_WRITE: {e}"

    if action == "get":
        if len(args) != 2:
            raise ValueError("ERR_USAGE: vault get [key]")
        key = _clean_key(str(args[1]))
        if not key:
            raise ValueError("ERR_INVALID_KEY")
        try:
            blob = ss.read_encrypted(key)
            value = blob.decode('utf-8')
            # wipe copy after converting
            try:
                SEC_KERNEL._wipe_memory(value)
            except Exception:
                pass
            return f"VAULT_DECRYPTED [{key}]: {value}"
        except FileNotFoundError:
            return f"ERR_KEY_NOT_FOUND: {key}"
        except Exception as e:
            logging.exception("Failed to read vault field")
            return f"ERR_VAULT_READ: {e}"

    return "ERR_UNKNOWN_VAULT_ACTION"