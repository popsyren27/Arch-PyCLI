import hashlib
import logging
from typing import Any, Dict
from core.security import SEC_KERNEL
from core.hal import HAL
from core.secure_store import write_encrypted


def _get_hw_fingerprint() -> str:
    # Prefer HAL-provided fingerprint helper if available
    try:
        fp = getattr(HAL, 'get_fingerprint', None)
        if callable(fp):
            return fp()
    except Exception:
        pass
    # Fallback to hardware summary
    try:
        return f"{HAL.TOTAL_RAM}-{HAL.CPU_CORES}"
    except Exception:
        return "unknown-hw"


def execute(context: Dict[str, Any], *args) -> str:
    """
    Trap plugin: on near-miss key attempts, store a trapped encrypted blob
    bound to local hardware in the secure store. This reduces file-system
    leakage risk and avoids writing plaintext files to the repository root.
    Usage: trap [check_key] [data]
    """
    if len(args) < 2:
        raise ValueError("ERR_USAGE: trap [check_key] [data]")

    input_key = str(args[0])
    raw_data = str(args[1])

    # Simulation sample key — in production compare to a secure hash
    real_key_sample = "Admin123"

    # Case-insensitive near-miss check
    if input_key != real_key_sample and input_key.lower() == real_key_sample.lower():
        logging.warning("Near-miss key detected; engaging trap storage")

        hw_fp = _get_hw_fingerprint()
        mutation_seed = hashlib.sha512((input_key + hw_fp).encode()).digest()

        try:
            # Encrypt the data bytes with the Security kernel
            blob = SEC_KERNEL.encrypt_bytes(raw_data.encode('utf-8'))
            # Store in secure store under a trap namespace
            path = f"trap/{hashlib.sha256(blob).hexdigest()}.bin"
            write_encrypted(path, blob, overwrite=False)
        except Exception:
            logging.exception("Failed to write trapped blob")
            # Don't leak details to caller
            return "[SUCCESS] Data saved to vault."

        # Intentionally return a success message to not reveal trap behavior
        return "[SUCCESS] Data saved to vault."

    return "ERR_AUTH_FAILED"