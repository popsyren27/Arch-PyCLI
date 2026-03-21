import json
import os
import logging
from core.security import SEC_KERNEL

DB_PATH = "vault.json"

def execute(context, *args):
    """
    Secure Vault Plugin.
    Demonstrates: Field-Level Encryption & Memory Wiping.
    Usage: 
      vault set [key] [value] - Encrypts and stores a value.
      vault get [key]         - Decrypts and retrieves a value.
    """
    assert len(args) > 1, "ERR_USAGE: vault [set | get]"
    
    action = args[0].lower()
    
    # Initialize DB if missing
    if not os.path.exists(DB_PATH):
        with open(DB_PATH, 'w') as f:
            json.dump({}, f)

    if action == "set":
        assert len(args) == 3, "ERR_USAGE: vault set [key] [value]"
        key, raw_value = args[1], args[2]
        
        # 1. Encrypt the field BEFORE it reaches the storage layer
        encrypted_data = SEC_KERNEL.encrypt_field(raw_value).hex()
        
        with open(DB_PATH, 'r+') as f:
            db = json.load(f)
            db[key] = encrypted_data
            f.seek(0)
            json.dump(db, f, indent=4)
            f.truncate()
        
        # 2. Memory Scavenging: Overwrite the plaintext value in RAM
        SEC_KERNEL._wipe_memory(raw_value)
        return f"[SECURE] Field '{key}' encrypted and persisted to {DB_PATH}."

    if action == "get":
        key = args[1]
        with open(DB_PATH, 'r') as f:
            db = json.load(f)
            
        if key not in db:
            return f"ERR_KEY_NOT_FOUND: {key}"
        
        # 3. Decrypt the specific field
        encrypted_blob = bytes.fromhex(db[key])
        decrypted_value = SEC_KERNEL.decrypt_field(encrypted_blob)
        
        # Logic-to-Assertion: Ensure decryption didn't return null
        assert decrypted_value, "ERR_DECRYPTION_FAILURE"
        
        result = f"VAULT_DECRYPTED [{key}]: {decrypted_value}"
        
        # 4. Immediate wipe of the decrypted string after use
        SEC_KERNEL._wipe_memory(decrypted_value)
        return result

    return "ERR_UNKNOWN_VAULT_ACTION"