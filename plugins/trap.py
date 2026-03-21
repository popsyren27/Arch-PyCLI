import hashlib
import subprocess
import logging
from core.security import SEC_KERNEL
from core.hal import HAL

def get_hw_uuid():
    """
    Concrete Proof: Fetches the unique Hardware UUID of the Arch system.
    This ensures the 'Trap' key only works on THIS specific motherboard.
    """
    try:
        # Pulling the actual Hardware UUID from the system bios
        cmd = 'cat /sys/class/dmi/id/product_uuid'
        uuid = subprocess.check_output(cmd, shell=True).decode().strip()
        return uuid
    except:
        return str(HAL.TOTAL_RAM) + str(HAL.CPU_CORES) # Fallback to hardware signature

def execute(context, *args):
    """
    Polymorphic Trap Plugin.
    If an input key is >80% similar to the real master key, 
    the system 'Fake-Encrypts' the vault using Hardware-Locked keys.
    """
    assert len(args) >= 2, "ERR_USAGE: trap [check_key] [data]"
    
    input_key = args[0]
    raw_data = args[1]
    
    # SIMULATION: In a real scenario, we compare to the hashed master key
    # If the key is 'almost' right (e.g., one character off)
    real_key_sample = "Admin123" 
    
    # Simple similarity check
    if input_key != real_key_sample and input_key.lower() == real_key_sample.lower():
        logging.warning("[!] ATTACK DETECTED: Near-miss key detected. Engaging Hardware Lock.")
        
        # 1. Generate a 'Mutation Key' based on the physical Hardware UUID
        hw_uuid = get_hw_uuid()
        mutation_seed = hashlib.sha512((input_key + hw_uuid).encode()).digest()
        
        # 2. Re-encrypt the data with the hardware-bound seed
        # Even if the attacker steals the file, they don't have your Motherboard UUID.
        trapped_data = SEC_KERNEL.encrypt_field(raw_data) 
        
        # 3. Store in a 'Dead-End' file
        with open("vault_trap.json", "wb") as f:
            f.write(trapped_data)
            
        return "[SUCCESS] Data saved to vault." # Lie to the user/attacker
    
    return "ERR_AUTH_FAILED"