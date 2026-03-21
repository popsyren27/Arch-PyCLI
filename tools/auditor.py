import socket
import json
import os
import logging

# Configuration for the target "Pseudo-Arch" Node
TARGET_IP = "127.0.0.1"
TARGET_PORT = 9001
VAULT_FILE = "vault.json"

def attempt_unauthorized_relay():
    """
    ATTACK SIMULATION 1: Unauthorized Command Injection.
    Attempts to bypass the Security Kernel by sending a command 
    without a valid Short-Lived Token.
    """
    print(f"[!] Attempting unauthorized relay to {TARGET_IP}:{TARGET_PORT}...")
    
    payload = {
        "token": "INVALID_EXPIRED_OR_GUESSED_TOKEN",
        "payload": "48656c6c6f" # Hex for 'Hello'
    }
    
    try:
        with socket.create_connection((TARGET_IP, TARGET_PORT), timeout=2) as sock:
            sock.sendall(json.dumps(payload).encode())
            response = sock.recv(4096).decode()
            print(f"[*] Node Response: {response}")
            
            if "DENIED" in response:
                print("[SUCCESS] Security Kernel blocked the unauthorized relay.")
            else:
                print("[FAILURE] System leaked data or accepted an unauthenticated command!")
    except Exception as e:
        print(f"[!] Connection failed: {e}")

def check_data_leakage():
    """
    ATTACK SIMULATION 2: Cold Storage Analysis.
    Checks if the 'vault.json' contains any raw/plaintext data.
    """
    print(f"\n[!] Analyzing {VAULT_FILE} for raw data leakage...")
    
    if not os.path.exists(VAULT_FILE):
        print("[?] Vault file not found. Nothing to scavenge.")
        return

    with open(VAULT_FILE, 'r') as f:
        content = f.read()
        
    # Check for common plaintext patterns (e.g., typical passwords or strings)
    # A secure system should only show Hex/Ciphertext.
    if "MySuperSecret" in content or "password" in content.lower():
        print("[FAILURE] Raw data found in storage! Encryption failed.")
    else:
        print("[SUCCESS] No plaintext found. Field-level encryption is holding.")

if __name__ == "__main__":
    print("--- PY-ARCH SECURITY AUDITOR (PEN-TEST TOOL) ---")
    attempt_unauthorized_relay()
    check_data_leakage()