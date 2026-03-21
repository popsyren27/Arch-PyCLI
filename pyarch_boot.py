import asyncio
import sys
import os

# Ensure the current directory is in the path so we can import the pyarch package
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from pyarch.node.agent import NodeAgent
from pyarch.ipc.network import Message

async def simulate_internal_client():
    """
    Simulates a local or remote client sending a command to the Node.
    
    This demonstrates the end-to-end flow:
    Auth -> Registry -> Capability Check -> Execution.
    """
    await asyncio.sleep(2) # Give the Node Agent time to bind the socket
    
    print("\n" + "="*50)
    print("PY-ARCH OS INTERACTIVE CLI SIMULATOR")
    print("="*50)

    try:
        # Attempt to connect to the Node's IPC Server
        reader, writer = await asyncio.open_connection('127.0.0.1', 8888)
        
        # Test Case 1: Authorized System Info Request
        print("[Client] Requesting 'system.info' with Admin Token...")
        msg_info = Message(
            sender_id="terminal_01",
            receiver_id="node_001",
            action="system.info",
            payload={},
            auth_token="admin_token_123"
        )
        writer.write(msg_info.to_json().encode())
        await writer.drain()
        
        response = await reader.read(4096)
        print(f"[Node Response]: {response.decode()}")

        # Test Case 2: Unauthorized Echo Request (Guest attempting Admin-level flow)
        print("\n[Client] Requesting 'system.echo' with Guest Token...")
        msg_echo = Message(
            sender_id="terminal_01",
            receiver_id="node_001",
            action="system.echo",
            payload={"text": "Hello Py-Arch!"},
            auth_token="guest_token_456"
        )
        writer.write(msg_echo.to_json().encode())
        await writer.drain()
        
        response = await reader.read(4096)
        print(f"[Node Response]: {response.decode()}")

        writer.close()
        await writer.wait_closed()
        print("="*50 + "\n")

    except ConnectionRefusedError:
        print("[!] Client Error: Could not connect to Node Agent. Check if port 8888 is occupied.")
    except Exception as e:
        print(f"[!] Client Error: {e}")

async def main():
    """
    Main OS Entry Point.
    
    Bootstraps the primary Node Agent and runs a simulation of system activity.
    """
    # Initialize Node 001
    node = NodeAgent("node_001")
    
    try:
        # Run the Node's boot sequence and our simulation concurrently
        # In a production environment, the node.boot() would run as a daemon.
        await asyncio.gather(
            node.boot(),
            simulate_internal_client()
        )
    except KeyboardInterrupt:
        print("\n[!] Shutdown signal received (Ctrl+C).")
    finally:
        node.shutdown()

if __name__ == "__main__":
    # Check for Python version compatibility
    if sys.version_info < (3, 7):
        print("Py-Arch OS requires Python 3.7+ for advanced asyncio features.")
        sys.exit(1)
        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass