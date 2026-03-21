import socket
import threading
import json
import time
import logging
from typing import Dict, Any, Optional
from core.security import SEC_KERNEL
from core.hal import HAL
from core.loader import KERNEL_LOADER

class DistributedNode:
    """
    Pseudo-Arch Network Layer.
    Handles Node-to-Node command routing with TTL Tokens and AES-GCM payloads.
    """
    def __init__(self, host: str = '127.0.0.1', port: int = 9001):
        self.host = host
        self.port = port
        self.node_id = f"node_{int(time.time())}"
        self._is_running = False
        self._server_thread: Optional[threading.Thread] = None

    def _process_inbound(self, conn: socket.socket):
        """
        Handles an incoming connection. 
        Implements strict authentication and memory zeroing.
        """
        try:
            # Receive the Encrypted Packet
            raw_data = conn.recv(4096)
            if not raw_data:
                return

            packet = json.loads(raw_data.decode())
            
            # --- ASSERTION: SECURITY CHECK ---
            token = packet.get("token")
            assert SEC_KERNEL.validate_token(token), "ERR_INVALID_OR_EXPIRED_TOKEN"
            
            # Decrypt the Command Payload
            encrypted_payload = bytes.fromhex(packet["payload"])
            decrypted_cmd = SEC_KERNEL.decrypt_field(encrypted_payload)
            
            # Execute via Kernel Loader
            cmd_parts = decrypted_cmd.split()
            cmd_name = cmd_parts[0]
            cmd_args = cmd_parts[1:]
            
            # Inject Hardware Context into execution
            context = {"health": HAL.get_health_report(), "origin": "remote"}
            result = KERNEL_LOADER.dispatch(cmd_name, context, *cmd_args)
            
            # Encrypt response before sending back
            response_payload = SEC_KERNEL.encrypt_field(str(result)).hex()
            conn.sendall(json.dumps({"status": "OK", "data": response_payload}).encode())

            # Memory Scavenging: Clear the decrypted command from RAM
            SEC_KERNEL._wipe_memory(decrypted_cmd)

        except AssertionError as ae:
            logging.error(f"Security Violation: {ae}")
            conn.sendall(json.dumps({"status": "DENIED", "msg": str(ae)}).encode())
        except Exception as e:
            logging.error(f"Network Fault: {e}")
        finally:
            conn.close()

    def listen(self):
        """Starts the Node Listener in a background thread."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        self._is_running = True
        
        logging.info(f"Node Online: {self.host}:{self.port} [ID: {self.node_id}]")
        
        while self._is_running:
            conn, addr = server.accept()
            # Fork a thread for the connection to prevent blocking the kernel
            client_thread = threading.Thread(target=self._process_inbound, args=(conn,))
            client_thread.start()

    def start_node(self):
        self._server_thread = threading.Thread(target=self.listen, daemon=True)
        self._server_thread.start()

    def send_remote_cmd(self, target_host: str, target_port: int, token: str, command: str):
        """
        Client method to send commands to other nodes.
        Uses Field-Level Encryption for the command string.
        """
        try:
            with socket.create_connection((target_host, target_port), timeout=5) as sock:
                # Encrypt the command string
                encrypted_cmd = SEC_KERNEL.encrypt_field(command).hex()
                packet = {
                    "token": token,
                    "payload": encrypted_cmd
                }
                sock.sendall(json.dumps(packet).encode())
                
                # Receive and Decrypt response
                resp_raw = sock.recv(4096)
                resp_json = json.loads(resp_raw.decode())
                
                if resp_json["status"] == "OK":
                    decrypted_resp = SEC_KERNEL.decrypt_field(bytes.fromhex(resp_json["data"]))
                    return decrypted_resp
                return f"Remote Error: {resp_json.get('msg', 'Unknown')}"
        except Exception as e:
            return f"Node Connection Failed: {e}"

# Global Network Node Context
NETWORK_NODE = DistributedNode()