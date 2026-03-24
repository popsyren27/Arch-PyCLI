import socket
import threading
import json
import time
import logging
import ssl
from typing import Dict, Any, Optional
from core.security import SEC_KERNEL
from core.hal import HAL
from core.loader import KERNEL_LOADER

class DistributedNode:
    """
    Pseudo-Arch Network Layer.
    Handles Node-to-Node command routing with TTL Tokens and AES-GCM payloads.
    """
    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = 9001,
        use_tls: bool = False,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None,
        cafile: Optional[str] = None,
        require_client_cert: bool = False,
        verify_server: bool = True,
    ):
        self.host = host
        self.port = port
        self.node_id = f"node_{int(time.time())}"
        self._is_running = False
        self._server_thread: Optional[threading.Thread] = None
        self._use_tls = bool(use_tls)
        self._verify_server = bool(verify_server)

        self._server_ssl_context: Optional[ssl.SSLContext] = None
        self._client_ssl_context: Optional[ssl.SSLContext] = None

        if self._use_tls:
            # Server TLS context (requires cert+key)
            if not certfile or not keyfile:
                raise ValueError("TLS enabled but certfile/keyfile not provided")
            srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            srv_ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
            if require_client_cert:
                srv_ctx.verify_mode = ssl.CERT_REQUIRED
                if cafile:
                    srv_ctx.load_verify_locations(cafile)
            self._server_ssl_context = srv_ctx

            # Client TLS context
            cli_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if cafile:
                cli_ctx.load_verify_locations(cafile)
            if not verify_server:
                cli_ctx.check_hostname = False
                cli_ctx.verify_mode = ssl.CERT_NONE
            self._client_ssl_context = cli_ctx

    def _process_inbound(self, conn: socket.socket):
        """
        Handles an incoming connection. 
        Implements strict authentication and memory zeroing.
        """
        def recv_all(n: int) -> bytes:
            buf = bytearray()
            while len(buf) < n:
                chunk = conn.recv(n - len(buf))
                if not chunk:
                    raise ConnectionError("Connection closed while reading")
                buf.extend(chunk)
            return bytes(buf)

        def recv_msg() -> bytes:
            # length-prefixed (4-byte BE) framing
            hdr = conn.recv(4)
            if not hdr:
                raise ConnectionError("No header received")
            if len(hdr) < 4:
                hdr += conn.recv(4 - len(hdr))
            size = int.from_bytes(hdr, byteorder='big')
            if size <= 0 or size > 10_000_000:
                raise ValueError("Invalid message size")
            return recv_all(size)

        def send_msg(payload: bytes) -> None:
            size = len(payload)
            conn.sendall(size.to_bytes(4, byteorder='big') + payload)

        try:
            # If server is configured with TLS, attempt to wrap the accepted socket
            if self._server_ssl_context is not None:
                try:
                    conn = self._server_ssl_context.wrap_socket(conn, server_side=True)
                except ssl.SSLError:
                    logging.exception("SSL handshake failed for incoming connection")
                    conn.close()
                    return
            raw = recv_msg()
            packet = json.loads(raw.decode('utf-8'))

            token = packet.get('token')
            if not SEC_KERNEL.validate_token(token):
                logging.warning("Invalid or expired token from remote connection")
                send_msg(json.dumps({"status": "DENIED", "msg": "ERR_INVALID_OR_EXPIRED_TOKEN"}).encode())
                return

            # Decrypt payload
            try:
                encrypted_payload = bytes.fromhex(packet['payload'])
                decrypted_bytes = SEC_KERNEL.decrypt_bytes(encrypted_payload)
                decrypted_cmd = decrypted_bytes.decode('utf-8')
            except Exception:
                logging.exception("Failed to decrypt incoming payload")
                send_msg(json.dumps({"status": "DENIED", "msg": "ERR_DECRYPTION_FAILED"}).encode())
                return

            # Basic input validation
            if not decrypted_cmd or len(decrypted_cmd) > 10_000:
                send_msg(json.dumps({"status": "DENIED", "msg": "ERR_INVALID_COMMAND"}).encode())
                return

            parts = decrypted_cmd.strip().split()
            if not parts:
                send_msg(json.dumps({"status": "DENIED", "msg": "ERR_EMPTY_COMMAND"}).encode())
                return

            cmd_name = parts[0]
            cmd_args = parts[1:]

            context = {"health": HAL.get_health_report(), "origin": "remote"}
            result = KERNEL_LOADER.dispatch(cmd_name, context, *cmd_args)

            try:
                resp_blob = SEC_KERNEL.encrypt_bytes(str(result).encode('utf-8')).hex()
                send_msg(json.dumps({"status": "OK", "data": resp_blob}).encode())
            except Exception:
                logging.exception("Failed to encrypt response")
                send_msg(json.dumps({"status": "ERROR", "msg": "ERR_ENCRYPTION_FAILED"}).encode())

            # attempt to sanitize memory
            try:
                if hasattr(SEC_KERNEL, '_secure_erase'):
                    SEC_KERNEL._secure_erase(decrypted_bytes)
                else:
                    SEC_KERNEL._wipe_memory(decrypted_cmd)
            except Exception:
                pass

        except Exception as e:
            logging.exception("Network Fault: %s", e)
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            conn.close()

    def listen(self):
        """Starts the Node Listener in a background thread."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        self._server_sock = server
        self._is_running = True

        logging.info("Node Online: %s:%s [ID: %s]", self.host, self.port, self.node_id)

        try:
            while self._is_running:
                try:
                    conn, addr = server.accept()
                except OSError:
                    # Socket closed during shutdown
                    break
                # Fork a thread for the connection to prevent blocking the kernel
                client_thread = threading.Thread(target=self._process_inbound, args=(conn,))
                client_thread.daemon = True
                client_thread.start()
        finally:
            try:
                server.close()
            except Exception:
                pass

    def start_node(self):
        self._server_thread = threading.Thread(target=self.listen, daemon=True)
        self._server_thread.start()

    def stop(self, timeout: float = 2.0):
        """Stop the listener and wait for the server thread to exit."""
        self._is_running = False
        try:
            if getattr(self, "_server_sock", None):
                try:
                    self._server_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    self._server_sock.close()
                except Exception:
                    pass
        except Exception:
            pass

        if self._server_thread is not None and self._server_thread.is_alive():
            try:
                self._server_thread.join(timeout=timeout)
            except Exception:
                pass

    def send_remote_cmd(self, target_host: str, target_port: int, token: str, command: str):
        """
        Client method to send commands to other nodes.
        Uses Field-Level Encryption for the command string.
        """
        try:
            with socket.create_connection((target_host, target_port), timeout=5) as sock:
                # prepare packet
                cmd_bytes = command.encode('utf-8')
                encrypted = SEC_KERNEL.encrypt_bytes(cmd_bytes).hex()
                packet = json.dumps({"token": token, "payload": encrypted}).encode('utf-8')
                # send length-prefixed
                sock.sendall(len(packet).to_bytes(4, byteorder='big') + packet)

                # receive response header
                hdr = sock.recv(4)
                if not hdr or len(hdr) < 4:
                    return "Node Connection Failed: no response"
                size = int.from_bytes(hdr, byteorder='big')
                resp = bytearray()
                while len(resp) < size:
                    chunk = sock.recv(min(65536, size - len(resp)))
                    if not chunk:
                        break
                    resp.extend(chunk)
                resp_json = json.loads(bytes(resp).decode('utf-8'))

                if resp_json.get('status') == 'OK':
                    try:
                        data = SEC_KERNEL.decrypt_bytes(bytes.fromhex(resp_json['data']))
                        return data.decode('utf-8')
                    except Exception:
                        return "Remote Error: decryption failed"
                return f"Remote Error: {resp_json.get('msg', 'Unknown')}"
        except Exception as e:
            return f"Node Connection Failed: {e}"

# Global Network Node Context
NETWORK_NODE = DistributedNode()