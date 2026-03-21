import asyncio
import json
import time
from typing import Dict, Any, Optional
import logging

class Message:
    """
    Standardized IPC message structure for Py-Arch OS.
    
    Includes metadata for routing, security, and replay protection.
    """
    def __init__(self, sender_id: str, receiver_id: str, action: str, payload: Dict[str, Any], auth_token: str):
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.action = action
        self.payload = payload
        self.auth_token = auth_token
        self.timestamp = time.time()
        self.nonce = hash(f"{self.timestamp}-{sender_id}-{action}")

    def to_json(self) -> str:
        return json.dumps(self.__dict__)

    @staticmethod
    def from_json(data: str) -> 'Message':
        data_dict = json.loads(data)
        msg = Message(
            data_dict['sender_id'], 
            data_dict['receiver_id'], 
            data_dict['action'], 
            data_dict['payload'], 
            data_dict['auth_token']
        )
        msg.timestamp = data_dict.get('timestamp', time.time())
        msg.nonce = data_dict.get('nonce', 0)
        return msg

class IPCManager:
    """
    Manages distributed and local communication for the node.
    
    Design Decision:
    - Uses an asynchronous TCP server for remote node communication.
    - Implements a local asyncio.Queue as a fallback if network binding fails.
    - Ensures that the system remains functional even in 'Airplane Mode' or 
      restricted network environments.
    """
    def __init__(self, config, logger: logging.Logger, node_agent):
        self.config = config
        self.logger = logger
        self.node_agent = node_agent # Reference to the core agent for routing
        self.server = None
        self.local_queue = asyncio.Queue()

    async def start_server(self):
        """
        Attempts to start the TCP IPC server.
        Falls back to local-only mode if the port is blocked or unavailable.
        """
        try:
            self.server = await asyncio.start_server(
                self.handle_client, self.config.host, self.config.port
            )
            addr = self.server.sockets[0].getsockname()
            self.logger.info(f"IPC Server successfully bound to {addr}")
            
            async with self.server:
                await self.server.serve_forever()
        except (OSError, PermissionError) as e:
            self.logger.error(f"Network IPC failed to start: {e}. Falling back to LOCAL-ONLY mode.")
            self.config.fallback_local_only = True
            # In local-only mode, we just keep the process alive and watch the queue
            await self.process_local_queue()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Callback for incoming TCP connections.
        """
        addr = writer.get_extra_info('peername')
        try:
            data = await reader.read(8192) # Standard buffer size
            if not data:
                return

            message_str = data.decode()
            message = Message.from_json(message_str)
            
            self.logger.debug(f"Remote IPC request from {addr}: {message.action}")
            
            # Dispatch to the Node Agent for execution
            response = await self.node_agent.execute_message(message)
            
            writer.write(json.dumps(response).encode())
            await writer.drain()
        except Exception as e:
            self.logger.error(f"Error handling remote IPC client {addr}: {e}")
            try:
                error_resp = {"status": "error", "error": "IPC processing failure"}
                writer.write(json.dumps(error_resp).encode())
                await writer.drain()
            except:
                pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def process_local_queue(self):
        """
        Processes messages placed directly into the local memory bus.
        Used as a fallback when networking is disabled.
        """
        self.logger.info("Internal IPC queue processor active.")
        while True:
            try:
                message = await self.local_queue.get()
                await self.node_agent.execute_message(message)
                self.local_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Local IPC queue execution error: {e}")

    async def send_remote(self, host: str, port: int, message: Message) -> Dict[str, Any]:
        """
        Client method to send a command to another Py-Arch node.
        """
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(message.to_json().encode())
            await writer.drain()

            data = await reader.read(8192)
            writer.close()
            await writer.wait_closed()
            
            return json.loads(data.decode())
        except Exception as e:
            self.logger.error(f"Failed to communicate with remote node {host}:{port}: {e}")
            return {"status": "error", "error": "Remote connection failed"}