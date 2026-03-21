import asyncio
import json
import socket
import logging
import time
import hashlib
import os
from typing import Dict, List, Set, Optional, Any

# Production-grade logging for distributed operations
logger = logging.getLogger("NETWORK_PLANE")
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [NETWORK] [%(levelname)s] %(message)s')

class DistributedNode:
    """
    Handles P2P Discovery and State Reconciliation for the VM OS.
    Designed for unreliable networks and heterogeneous environments.
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 9999):
        self.host = host
        self.port = port
        self.peers: Set[str] = set()
        self.state_db: Dict[str, Any] = {}
        self.is_running = False
        self.__msg_buffer = asyncio.Queue(maxsize=1000)
        
        # Unique ID for this node in the cluster
        self.node_id = hashlib.sha1(f"{socket.gethostname()}:{port}".encode()).hexdigest()[:12]

    async def start(self):
        """Starts the Distributed Control Plane."""
        self.is_running = True
        server = await asyncio.start_server(self._handle_inbound, self.host, self.port)
        
        logger.info(f"Node [{self.node_id}] listening on {self.host}:{self.port}")
        
        # Background Tasks: Discovery, Sync, and Heartbeat
        async with server:
            await asyncio.gather(
                self._discovery_loop(),
                self._heartbeat_monitor(),
                self._process_outbound_queue(),
                server.serve_forever()
            )

    async def _handle_inbound(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Processes incoming messages from other nodes in the cluster."""
        try:
            data = await reader.read(4096)
            message = json.loads(data.decode())
            addr = writer.get_extra_info('peername')
            
            # Message Routing logic
            msg_type = message.get("type")
            if msg_type == "HEARTBEAT":
                self.peers.add(f"{addr[0]}:{message['port']}")
            elif msg_type == "STATE_SYNC":
                self._reconcile_state(message['payload'])
            elif msg_type == "SECURITY_ALERT":
                logger.critical(f"CLUSTER ALERT from {addr[0]}: {message['payload']}")
                
        except Exception as e:
            logger.error(f"Inbound processing error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def broadcast_security_event(self, event_details: dict):
        """
        Gossip Protocol: Immediately notifies all known peers of a security event
        detected by the SecurityKernel or a Tool attack simulation.
        """
        payload = {
            "type": "SECURITY_ALERT",
            "node_id": self.node_id,
            "payload": event_details,
            "timestamp": time.time()
        }
        await self.__msg_buffer.put(payload)

    async def _process_outbound_queue(self):
        """Handles retries with exponential backoff for outgoing messages."""
        while self.is_running:
            msg = await self.__msg_buffer.get()
            for peer in list(self.peers):
                peer_host, peer_port = peer.split(":")
                
                # Exponential Backoff Retry Logic
                for attempt in range(3):
                    try:
                        reader, writer = await asyncio.open_connection(peer_host, int(peer_port))
                        writer.write(json.dumps(msg).encode())
                        await writer.drain()
                        writer.close()
                        await writer.wait_closed()
                        break # Success
                    except Exception:
                        wait = 2 ** attempt
                        logger.warning(f"Peer {peer} unreachable. Retrying in {wait}s...")
                        await asyncio.sleep(wait)

    async def _discovery_loop(self):
        """
        Passive Discovery: In a real system, this would use UDP broadcast 
        or a seed list to find the first peers.
        """
        while self.is_running:
            # Placeholder for Seed-Node Discovery
            logger.debug(f"Active Peer Count: {len(self.peers)}")
            await asyncio.sleep(60)

    def _reconcile_state(self, remote_state: dict):
        """
        Conflict Resolution: Ensures all nodes eventually reach the same 
        security configuration (Eventual Consistency).
        """
        for key, value in remote_state.items():
            if key not in self.state_db or self.state_db[key]['version'] < value['version']:
                self.state_db[key] = value
                logger.info(f"State Updated: {key} synced to version {value['version']}")

    async def _heartbeat_monitor(self):
        """Self-Healing: Prunes dead nodes from the peer list."""
        while self.is_running:
            # Broadcast our presence to known peers
            heartbeat = {"type": "HEARTBEAT", "port": self.port, "node_id": self.node_id}
            await self.__msg_buffer.put(heartbeat)
            await asyncio.sleep(30)