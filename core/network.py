"""
Network Module for Arch-PyCLI.

This module provides the distributed networking layer for Arch-PyCLI,
enabling secure node-to-node communication over TCP with TLS support.

Features:
- TCP server with configurable connection limits
- TLS/SSL support with client certificate verification
- Encrypted command routing with token authentication
- Thread-safe connection handling
- Automatic timeout enforcement
- Rate limiting per connection
- Comprehensive error handling and fallbacks

SECURITY NOTES:
    - All remote commands require valid tokens
    - Payloads are encrypted with AES-GCM
    - TLS provides transport layer security
    - Connection limits prevent resource exhaustion

Author: Arch-PyCLI Team
Version: 0.1.0
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

# Import security kernel for encryption and token validation
from core.security import SEC_KERNEL

# Import hardware abstraction for health checks
try:
    from core.hal import HAL
except ImportError:
    # Fallback if HAL not available
    class HALFallback:
        @staticmethod
        def get_health_report():
            return {"status": "UNKNOWN", "memory_pressure": 0, "cpu_utilization": 0}
    HAL = HALFallback()

# Import plugin loader for command dispatch
try:
    from core.loader import KERNEL_LOADER
except ImportError:
    KERNEL_LOADER = None


# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

# Connection limits
DEFAULT_MAX_CONNECTIONS: int = 50  # Maximum concurrent connections
DEFAULT_CONNECTION_TIMEOUT: float = 30.0  # Socket timeout in seconds
DEFAULT_SHUTDOWN_TIMEOUT: float = 5.0  # Graceful shutdown timeout
MAX_PACKET_SIZE: int = 10_000_000  # 10MB max packet size (protection)
MIN_PACKET_SIZE: int = 1  # Minimum valid packet size

# Threading
WORKER_THREAD_PREFIX: str = "NetworkWorker"
CLEANUP_THREAD_PREFIX: str = "NetworkCleanup"

# Debug configuration
DEBUG_PREFIX: str = "[NETWORK_DEBUG]"
_is_debug_mode: bool = False


def set_debug_mode(enabled: bool) -> None:
    """Enable or disable debug logging for network operations."""
    global _is_debug_mode
    _is_debug_mode = enabled


def _debug_log(message: str, *args: Any) -> None:
    """Internal debug logger that respects debug mode."""
    if _is_debug_mode:
        _logger.debug(f"{DEBUG_PREFIX} {message}", *args)


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class NetworkError(Exception):
    """Base exception for all network errors."""
    pass


class ConnectionLimitExceededError(NetworkError):
    """Raised when maximum connections are exceeded."""
    pass


class ConnectionTimeoutError(NetworkError):
    """Raised when connection times out."""
    pass


class InvalidPacketError(NetworkError):
    """Raised when packet format is invalid."""
    pass


class TLSConfigurationError(NetworkError):
    """Raised when TLS configuration is invalid."""
    pass


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class ConnectionStats:
    """
    Statistics for a single connection.
    
    Attributes:
        connection_id: Unique identifier for this connection
        remote_address: Tuple of (host, port)
        connected_at: Unix timestamp when connected
        bytes_received: Total bytes received
        bytes_sent: Total bytes sent
        requests_processed: Number of requests handled
        last_activity: Unix timestamp of last activity
    """
    connection_id: str
    remote_address: Tuple[str, int]
    connected_at: float
    bytes_received: int = 0
    bytes_sent: int = 0
    requests_processed: int = 0
    last_activity: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)
    
    def update_activity(self, bytes_in: int = 0, bytes_out: int = 0) -> None:
        """Update connection statistics."""
        with self._lock:
            self.last_activity = time.time()
            self.bytes_received += bytes_in
            self.bytes_sent += bytes_out
            if bytes_in > 0:
                self.requests_processed += 1
    
    @property
    def age_seconds(self) -> float:
        """Get connection age in seconds."""
        return time.time() - self.connected_at
    
    @property
    def is_idle_too_long(self) -> bool:
        """Check if connection has been idle too long."""
        return (time.time() - self.last_activity) > DEFAULT_CONNECTION_TIMEOUT
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/debugging."""
        with self._lock:
            return {
                "connection_id": self.connection_id,
                "remote_address": f"{self.remote_address[0]}:{self.remote_address[1]}",
                "connected_at": self.connected_at,
                "age_seconds": self.age_seconds,
                "bytes_received": self.bytes_received,
                "bytes_sent": self.bytes_sent,
                "requests_processed": self.requests_processed,
                "last_activity": self.last_activity,
                "idle_seconds": time.time() - self.last_activity,
            }


@dataclass
class NetworkConfig:
    """
    Configuration for the distributed network node.
    
    Attributes:
        host: Host address to bind to
        port: Port number to listen on
        max_connections: Maximum concurrent connections
        connection_timeout: Socket timeout in seconds
        use_tls: Enable TLS encryption
        certfile: Path to TLS certificate
        keyfile: Path to TLS private key
        cafile: Path to CA certificate for client verification
        require_client_cert: Require client certificates
        verify_server: Verify server certificates (client mode)
    """
    host: str = "127.0.0.1"
    port: int = 9001
    max_connections: int = DEFAULT_MAX_CONNECTIONS
    connection_timeout: float = DEFAULT_CONNECTION_TIMEOUT
    use_tls: bool = False
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    cafile: Optional[str] = None
    require_client_cert: bool = False
    verify_server: bool = True


# =============================================================================
# SETUP LOGGING
# =============================================================================

# Create module-level logger
_logger: logging.Logger = logging.getLogger("NETWORK")
if not _logger.handlers:
    # Configure with console handler
    _handler: logging.Handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter: logging.Formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
    )
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

# Also try to add file handler if possible (non-blocking)
try:
    _file_handler: logging.Handler = logging.FileHandler("network.log")
    _file_handler.setLevel(logging.INFO)
    _file_handler.setFormatter(_formatter)
    _logger.addHandler(_file_handler)
except (IOError, PermissionError, OSError):
    _logger.warning(
        "[NETWORK] File logging unavailable, using stdout only."
    )

_logger.info("[NETWORK] Network module initialized")


# =============================================================================
# GLOBAL CONNECTION TRACKING
# =============================================================================

# Thread-safe connection tracking
_connection_lock: threading.Lock = threading.Lock()
_active_connections: Dict[str, ConnectionStats] = {}
_connection_counter: int = 0
_total_connections_handled: int = 0
_total_bytes_received: int = 0
_total_bytes_sent: int = 0


def _get_connection_id() -> str:
    """Generate a unique connection ID."""
    global _connection_counter
    with _connection_lock:
        _connection_counter += 1
        return f"conn_{_connection_counter}_{int(time.time())}"


def _register_connection(stats: ConnectionStats) -> None:
    """Register a new connection."""
    global _total_connections_handled
    with _connection_lock:
        _active_connections[stats.connection_id] = stats
        _total_connections_handled += 1
    _debug_log("Connection registered: %s", stats.connection_id)


def _unregister_connection(connection_id: str) -> None:
    """Unregister a connection."""
    with _connection_lock:
        if connection_id in _active_connections:
            del _active_connections[connection_id]
    _debug_log("Connection unregistered: %s", connection_id)


def get_connection_count() -> int:
    """Get current active connection count."""
    with _connection_lock:
        return len(_active_connections)


def get_network_stats() -> Dict[str, Any]:
    """Get network statistics."""
    global _total_bytes_received, _total_bytes_sent
    with _connection_lock:
        return {
            "active_connections": len(_active_connections),
            "total_connections_handled": _total_connections_handled,
            "total_bytes_received": _total_bytes_received,
            "total_bytes_sent": _total_bytes_sent,
            "connections": [c.to_dict() for c in _active_connections.values()],
        }


# =============================================================================
# DISTRIBUTED NODE CLASS
# =============================================================================

class DistributedNode:
    """
    TCP-based distributed node for command routing.
    
    This class implements:
        - TCP server with configurable connection limits
        - TLS/SSL encryption support
        - Token-based authentication
        - AES-GCM encrypted payloads
        - Thread-safe connection handling
    
    Thread Safety:
        All public methods are thread-safe. Connection handling
        is done in separate worker threads.
    
    Example:
        >>> node = DistributedNode(host="0.0.0.0", port=9001)
        >>> node.start_node()
        >>> # Node is now listening for connections...
        >>> node.stop()
    """
    
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9001,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        connection_timeout: float = DEFAULT_CONNECTION_TIMEOUT,
        use_tls: bool = False,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None,
        cafile: Optional[str] = None,
        require_client_cert: bool = False,
        verify_server: bool = True,
    ) -> None:
        """
        Initialize the distributed node.
        
        Args:
            host: Host address to bind to
            port: Port number to listen on
            max_connections: Maximum concurrent connections
            connection_timeout: Socket timeout in seconds
            use_tls: Enable TLS encryption
            certfile: Path to TLS certificate
            keyfile: Path to TLS private key
            cafile: Path to CA certificate for client verification
            require_client_cert: Require client certificates
            verify_server: Verify server certificates
        
        Raises:
            TLSConfigurationError: If TLS is enabled but cert/key missing
        """
        self.host = host
        self.port = port
        self.node_id: str = f"node_{int(time.time())}"
        
        # Configuration
        self._config: NetworkConfig = NetworkConfig(
            host=host,
            port=port,
            max_connections=max_connections,
            connection_timeout=connection_timeout,
            use_tls=use_tls,
            certfile=certfile,
            keyfile=keyfile,
            cafile=cafile,
            require_client_cert=require_client_cert,
            verify_server=verify_server,
        )
        
        # State
        self._is_running: bool = False
        self._server_socket: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None
        self._cleanup_thread: Optional[threading.Thread] = None
        self._shutdown_requested: bool = False
        self._main_lock: threading.Lock = threading.Lock()
        
        # SSL contexts
        self._server_ssl_context: Optional[ssl.SSLContext] = None
        self._client_ssl_context: Optional[ssl.SSLContext] = None
        
        # Initialize SSL contexts if TLS enabled
        if use_tls:
            self._initialize_ssl_contexts()
        
        # Logger
        self._logger: logging.Logger = logging.getLogger("NETWORK")
        _logger.info(
            "[NETWORK] Node initialized: %s:%d (TLS=%s, max_conn=%d)",
            host,
            port,
            use_tls,
            max_connections
        )
        _debug_log(
            "Node config: timeout=%.1fs, verify_server=%s",
            connection_timeout,
            verify_server
        )
    
    def _initialize_ssl_contexts(self) -> None:
        """
        Initialize SSL contexts for server and client.
        
        Raises:
            TLSConfigurationError: If TLS configuration is invalid
        """
        try:
            # Validate TLS configuration
            if not self._config.certfile or not self._config.keyfile:
                raise TLSConfigurationError(
                    "TLS enabled but certfile/keyfile not provided"
                )
            
            # Server context
            try:
                self._server_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self._server_ssl_context.load_cert_chain(
                    certfile=self._config.certfile,
                    keyfile=self._config.keyfile
                )
                
                if self._config.require_client_cert:
                    self._server_ssl_context.verify_mode = ssl.CERT_REQUIRED
                    if self._config.cafile:
                        self._server_ssl_context.load_verify_locations(
                            self._config.cafile
                        )
                
                _debug_log("Server SSL context initialized")
                
            except ssl.SSLError as e:
                raise TLSConfigurationError(f"Failed to initialize server SSL: {e}")
            
            # Client context
            try:
                self._client_ssl_context = ssl.create_default_context(
                    ssl.Purpose.SERVER_AUTH
                )
                
                if self._config.cafile:
                    self._client_ssl_context.load_verify_locations(
                        self._config.cafile
                    )
                
                if not self._config.verify_server:
                    self._client_ssl_context.check_hostname = False
                    self._client_ssl_context.verify_mode = ssl.CERT_NONE
                
                _debug_log("Client SSL context initialized")
                
            except ssl.SSLError as e:
                self._logger.warning(
                    "[NETWORK] Client SSL context warning: %s",
                    e
                )
            
            _logger.info(
                "[NETWORK] TLS initialized (require_client_cert=%s)",
                self._config.require_client_cert
            )
            
        except TLSConfigurationError:
            raise
        except Exception as e:
            raise TLSConfigurationError(f"TLS initialization failed: {e}") from e
    
    # =========================================================================
    # CONNECTION HANDLING
    # =========================================================================
    
    def _handle_connection(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        """
        Handle an incoming connection in a worker thread.
        
        This method:
            1. Registers the connection
            2. Wraps socket with SSL if configured
            3. Processes the request
            4. Cleans up on completion
        
        Args:
            conn: Connected socket
            addr: Remote address tuple
        """
        connection_id: str = _get_connection_id()
        stats: Optional[ConnectionStats] = None
        
        try:
            # Create connection stats
            stats = ConnectionStats(
                connection_id=connection_id,
                remote_address=addr,
                connected_at=time.time()
            )
            _register_connection(stats)
            
            self._logger.info(
                "[NETWORK] New connection from %s:%s [%s]",
                addr[0],
                addr[1],
                connection_id
            )
            _debug_log("Handling connection %s", connection_id)
            
            # Set socket timeout
            conn.settimeout(self._config.connection_timeout)
            
            # Wrap with SSL if configured
            if self._server_ssl_context is not None:
                try:
                    conn = self._server_ssl_context.wrap_socket(
                        conn,
                        server_side=True
                    )
                    _debug_log("SSL handshake completed for %s", connection_id)
                except ssl.SSLError as e:
                    self._logger.warning(
                        "[NETWORK] SSL handshake failed for %s: %s",
                        connection_id,
                        e
                    )
                    return
            
            # Process the connection
            self._process_connection(conn, stats)
            
        except socket.timeout:
            self._logger.warning(
                "[NETWORK] Connection timeout: %s [%s]",
                addr,
                connection_id
            )
        except ConnectionResetError:
            self._logger.info(
                "[NETWORK] Connection reset by peer: %s [%s]",
                addr,
                connection_id
            )
        except BrokenPipeError:
            self._logger.info(
                "[NETWORK] Broken pipe: %s [%s]",
                addr,
                connection_id
            )
        except Exception as e:
            self._logger.exception(
                "[NETWORK] Connection error for %s [%s]: %s",
                addr,
                connection_id,
                e
            )
        finally:
            # Cleanup
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            
            try:
                conn.close()
            except Exception:
                pass
            
            if stats:
                _unregister_connection(connection_id)
            
            self._logger.info(
                "[NETWORK] Connection closed: %s [%s] (processed=%d)",
                addr[0],
                connection_id,
                stats.requests_processed if stats else 0
            )
    
    def _process_connection(self, conn: socket.socket, stats: ConnectionStats) -> None:
        """
        Process a single connection request.
        
        Handles the full request-response cycle including:
            1. Receive length-prefixed packet
            2. Parse JSON payload
            3. Validate token
            4. Decrypt command
            5. Dispatch to command handler
            6. Encrypt and send response
        
        Args:
            conn: Connected socket
            stats: Connection statistics
        """
        try:
            # Receive packet
            packet: bytes = self._receive_packet(conn)
            stats.update_activity(bytes_in=len(packet))
            
            # Parse JSON
            try:
                data: Dict[str, Any] = json.loads(packet.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                self._logger.warning(
                    "[NETWORK] Invalid JSON from %s: %s",
                    stats.remote_address,
                    e
                )
                self._send_response(
                    conn,
                    stats,
                    status="DENIED",
                    message="ERR_INVALID_JSON"
                )
                return
            
            # Extract token and payload
            token: Optional[str] = data.get('token')
            encrypted_payload: Optional[str] = data.get('payload')
            
            # Validate token
            if not token or not SEC_KERNEL.validate_token(token):
                self._logger.warning(
                    "[NETWORK] Invalid/expired token from %s",
                    stats.remote_address
                )
                self._send_response(
                    conn,
                    stats,
                    status="DENIED",
                    message="ERR_INVALID_OR_EXPIRED_TOKEN"
                )
                return
            
            # Decrypt payload
            if not encrypted_payload:
                self._send_response(
                    conn,
                    stats,
                    status="DENIED",
                    message="ERR_MISSING_PAYLOAD"
                )
                return
            
            try:
                encrypted_bytes: bytes = bytes.fromhex(encrypted_payload)
                decrypted_bytes: bytes = SEC_KERNEL.decrypt_bytes(encrypted_bytes)
                command: str = decrypted_bytes.decode('utf-8')
            except Exception as e:
                self._logger.warning(
                    "[NETWORK] Decryption failed for %s: %s",
                    stats.connection_id,
                    e
                )
                self._send_response(
                    conn,
                    stats,
                    status="DENIED",
                    message="ERR_DECRYPTION_FAILED"
                )
                return
            
            # Validate command
            if not command or len(command) > 10000:
                self._send_response(
                    conn,
                    stats,
                    status="DENIED",
                    message="ERR_INVALID_COMMAND"
                )
                return
            
            # Parse command
            parts: List[str] = command.strip().split()
            if not parts:
                self._send_response(
                    conn,
                    stats,
                    status="DENIED",
                    message="ERR_EMPTY_COMMAND"
                )
                return
            
            cmd_name: str = parts[0]
            cmd_args: List[str] = parts[1:]
            
            _debug_log(
                "Executing command '%s' from %s",
                cmd_name,
                stats.connection_id
            )
            
            # Dispatch command
            context: Dict[str, Any] = {
                "health": HAL.get_health_report(),
                "origin": "remote",
                "connection_id": stats.connection_id,
            }
            
            # Check if loader is available
            if KERNEL_LOADER is None:
                result: str = "ERR_LOADER_UNAVAILABLE"
            else:
                result = KERNEL_LOADER.dispatch(cmd_name, context, *cmd_args)
            
            # Encrypt and send response
            try:
                response_bytes: bytes = str(result).encode('utf-8')
                encrypted_response: bytes = SEC_KERNEL.encrypt_bytes(response_bytes)
                response_hex: str = encrypted_response.hex()
                
                self._send_response(
                    conn,
                    stats,
                    status="OK",
                    data=response_hex
                )
                
                stats.update_activity(bytes_out=len(response_hex))
                
            except Exception as e:
                self._logger.exception("Failed to encrypt response")
                self._send_response(
                    conn,
                    stats,
                    status="ERROR",
                    message="ERR_ENCRYPTION_FAILED"
                )
            
            # Wipe decrypted command from memory
            try:
                SEC_KERNEL._wipe_memory(command)
                SEC_KERNEL._wipe_memory(decrypted_bytes)
            except Exception:
                pass
            
        except socket.timeout:
            self._logger.warning(
                "[NETWORK] Timeout during processing: %s",
                stats.connection_id
            )
        except Exception as e:
            self._logger.exception(
                "[NETWORK] Processing error for %s: %s",
                stats.connection_id,
                e
            )
    
    def _receive_packet(self, conn: socket.socket) -> bytes:
        """
        Receive a length-prefixed packet from the connection.
        
        Packet format:
            - 4 bytes: big-endian packet length
            - N bytes: packet data (JSON)
        
        Args:
            conn: Connected socket
        
        Returns:
            Raw packet bytes
        
        Raises:
            InvalidPacketError: If packet is invalid
            ConnectionTimeoutError: If receive times out
        """
        try:
            # Receive header (4 bytes)
            header: bytes = b""
            while len(header) < 4:
                chunk: bytes = conn.recv(4 - len(header))
                if not chunk:
                    raise ConnectionError("Connection closed during header receive")
                header += chunk
            
            # Parse length
            packet_len: int = int.from_bytes(header, byteorder='big')
            
            # Validate length
            if packet_len < MIN_PACKET_SIZE or packet_len > MAX_PACKET_SIZE:
                raise InvalidPacketError(
                    f"Invalid packet length: {packet_len}"
                )
            
            # Receive payload
            payload: bytes = b""
            while len(payload) < packet_len:
                remaining: int = packet_len - len(payload)
                chunk = conn.recv(min(65536, remaining))
                if not chunk:
                    raise ConnectionError("Connection closed during payload receive")
                payload += chunk
            
            _debug_log(
                "Received packet: %d bytes",
                packet_len
            )
            
            return payload
            
        except socket.timeout:
            raise ConnectionTimeoutError("Receive timed out")
        except InvalidPacketError:
            raise
        except Exception as e:
            raise NetworkError(f"Failed to receive packet: {e}") from e
    
    def _send_response(
        self,
        conn: socket.socket,
        stats: ConnectionStats,
        status: str,
        data: Optional[str] = None,
        message: Optional[str] = None
    ) -> None:
        """
        Send a response packet to the connection.
        
        Args:
            conn: Connected socket
            stats: Connection statistics
            status: Response status (OK, DENIED, ERROR)
            data: Optional encrypted response data
            message: Optional error message
        """
        try:
            response: Dict[str, Any] = {"status": status}
            
            if data is not None:
                response["data"] = data
            
            if message is not None:
                response["msg"] = message
            
            payload: bytes = json.dumps(response).encode('utf-8')
            
            # Send length prefix
            length_prefix: bytes = len(payload).to_bytes(4, byteorder='big')
            conn.sendall(length_prefix + payload)
            
            stats.update_activity(bytes_out=len(payload))
            _debug_log("Sent response: status=%s, size=%d", status, len(payload))
            
        except socket.timeout:
            self._logger.warning(
                "[NETWORK] Response send timeout: %s",
                stats.connection_id
            )
        except Exception as e:
            self._logger.warning(
                "[NETWORK] Failed to send response to %s: %s",
                stats.connection_id,
                e
            )
    
    # =========================================================================
    # SERVER LIFECYCLE
    # =========================================================================
    
    def listen(self) -> None:
        """
        Main server loop - runs in a separate thread.
        
        Accepts incoming connections and spawns worker threads
        to handle each connection.
        """
        server: Optional[socket.socket] = None
        
        try:
            # Create server socket
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Set socket timeout for accept
            server.settimeout(1.0)  # Allow periodic checks for shutdown
            
            # Bind and listen
            server.bind((self.host, self.port))
            server.listen(5)
            
            self._server_socket = server
            
            self._logger.info(
                "[NETWORK] Node listening: %s:%d [ID: %s]",
                self.host,
                self.port,
                self.node_id
            )
            
            # Main accept loop
            while not self._shutdown_requested:
                try:
                    # Accept connection with timeout
                    conn, addr = server.accept()
                    
                    # Check connection limit
                    current_count = get_connection_count()
                    if current_count >= self._config.max_connections:
                        self._logger.warning(
                            "[NETWORK] Connection limit reached (%d), rejecting %s",
                            current_count,
                            addr
                        )
                        try:
                            conn.shutdown(socket.SHUT_RDWR)
                        except Exception:
                            pass
                        try:
                            conn.close()
                        except Exception:
                            pass
                        continue
                    
                    # Spawn worker thread
                    worker = threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr),
                        daemon=True,
                        name=f"{WORKER_THREAD_PREFIX}_{int(time.time() * 1000) % 10000}"
                    )
                    worker.start()
                    _debug_log("Spawned worker thread for %s", addr)
                    
                except socket.timeout:
                    # Timeout is expected, continue loop to check shutdown flag
                    continue
                except OSError as e:
                    if self._shutdown_requested:
                        break
                    self._logger.warning("[NETWORK] Accept error: %s", e)
                    continue
                    
        except Exception as e:
            self._logger.exception("[NETWORK] Server error: %s", e)
        finally:
            # Cleanup server socket
            if server:
                try:
                    server.close()
                except Exception:
                    pass
            self._server_socket = None
            self._logger.info("[NETWORK] Server stopped")
    
    def start_node(self) -> None:
        """
        Start the network node in a background thread.
        
        Thread-safe method that can be called multiple times safely.
        """
        with self._main_lock:
            if self._is_running:
                _debug_log("Node already running")
                return
            
            self._is_running = True
            self._shutdown_requested = False
            
            # Start server thread
            self._server_thread = threading.Thread(
                target=self.listen,
                daemon=True,
                name="NetworkServerThread"
            )
            self._server_thread.start()
            
            # Start cleanup thread for idle connections
            self._cleanup_thread = threading.Thread(
                target=self._cleanup_loop,
                daemon=True,
                name=f"{CLEANUP_THREAD_PREFIX}"
            )
            self._cleanup_thread.start()
            
            _logger.info(
                "[NETWORK] Node started: %s [threads=server+cleanup]",
                self.node_id
            )
    
    def stop(self, timeout: float = DEFAULT_SHUTDOWN_TIMEOUT) -> None:
        """
        Stop the network node gracefully.
        
        Args:
            timeout: Maximum seconds to wait for shutdown
        """
        self._logger.info("[NETWORK] Stopping node...")
        
        # Signal shutdown
        self._shutdown_requested = True
        
        # Close server socket to unblock accept
        with self._main_lock:
            if self._server_socket:
                try:
                    self._server_socket.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    self._server_socket.close()
                except Exception:
                    pass
                self._server_socket = None
        
        # Wait for server thread
        if self._server_thread and self._server_thread.is_alive():
            try:
                self._server_thread.join(timeout=timeout)
            except Exception:
                pass
        
        self._is_running = False
        _logger.info("[NETWORK] Node stopped")
    
    def _cleanup_loop(self) -> None:
        """
        Background loop to clean up idle connections.
        
        Periodically checks for connections that have been idle
        beyond the timeout threshold and closes them.
        """
        cleanup_interval: float = 10.0  # Check every 10 seconds
        
        while not self._shutdown_requested:
            try:
                self._cleanup_idle_connections()
            except Exception as e:
                _debug_log("Cleanup error: %s", e)
            
            # Sleep with early termination check
            for _ in range(int(cleanup_interval * 10)):
                if self._shutdown_requested:
                    break
                time.sleep(0.1)
    
    def _cleanup_idle_connections(self) -> None:
        """Clean up connections that have been idle too long."""
        with _connection_lock:
            idle_connections: List[str] = [
                conn_id for conn_id, stats in _active_connections.items()
                if stats.is_idle_too_long
            ]
        
        for conn_id in idle_connections:
            self._logger.info(
                "[NETWORK] Closing idle connection: %s",
                conn_id
            )
            # Note: actual socket cleanup happens in _handle_connection's finally block
            # This just unregisters from tracking
            _unregister_connection(conn_id)
    
    # =========================================================================
    # CLIENT METHODS
    # =========================================================================
    
    def send_remote_cmd(
        self,
        target_host: str,
        target_port: int,
        token: str,
        command: str,
        timeout: float = 30.0
    ) -> str:
        """
        Send a command to a remote node.
        
        Args:
            target_host: Target node hostname/IP
            target_port: Target node port
            token: Authentication token
            command: Command string to execute
            timeout: Operation timeout in seconds
        
        Returns:
            Response string from remote node
        
        Raises:
            NetworkError: If send fails
        """
        sock: Optional[socket.socket] = None
        
        try:
            # Validate inputs
            if not target_host or len(target_host) > 255:
                raise NetworkError("Invalid target host")
            
            if not (1 <= target_port <= 65535):
                raise NetworkError("Invalid port number")
            
            if len(token) > 1024:
                raise NetworkError("Token too long")
            
            if len(command) > 10000:
                raise NetworkError("Command too long")
            
            _debug_log(
                "Sending command to %s:%d (timeout=%.1f)",
                target_host,
                target_port,
                timeout
            )
            
            # Create connection
            sock = socket.create_connection(
                (target_host, target_port),
                timeout=min(timeout, 10.0)  # Connection timeout
            )
            sock.settimeout(timeout)  # Socket operations timeout
            
            # Wrap with SSL if configured
            if self._client_ssl_context is not None:
                try:
                    sock = self._client_ssl_context.wrap_socket(
                        sock,
                        server_hostname=target_host
                    )
                    _debug_log("Client SSL handshake completed")
                except ssl.SSLError as e:
                    self._logger.warning(
                        "[NETWORK] Client SSL error: %s",
                        e
                    )
            
            # Encrypt command
            cmd_bytes: bytes = command.encode('utf-8')
            encrypted: bytes = SEC_KERNEL.encrypt_bytes(cmd_bytes)
            encrypted_hex: str = encrypted.hex()
            
            # Build packet
            packet: Dict[str, Any] = {
                "token": token,
                "payload": encrypted_hex
            }
            packet_bytes: bytes = json.dumps(packet).encode('utf-8')
            
            # Send length prefix + packet
            length_prefix: bytes = len(packet_bytes).to_bytes(4, byteorder='big')
            sock.sendall(length_prefix + packet_bytes)
            
            _debug_log("Sent packet: %d bytes", len(packet_bytes))
            
            # Receive response header
            header: bytes = b""
            try:
                while len(header) < 4:
                    chunk = sock.recv(4 - len(header))
                    if not chunk:
                        return "Node Connection Failed: no response header"
                    header += chunk
            except socket.timeout:
                return "Node Connection Failed: receive timeout"
            
            # Parse response length
            resp_len: int = int.from_bytes(header, byteorder='big')
            
            if resp_len < 0 or resp_len > MAX_PACKET_SIZE:
                return f"Node Connection Failed: invalid response length {resp_len}"
            
            # Receive response
            response: bytearray = bytearray()
            while len(response) < resp_len:
                remaining: int = resp_len - len(response)
                chunk = sock.recv(min(65536, remaining))
                if not chunk:
                    return "Node Connection Failed: incomplete response"
                response.extend(chunk)
            
            # Parse JSON response
            resp_data: Dict[str, Any] = json.loads(bytes(response).decode('utf-8'))
            
            status: str = resp_data.get('status', 'UNKNOWN')
            
            if status == 'OK':
                # Decrypt response data
                try:
                    data_hex: str = resp_data.get('data', '')
                    if data_hex:
                        encrypted_resp: bytes = bytes.fromhex(data_hex)
                        decrypted_resp: bytes = SEC_KERNEL.decrypt_bytes(encrypted_resp)
                        return decrypted_resp.decode('utf-8')
                    return ""
                except Exception as e:
                    return f"Remote Error: decryption failed - {e}"
            
            # Error response
            msg: str = resp_data.get('msg', 'Unknown error')
            return f"Remote Error: {msg}"
            
        except socket.timeout:
            return "Node Connection Failed: operation timeout"
        except socket.gaierror as e:
            return f"Node Connection Failed: DNS resolution failed - {e}"
        except ConnectionRefusedError:
            return "Node Connection Failed: connection refused"
        except Exception as e:
            self._logger.exception("[NETWORK] Remote command failed")
            return f"Node Connection Failed: {e}"
        finally:
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    sock.close()
                except Exception:
                    pass
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get node status and statistics.
        
        Returns:
            Dictionary with node status information
        """
        return {
            "node_id": self.node_id,
            "host": self.host,
            "port": self.port,
            "is_running": self._is_running,
            "config": {
                "max_connections": self._config.max_connections,
                "connection_timeout": self._config.connection_timeout,
                "use_tls": self._config.use_tls,
            },
            "stats": get_network_stats(),
        }
    
    def __repr__(self) -> str:
        """String representation of the node."""
        status = "running" if self._is_running else "stopped"
        return f"DistributedNode({self.host}:{self.port}, {status})"


# =============================================================================
# GLOBAL NETWORK NODE
# =============================================================================

# Default network node instance
NETWORK_NODE: DistributedNode = DistributedNode()

# Alias for backward compatibility
NetworkNode = DistributedNode
