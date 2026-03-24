import logging
import sys
import os
from typing import Optional

class PyArchConfig:
    """
    Central configuration for a Py-Arch Node.
    
    Design Decision: 
    - Uses a simple attribute-based config for speed.
    - Implements a fallback for the plugin directory to ensure the OS 
      can still attempt to load functional modules even if the primary 
      working directory is write-protected.
    """
    def __init__(self, node_id: str, host: str = "127.0.0.1", port: int = 8888):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.plugin_dir = "plugins"
        self.fallback_local_only = False
        # Network / TLS configuration
        # Set `network_use_tls` to True and provide `network_certfile`/`network_keyfile` to enable TLS.
        self.network_use_tls = False
        self.network_certfile: Optional[str] = None
        self.network_keyfile: Optional[str] = None
        self.network_cafile: Optional[str] = None
        self.network_require_client_cert = False
        self.network_verify_server = True

        # Apply environment overrides if present (convenience for containers/CI)
        try:
            self._apply_env_overrides()
        except Exception:
            # Don't fail construction due to malformed env; fall back to defaults
            pass

    def _parse_bool(self, v: Optional[str]) -> bool:
        if v is None:
            return False
        return str(v).lower() in ("1", "true", "yes", "on")

    def _apply_env_overrides(self) -> None:
        """Read known environment variables and override defaults.

        Supported variables:
          PYARCH_HOST, PYARCH_PORT, PYARCH_PLUGIN_DIR
          PYARCH_NETWORK_USE_TLS, PYARCH_NETWORK_CERTFILE, PYARCH_NETWORK_KEYFILE
          PYARCH_NETWORK_CAFILE, PYARCH_NETWORK_REQUIRE_CLIENT_CERT
          PYARCH_NETWORK_VERIFY_SERVER
        """
        env = os.environ
        host = env.get("PYARCH_HOST")
        if host:
            self.host = host
        port = env.get("PYARCH_PORT")
        if port:
            try:
                self.port = int(port)
            except Exception:
                pass
        plugin_dir = env.get("PYARCH_PLUGIN_DIR")
        if plugin_dir:
            self.plugin_dir = plugin_dir
        # TLS related
        self.network_use_tls = self._parse_bool(env.get("PYARCH_NETWORK_USE_TLS"))
        self.network_certfile = env.get("PYARCH_NETWORK_CERTFILE") or self.network_certfile
        self.network_keyfile = env.get("PYARCH_NETWORK_KEYFILE") or self.network_keyfile
        self.network_cafile = env.get("PYARCH_NETWORK_CAFILE") or self.network_cafile
        self.network_require_client_cert = self._parse_bool(env.get("PYARCH_NETWORK_REQUIRE_CLIENT_CERT"))
        # By default verify server unless explicitly disabled
        v = env.get("PYARCH_NETWORK_VERIFY_SERVER")
        if v is not None:
            self.network_verify_server = self._parse_bool(v)

    @classmethod
    def from_env(cls, node_id: Optional[str] = None) -> "PyArchConfig":
        nid = node_id or f"node_{int(time.time())}"
        return cls(nid)
        
        # Ensure plugin directory exists
        try:
            if not os.path.exists(self.plugin_dir):
                os.makedirs(self.plugin_dir, exist_ok=True)
        except OSError as e:
            # Fallback: run without custom plugin directory if disk is unwritable
            # using /tmp as a common volatile storage area in Unix-like systems.
            self.plugin_dir = "/tmp/pyarch_plugins"
            try:
                os.makedirs(self.plugin_dir, exist_ok=True)
            except OSError:
                # Absolute fallback: if /tmp is also gone, plugins must be loaded from memory/python path
                self.plugin_dir = "."

def setup_logger(node_id: str) -> logging.Logger:
    """
    Sets up a fail-safe, centralized logger for the node.
    
    Failure Handling:
    - If FileHandler fails (e.g., Permission Denied), it degrades to 
      StreamHandler (stdout) only. This prevents the OS from crashing 
      before it even starts due to logging IO errors.
    """
    logger = logging.getLogger(f"PyArch-{node_id}")
    logger.setLevel(logging.DEBUG)
    
    # Standard output handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] - %(message)s')
    ch.setFormatter(formatter)
    
    if not logger.handlers:
        logger.addHandler(ch)
        
    try:
        # Try to add a file handler for persistence
        log_file = f"pyarch_{node_id}.log"
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except (IOError, PermissionError):
        # Fallback: If filesystem is read-only, log heavily to stdout and warn
        logger.warning("Filesystem read-only or inaccessible. Falling back to stdout-only logging.")
        
    return logger