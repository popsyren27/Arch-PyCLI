import logging
import sys
import os

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