import sys
import os
import time
import logging
import signal
import argparse
from core.hal import HAL
from core.security import SEC_KERNEL
from core.loader import KERNEL_LOADER
from core.network import DistributedNode
import core.network as core_network
from core.config import PyArchConfig, setup_logger
import inspect

class ArchKernel:
    def __init__(self):
        self.is_running = False
        self.version = "0.1.0-alpha (Pseudo-Arch)"
        # Load default configuration for the node (env-aware)
        self.config = PyArchConfig.from_env(node_id=f"kernel_{int(time.time())}")
        self.logger = setup_logger(self.config.node_id)
        self._shutdown_requested = False
        
    def boot_sequence(self):
        """Cold Boot with Logic-to-Assertion checks."""
        self.logger.info("Initializing %s", self.version)
        
        # Hardware Validation
        try:
            report = HAL.get_health_report()
            if report.get('status') == "CRITICAL":
                raise RuntimeError("Hardware Failure on Boot")
            self.logger.info("HAL: %s cores | latency %.6fs", getattr(HAL, 'CPU_CORES', 0), report.get('internal_latency', 0.0))
            
            # Plugin Loading
            KERNEL_LOADER.bootstrap()
            if not isinstance(KERNEL_LOADER.commands, dict):
                raise RuntimeError("Loader Initialization Failure")
            self.logger.info("Commands Loaded: %s", list(KERNEL_LOADER.commands.keys()))
            
            # Network Setup
            # Initialize network node according to config (may enable TLS)
            try:
                node_kwargs = {
                    'host': self.config.host,
                    'port': self.config.port,
                    'use_tls': self.config.network_use_tls,
                    'certfile': self.config.network_certfile,
                    'keyfile': self.config.network_keyfile,
                    'cafile': self.config.network_cafile,
                    'require_client_cert': self.config.network_require_client_cert,
                    'verify_server': self.config.network_verify_server,
                }
                # Create and replace module-global NETWORK_NODE so plugins referring to it continue to work
                core_network.NETWORK_NODE = DistributedNode(**node_kwargs)
                core_network.NETWORK_NODE.start_node()
                self.logger.info("Node ID: %s Active", core_network.NETWORK_NODE.node_id)
            except Exception as e:
                self.logger.exception("Failed to start network node")
                raise
            
            self.is_running = True
        except Exception as e:
            self.logger.exception("Boot sequence failed: %s", e)
            sys.exit(1)

    def run_cli(self):
        """Interactive Shell with Force-Keep-Alive."""
        self.logger.info("Entering interactive CLI; type 'help' or 'exit'")
        
        while self.is_running:
            try:
                # Refresh Health Context for the Prompt
                health = HAL.get_health_report()
                node = getattr(core_network, 'NETWORK_NODE', None)
                node_id = getattr(node, 'node_id', 'unknown')
                mem = int(health.get('memory_pressure', 0)) if isinstance(health, dict) else 0
                prompt = f"(arch@{node_id})-[{mem}%] # "
                
                # Use sys.stdin.readline for robust input
                sys.stdout.write(prompt)
                sys.stdout.flush()
                line = sys.stdin.readline()
                
                if not line: # Handle EOF
                    break
                    
                cmd_input = line.strip()
                if not cmd_input:
                    continue
                
                if cmd_input.lower() in ['exit', 'quit', 'shutdown']:
                    self.is_running = False
                    break

                # Execution Logic
                parts = cmd_input.split()
                if not parts:
                    continue
                cmd_name = parts[0]
                args = parts[1:]
                
                # Validate command name (alphanumeric + underscore only)
                if not cmd_name.replace('_', '').isalnum():
                    print(f"Invalid command name: {cmd_name}")
                    continue
                
                context = {"health": health, "user": "root"}
                result = KERNEL_LOADER.dispatch(cmd_name, context, *args)
                print(f"{result}\n")

            except KeyboardInterrupt:
                self.logger.info("Interrupt received; shutting down")
                break
            except Exception as e:
                self.logger.exception("Runtime Error during CLI")
                print(f"Runtime Error: {e}")

        self.shutdown()

    def shutdown(self):
        self.logger.info("Shutdown requested; wiping sensitive buffers")
        # Attempt graceful network shutdown
        try:
            if getattr(core_network, 'NETWORK_NODE', None):
                try:
                    core_network.NETWORK_NODE.stop()
                except Exception:
                    self.logger.exception("Failed to stop network node cleanly")
        except Exception:
            pass

        # Security: Overwrite master key in RAM if available
        try:
            SEC_KERNEL._wipe_memory(getattr(SEC_KERNEL, '_master_key', b''))
        except Exception:
            self.logger.exception("Failed to wipe master key from memory")

        self.logger.info("System halted")
        sys.exit(0)

def _parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--host", help="listen host")
    p.add_argument("--port", type=int, help="listen port")
    p.add_argument("--tls", action='store_true', help="enable TLS for network")
    p.add_argument("--certfile", help="TLS cert file path")
    p.add_argument("--keyfile", help="TLS key file path")
    p.add_argument("--cafile", help="TLS CA file path")
    p.add_argument("--no-verify", action='store_true', help="do not verify peer certificates")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    os_kernel = ArchKernel()

    # Apply CLI overrides on top of env/config
    try:
        if args.host:
            os_kernel.config.host = args.host
        if args.port:
            os_kernel.config.port = int(args.port)
        if args.tls:
            os_kernel.config.network_use_tls = True
        if args.certfile:
            os_kernel.config.network_certfile = args.certfile
        if args.keyfile:
            os_kernel.config.network_keyfile = args.keyfile
        if args.cafile:
            os_kernel.config.network_cafile = args.cafile
        if args.no_verify:
            os_kernel.config.network_verify_server = False
    except Exception:
        os_kernel.logger.exception("Failed to apply CLI overrides")

    # Setup signal handlers for graceful shutdown
    def _handle_signal(signum, frame):
        os_kernel.logger.info("Signal %s received, shutting down", signum)
        os_kernel.shutdown()

    try:
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)
    except Exception:
        # Not all platforms support signals the same way; continue
        pass

    os_kernel.boot_sequence()
    os_kernel.run_cli()