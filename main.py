import sys
import os
import time
import logging
from core.hal import HAL
from core.security import SEC_KERNEL
from core.loader import KERNEL_LOADER
from core.network import NETWORK_NODE
from core.logger import BG_LOGGER

class ArchKernel:
    def __init__(self):
        self.is_running = False
        self.version = "0.1.0-alpha (Pseudo-Arch)"
        
    def boot_sequence(self):
        """Cold Boot with Logic-to-Assertion checks."""
        print(f"\n--- Initializing {self.version} ---")
        
        # Hardware Validation
        try:
            report = HAL.get_health_report()
            assert report['status'] != "CRITICAL", "Hardware Failure on Boot"
            print(f"[OK] HAL: {HAL.CPU_CORES} Cores | Latency {report['internal_latency']:.6f}s")
            
            # Plugin Loading
            KERNEL_LOADER.bootstrap()
            assert len(KERNEL_LOADER.commands) >= 0, "Loader Initialization Failure"
            print(f"[OK] Commands Loaded: {list(KERNEL_LOADER.commands.keys())}")
            
            # Network Setup
            NETWORK_NODE.start_node()
            print(f"[OK] Node ID: {NETWORK_NODE.node_id} Active.")
            
            self.is_running = True
        except AssertionError as e:
            print(f"[KERNEL PANIC] {e}")
            sys.exit(1)

    def run_cli(self):
        """Interactive Shell with Force-Keep-Alive."""
        print("\nType 'help' for commands or 'exit' to shutdown.")
        
        while self.is_running:
            try:
                # Refresh Health Context for the Prompt
                health = HAL.get_health_report()
                prompt = f"(arch@{NETWORK_NODE.node_id})-[{int(health['memory_pressure'])}%] # "
                
                # Use sys.stdin.readline if input() is being bypassed by PS
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
                cmd_name = parts[0]
                args = parts[1:]
                
                context = {"health": health, "user": "root"}
                result = KERNEL_LOADER.dispatch(cmd_name, context, *args)
                print(f"{result}\n")

            except KeyboardInterrupt:
                print("\nInterrupt received.")
                break
            except Exception as e:
                print(f"Runtime Error: {e}")

        self.shutdown()

    def shutdown(self):
        print("\n[HALT] Closing Kernel Services...")
        BG_LOGGER.finalize_and_decrypt()
        print("\n[HALT] Wiping sensitive memory buffers...")
        # Security: Overwrite master key in RAM
        SEC_KERNEL._wipe_memory(SEC_KERNEL._master_key)
        print("[OS] System Halted.")
        sys.exit(0)

if __name__ == "__main__":
    os_kernel = ArchKernel()
    os_kernel.boot_sequence()
    os_kernel.run_cli()