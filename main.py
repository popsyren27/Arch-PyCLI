import asyncio
import sys
import os
import logging
import time
from core.security import SEC_KERNEL
from core.hal import HAL
from core.loader import KERNEL_LOADER
from core.network import NETWORK_NODE

# Configure Kernel Logging - Arch-style system journaling
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [KERNEL] %(message)s',
    handlers=[logging.FileHandler("sys_kernel.log"), logging.StreamHandler()]
)

class PyArchOS:
    """
    KERNEL ORCHESTRATOR:
    Manages the lifecycle of background services and the User CLI.
    """
    def __init__(self):
        self.is_running = True
        self._loop = None

    async def hardware_watchdog(self):
        """
        BACKGROUND SERVICE:
        Continuously polls HAL to ensure hardware integrity.
        If a 'Cold Boot' or RAM swap is detected, it triggers a wipe.
        """
        logging.info("Service 'watchdog' started (Integrity Mode).")
        while self.is_running:
            try:
                # Check 1: Machine Identity Verification
                if not HAL.check_integrity():
                    logging.critical("HARDWARE_TAMPER_DETECTED: Environment compromised.")
                    SEC_KERNEL.panic_self_destruct("ENV_INTEGRITY_FAILURE")
                    self.is_running = False
                    break
                
                # Check 2: Thermal/Pressure Failsafe
                stats = HAL.get_health_report()
                if stats.get("status") == "CRITICAL":
                    logging.error("SYSTEM_OVERLOAD: Throttling kernel services.")
                
                await asyncio.sleep(2) # Poll every 2 seconds to save CPU
            except Exception as e:
                logging.debug(f"Watchdog stutter: {e}")

    async def shell_prompt(self):
        """
        FOREGROUND SERVICE:
        The interactive CLI. Uses an executor to prevent input() from 
        blocking background network and watchdog tasks.
        """
        print("\n" + "="*40)
        print("  PY-ARCH KERNEL v2.0 (ASYNC/HARDENED)")
        print("  Status: SECURE | Integrity: VERIFIED")
        print("="*40)
        print("Type 'help' for plugins or 'exit' to halt.\n")
        
        while self.is_running:
            try:
                # 'run_in_executor' keeps the event loop spinning while waiting for user input
                user_input = await self._loop.run_in_executor(None, input, "arch# ")
                
                if not user_input.strip():
                    continue
                
                parts = user_input.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd == "exit":
                    self.is_running = False
                    break
                
                # Plugin Dispatch: Injecting real-time Hardware Context
                context = {
                    "health": HAL.get_health_report(), 
                    "origin": "local_terminal",
                    "timestamp": time.time() if 'time' in globals() else None
                }
                
                result = KERNEL_LOADER.dispatch(cmd, context, *args)
                print(f"[RESULT]: {result}")

            except KeyboardInterrupt:
                self.is_running = False
            except Exception as e:
                print(f"[ERROR]: {e}")

    async def boot(self):
        """
        INIT SYSTEM:
        Launches all kernel services concurrently.
        """
        self._loop = asyncio.get_running_loop()

        # 1. AUTHENTICATION GATE
        # Must pass before any background tasks start
        password = input("Enter Master Key to unlock Kernel: ")
        if not SEC_KERNEL.bootstrap_kernel(password):
            print("BOOT_FAILURE: Authentication Rejected.")
            return

        # 2. CONCURRENT SERVICE LAUNCH
        # background_tasks allow the node and watchdog to survive errors in the CLI
        try:
            logging.info("Initializing system services...")
            await asyncio.gather(
                self.hardware_watchdog(),
                NETWORK_NODE.start_node(),
                self.shell_prompt()
            )
        except Exception as e:
            logging.error(f"KERNEL_PANIC: {e}")
        finally:
            self.shutdown()

    def shutdown(self):
        """Cleanly wipes memory and halts the CPU process."""
        print("\n[HALT] Wiping sensitive RAM buffers...")
        
        # Zero out master keys and salts in physical RAM
        SEC_KERNEL.panic_self_destruct("USER_INITIATED_SHUTDOWN")
        
        print("[HALT] Security context cleared. System Offline.")
        sys.exit(0)

if __name__ == "__main__":
    os_kernel = PyArchOS()
    try:
        # Start the Asynchronous Event Loop
        asyncio.run(os_kernel.boot())
    except KeyboardInterrupt:
        os_kernel.shutdown()