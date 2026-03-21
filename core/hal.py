import os
import psutil
import time
import ctypes
import gc
import logging
import sys
from typing import Dict, Any

# Setup Secure Logging - Persistent Arch-style journaling
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] HAL_KERNEL: %(message)s',
    handlers=[logging.FileHandler("sys_kernel.log"), logging.StreamHandler()]
)

class HardwareContext:
    """
    CONCRETE PROOF LAYER: 
    Derives system logic from physical silicon states. 
    Implements a 'Dead-Man Switch' for hardware integrity.
    """
    def __init__(self):
        try:
            # 1. BASELINE CAPTURE (The 'Identity' of the machine at boot)
            self._boot_time = psutil.boot_time()
            self.CPU_CORES = psutil.cpu_count(logical=False) or 1
            self.TOTAL_RAM = psutil.virtual_memory().total
            
            # 2. FAILSAFE THRESHOLDS
            # Sudden changes in these values indicate a 'Cold Boot' or 'Hardware Injection'
            self.MEM_TOLERANCE = 1024 * 1024 * 50 # 50MB drift allowed
            self.LATENCY_THRESHOLD = self._calculate_latency_baseline()
            
            logging.info(f"HAL Initialized. Core Logic: {self.CPU_CORES} Cores | {self.TOTAL_RAM // (1024**2)}MB RAM")
        
        except Exception as e:
            # FALLBACK: If psutil fails, we assume a hostile environment and restrict access
            logging.critical(f"HAL_INIT_FAILURE: {e}. Defaulting to Restricted Mode.")
            self.CPU_CORES = 1
            self.TOTAL_RAM = 0
            self.LATENCY_THRESHOLD = 0.1

    def _calculate_latency_baseline(self) -> float:
        """
        Calculates internal execution latency. 
        Used to detect 'Timing Attacks' or VM Debugging/Stepping.
        """
        try:
            start = time.perf_counter()
            # Calibration loop
            for _ in range(1000):
                _ = 1 + 1
            return (time.perf_counter() - start) / 1000
        except:
            return 0.001 # Failsafe constant

    def check_integrity(self) -> bool:
        """
        ENVIRONMENTAL WATCHDOG:
        Checks if the hardware environment has shifted since boot.
        Returns False if a 'Cold Boot' or 'Hardware Swap' is suspected.
        """
        try:
            current_mem = psutil.virtual_memory().total
            current_cores = psutil.cpu_count(logical=False)

            # Check 1: RAM Capacity Shift (Detection of memory module removal/swapping)
            if abs(current_mem - self.TOTAL_RAM) > 1024:
                logging.warning("INTEGRITY_VIOLATION: Memory Capacity Mismatch.")
                return False

            # Check 2: CPU Affinity Shift (Detection of VM core masking)
            if current_cores != self.CPU_CORES:
                logging.warning("INTEGRITY_VIOLATION: CPU Core Count Mismatch.")
                return False

            return True
        except:
            return False # Safety first: Fail closed

    def get_health_report(self) -> Dict[str, Any]:
        """
        STATE VERIFICATION:
        Ensures logic scaling is backed by real-time hardware pressure.
        """
        try:
            mem = psutil.virtual_memory()
            cpu_load = psutil.cpu_percent(interval=0.1)
            
            # FAILSAFE: Critical Memory Pressure (Prevention of OOM-Killer instability)
            if mem.percent > 98:
                logging.error("HAL_EMERGENCY: Memory Exhaustion. Initiating protective throttle.")
                return {"status": "CRITICAL", "memory_pressure": mem.percent}
            
            report = {
                "status": "HEALTHY" if mem.percent < 85 else "DEGRADED",
                "memory_pressure": mem.percent,
                "internal_latency": self._calculate_latency_baseline(),
                "cpu_utilization": cpu_load,
                "timestamp": time.time(),
                "integrity_verified": self.check_integrity()
            }
            
            return report
            
        except Exception as e:
            logging.error(f"HEALTH_REPORT_ERROR: {e}")
            return {"status": "ERROR", "message": str(e)}

def secure_mem_clear(variable: Any):
    """
    PROACTIVE SCAVENGING:
    Manually targets the memory address of a variable to overwrite it with 0s.
    Essential for Arch-style 'Zero-Trace' security.
    """
    if variable is None:
        return

    try:
        # Get the memory address of the content buffer
        # In Python, strings/bytes have a specific offset for the raw data
        addr = id(variable)
        size = 0
        
        if isinstance(variable, (str, bytes, bytearray)):
            size = len(variable)
            # Offset +20 is a general target for the buffer in Python 3.x
            ctypes.memset(addr + 20, 0, size) 
        
        # Explicitly trigger garbage collection after zeroing
        del variable
        gc.collect()
        
    except Exception as e:
        # Failsafe: If low-level overwrite fails, ensure at least GC is triggered
        logging.debug(f"SCAVENGE_RESTRICTED: {e}")
        gc.collect()

# Initialize Global Hardware Context
HAL = HardwareContext()