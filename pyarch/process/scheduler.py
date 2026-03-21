import asyncio
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from typing import Callable, Any, Optional
import logging

class ProcessManager:
    """
    Abstracts OS-level execution, utilizing the optimal concurrency model with fallbacks.
    
    Design Decision:
    - CPU-bound tasks are sent to a ProcessPool to bypass the Python GIL.
    - IO-bound tasks use a ThreadPool or the Async loop.
    - Implements 'Graceful Degradation': if multiprocessing is restricted by the OS 
      (e.g., in certain containerized or low-privilege environments), it 
      automatically falls back to threading.
    """
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
        # Attempt to initialize CPU-bound Process Pool
        try:
            # We use the 'spawn' or 'fork' method provided by the OS
            self.process_pool = ProcessPoolExecutor(max_workers=multiprocessing.cpu_count())
            self.logger.info(f"ProcessPoolExecutor initialized with {multiprocessing.cpu_count()} workers.")
        except (OSError, ImportError, RuntimeError) as e:
            # Fallback: If OS limits processes or multiprocessing is unavailable
            self.logger.error(f"Failed to create ProcessPool: {e}. Falling back to ThreadPoolExecutor.")
            self.process_pool = ThreadPoolExecutor(max_workers=4)

        # Initialize IO-bound Thread Pool for lightweight tasks
        self.thread_pool = ThreadPoolExecutor(max_workers=10)

    async def run_io_task(self, func: Callable, *args) -> Any:
        """
        Runs IO-bound tasks in a thread pool to avoid blocking the main async event loop.
        """
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(self.thread_pool, func, *args)
        except Exception as e:
            self.logger.error(f"IO Task execution failed: {e}. Attempting synchronous fallback.")
            # Absolute Fallback: run synchronously if thread pool is exhausted or loop fails
            return func(*args)

    async def run_cpu_task(self, func: Callable, *args) -> Any:
        """
        Runs CPU-bound tasks in the process pool.
        """
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(self.process_pool, func, *args)
        except Exception as e:
            self.logger.error(f"CPU Task execution failed in ProcessPool: {e}. Falling back to ThreadPool.")
            # Fallback: if process pool fails, try thread pool (CPU performance will drop, but OS stays alive)
            try:
                return await self.run_io_task(func, *args)
            except Exception as inner_e:
                self.logger.critical(f"All concurrency mechanisms failed for CPU task: {inner_e}. Running synchronously.")
                return func(*args) 

    def shutdown(self):
        """
        Graceful shutdown of execution pools.
        """
        self.logger.info("Shutting down process and thread pools...")
        self.process_pool.shutdown(wait=False)
        self.thread_pool.shutdown(wait=False)