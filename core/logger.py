import threading
import time
import os
from datetime import datetime
from core.hal import HAL
from core.security import SEC_KERNEL

class SecureLogger:
    def __init__(self, filename="sys_kernel.log"):
        self.filename = filename
        self.is_active = True
        self.thread = threading.Thread(target=self._log_loop, daemon=True)
        self.thread.start()

    def _log_loop(self):
        while self.is_active:
            try:
                report = HAL.get_health_report()
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                raw_entry = f"{timestamp} [ INFO ] RAM: {report['memory_pressure']}% | Status: {report['status']}"
                
                # Encrypt and write to disk as hex
                encrypted_hex = SEC_KERNEL.encrypt_field(raw_entry).hex()
                with open(self.filename, "a") as f:
                    f.write(encrypted_hex + "\n")

                time.sleep(5)
            except:
                pass

    def finalize_and_decrypt(self):
        self.is_active = False
        if not os.path.exists(self.filename): return

        try:
            with open(self.filename, "r") as f:
                lines = [line.strip() for line in f if line.strip()]
            
            decrypted_lines = []
            for line in lines:
                try:
                    blob = bytes.fromhex(line)
                    decrypted_lines.append(SEC_KERNEL.decrypt_field(blob))
                except: continue

            with open(self.filename, "w") as f:
                f.write("--- DECRYPTED SESSION LOG ---\n")
                f.write("\n".join(decrypted_lines))
            print(f"[SUCCESS] Logs decrypted: {self.filename}")
        except Exception as e:
            print(f"[ERROR] Log Decryption Failed: {e}")

# Create the global instance here
SYS_LOGGER = SecureLogger()