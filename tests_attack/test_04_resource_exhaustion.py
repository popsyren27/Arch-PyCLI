"""
Attack Test 04: Resource Exhaustion Test

This test attempts to exhaust system resources like
memory, CPU, and file descriptors to test resilience.

Run with: python tests_attack/test_04_resource_exhaustion.py
"""

import socket
import time
import sys
import os
import threading
import gc

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_resource_exhaustion():
    """Test resource exhaustion resilience."""
    print("=" * 60)
    print("ATTACK TEST 04: Resource Exhaustion")
    print("=" * 60)
    
    target_host = "127.0.0.1"
    target_port = 8888
    
    print(f"\n[1] Target: {target_host}:{target_port}")
    
    print("\n[2] Testing memory exhaustion...")
    
    # Try to allocate lots of memory in threads
    memory_test_results = {"threads": 0, "allocated": 0, "errors": 0}
    
    def allocate_memory():
        try:
            # Allocate 10MB chunks
            chunk = b"A" * (10 * 1024 * 1024)
            memory_test_results["allocated"] += 10
            time.sleep(0.1)
        except MemoryError:
            memory_test_results["errors"] += 1
        except Exception:
            memory_test_results["errors"] += 1
    
    threads = []
    for i in range(5):
        t = threading.Thread(target=allocate_memory)
        t.start()
        threads.append(t)
        memory_test_results["threads"] += 1
    
    for t in threads:
        t.join()
    
    print(f"    - Threads created: {memory_test_results['threads']}")
    print(f"    - Memory allocated (MB): {memory_test_results['allocated']}")
    print(f"    - Errors: {memory_test_results['errors']}")
    
    # Force garbage collection
    gc.collect()
    
    print("\n[3] Testing file descriptor exhaustion...")
    
    fd_test_results = {"sockets": 0, "errors": 0}
    sockets = []
    
    try:
        for i in range(100):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                try:
                    sock.connect((target_host, target_port))
                except:
                    pass
                sockets.append(sock)
                fd_test_results["sockets"] += 1
            except OSError as e:
                # Too many open files
                fd_test_results["errors"] += 1
                break
            except Exception:
                fd_test_results["errors"] += 1
    finally:
        # Clean up
        for sock in sockets:
            try:
                sock.close()
            except:
                pass
    
    print(f"    - Sockets opened: {fd_test_results['sockets']}")
    print(f"    - Errors: {fd_test_results['errors']}")
    
    print("\n[4] Testing rapid connection/disconnection...")
    
    rapid_test_results = {"connections": 0, "errors": 0}
    
    for i in range(50):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            sock.connect((target_host, target_port))
            sock.close()
            rapid_test_results["connections"] += 1
        except Exception:
            rapid_test_results["errors"] += 1
        
        # Very small delay
        time.sleep(0.01)
    
    print(f"    - Rapid connections: {rapid_test_results['connections']}")
    print(f"    - Errors: {rapid_test_results['errors']}")
    
    print("\n[5] Testing keep-alive exhaustion...")
    
    keepalive_results = {"connections": 0, "errors": 0}
    keepalive_sockets = []
    
    try:
        for i in range(20):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                sock.settimeout(1)
                sock.connect((target_host, target_port))
                keepalive_sockets.append(sock)
                keepalive_results["connections"] += 1
            except Exception:
                keepalive_results["errors"] += 1
    finally:
        for sock in keepalive_sockets:
            try:
                sock.close()
            except:
                pass
    
    print(f"    - Keep-alive connections: {keepalive_results['connections']}")
    print(f"    - Errors: {keepalive_results['errors']}")
    
    print("\n[6] Cleanup and verification...")
    gc.collect()
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_host, target_port))
        print(f"    ✓ CLI still reachable after resource tests")
        sock.close()
    except Exception as e:
        print(f"    ! CLI unreachable: {type(e).__name__}")
    
    print("\n" + "=" * 60)
    print("RESULT: Resource exhaustion test complete")
    print("=" * 60)
    return True


if __name__ == "__main__":
    test_resource_exhaustion()