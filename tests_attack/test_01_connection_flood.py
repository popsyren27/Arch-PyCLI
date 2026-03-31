"""
Attack Test 01: Connection Flood Test

This test attempts to flood the CLI with connections to test
DoS resilience and connection handling.

Run with: python tests_attack/test_01_connection_flood.py
"""

import socket
import time
import sys
import os

# For ConnectionRefused
ConnectionRefused = socket.error

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_connection_flood():
    """Test connection flood resilience."""
    print("=" * 60)
    print("ATTACK TEST 01: Connection Flood")
    print("=" * 60)
    
    target_host = "127.0.0.1"
    target_port = 8888
    
    print(f"\n[1] Target: {target_host}:{target_port}")
    
    print("\n[2] Attempting rapid connections...")
    
    connections = []
    max_connections = 50
    successful = 0
    failed = 0
    
    try:
        for i in range(max_connections):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_host, target_port))
                
                if result == 0:
                    successful += 1
                    connections.append(sock)
                else:
                    failed += 1
                    sock.close()
                    
            except Exception as e:
                failed += 1
                
            # Small delay to not instantly overwhelm
            if i % 10 == 0:
                time.sleep(0.1)
                
        print(f"    - Successful connections: {successful}")
        print(f"    - Failed connections: {failed}")
        print(f"    - Total attempted: {max_connections}")
        
    except Exception as e:
        print(f"    ❌ Connection test error: {e}")
    
    print("\n[3] Closing connections...")
    for sock in connections:
        try:
            sock.close()
        except:
            pass
    
    print("\n[4] Testing connection timeout handling...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect((target_host, target_port))
        print(f"    ✓ Connection to CLI successful")
        sock.close()
    except socket.timeout:
        print(f"    ! Connection timeout (CLI may be idle)")
    except ConnectionRefused:
        print(f"    ! Connection refused - CLI may not be running")
    except Exception as e:
        print(f"    ! Connection error: {type(e).__name__}")
    
    print("\n" + "=" * 60)
    print("RESULT: Connection flood test complete")
    print("=" * 60)
    return True


if __name__ == "__main__":
    test_connection_flood()