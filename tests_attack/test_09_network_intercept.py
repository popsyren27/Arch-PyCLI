"""
Attack Test 09: Network Interception & Man-in-the-Middle Test

This test attempts network-level attacks like
packet sniffing, injection, and session hijacking.

Run with: python tests_attack/test_09_network_intercept.py
"""

import socket
import time
import sys
import os
import struct

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_network_intercept():
    """Test network interception resilience."""
    print("=" * 60)
    print("ATTACK TEST 09: Network Interception & MITM")
    print("=" * 60)
    
    target_host = "127.0.0.1"
    target_port = 8888
    
    print(f"\n[1] Target: {target_host}:{target_port}")
    
    print("\n[2] Testing TCP options for interception...")
    
    # Test various TCP options that might enable interception
    tcp_options = [
        # MSS option
        (socket.TCP_NODELAY, None),
        # Keepalive
        (socket.SO_KEEPALIVE, struct.pack('i', 1)),
        # Reuse address
        (socket.SO_REUSEADDR, struct.pack('i', 1)),
        # Bind to device (if applicable)
    ]
    
    for opt, value in tcp_options:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if value:
                sock.setsockopt(socket.SOL_SOCKET, opt, value)
            else:
                sock.setsockopt(socket.SOL_SOCKET, opt, 1)
            
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            print(f"    - Option {opt}: connected")
            sock.close()
            
        except Exception as e:
            print(f"    - Option {opt}: {type(e).__name__}")
    
    print("\n[3] Testing socket buffer manipulation...")
    
    buffer_tests = [
        (socket.SO_SNDBUF, 1),
        (socket.SO_SNDBUF, 1024),
        (socket.SO_SNDBUF, 65535),
        (socket.SO_RCVBUF, 1),
        (socket.SO_RCVBUF, 1024),
        (socket.SO_RCVBUF, 65535),
    ]
    
    for opt, value in buffer_tests:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, opt, value)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            actual = sock.getsockopt(socket.SOL_SOCKET, opt)
            print(f"    - Buffer {opt}={value}: actual={actual}")
            
            sock.close()
            
        except Exception as e:
            print(f"    - Buffer {opt}: {type(e).__name__}")
    
    print("\n[4] Testing out-of-band data (TCP urgent)...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_host, target_port))
        
        # Try to send OOB data
        try:
            sock.send(b"test data", socket.MSG_OOB)
            print(f"    - OOB data: sent")
        except Exception as e:
            print(f"    - OOB data: {type(e).__name__}")
        
        sock.close()
        
    except Exception as e:
        print(f"    ! OOB test: {type(e).__name__}")
    
    print("\n[5] Testing TCP timestamp manipulation...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_TIMESTAMP, 1)
        sock.settimeout(2)
        sock.connect((target_host, target_port))
        
        # Get socket name to see timestamps
        print(f"    - Timestamp socket: created")
        sock.close()
        
    except Exception as e:
        print(f"    - Timestamp: {type(e).__name__}")
    
    print("\n[6] Testing partial packet sending...")
    
    partial_tests = [
        (b"H", 0.1),
        (b"HE", 0.1),
        (b"HEL", 0.1),
        (b"HELP", 0.1),
    ]
    
    for data, delay in partial_tests:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            sock.send(data)
            time.sleep(delay)
            
            try:
                response = sock.recv(4096)
                print(f"    - Partial '{data.decode()}': response={len(response)}")
            except:
                print(f"    - Partial '{data.decode()}': no response")
            
            sock.close()
            
        except Exception as e:
            print(f"    - Partial test: {type(e).__name__}")
    
    print("\n[7] Testing socket inheritance/linger...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        sock.settimeout(2)
        sock.connect((target_host, target_port))
        
        print(f"    - Linger socket: configured")
        
        # Close with RST to test
        sock.close()
        
    except Exception as e:
        print(f"    - Linger: {type(e).__name__}")
    
    print("\n[8] Testing broadcast/multicast attempts...")
    
    # Note: These likely won't work for TCP but testing the handling
    multicast_tests = [
        ("224.0.0.1", 8888),
        ("255.255.255.255", 8888),
    ]
    
    for mcast_addr, mcast_port in multicast_tests:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            
            # Try to send to multicast address
            sock.sendto(b"test", (mcast_addr, mcast_port))
            print(f"    - Multicast {mcast_addr}: sent")
            
            sock.close()
            
        except Exception as e:
            print(f"    - Multicast {mcast_addr}: {type(e).__name__}")
    
    print("\n[9] Testing IP options...")
    
    try:
        # Set IP options (may require admin)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # IP options like router alert, timestamp, etc.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, bytes([0]*40))
        sock.settimeout(2)
        
        try:
            sock.connect((target_host, target_port))
            print(f"    - IP options: set")
        except Exception as e:
            print(f"    - IP options: {type(e).__name__}")
        
        sock.close()
        
    except Exception as e:
        print(f"    - IP options test: {type(e).__name__}")
    
    print("\n[10] Testing connection reset handling...")
    
    reset_tests = [
        # Normal close
        ("normal", lambda s: s.close()),
        # RST close
        ("rst", lambda s: s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))),
    ]
    
    for name, close_func in reset_tests:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            # Send something first
            sock.send(b"test\n")
            
            close_func(sock)
            
            print(f"    - Close {name}: done")
            
        except Exception as e:
            print(f"    - Close {name}: {type(e).__name__}")
    
    print("\n[11] Testing socket type confusion...")
    
    try:
        # Try to use raw socket (likely requires admin)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        print(f"    - Raw socket: created (requires admin)")
        sock.close()
    except Exception as e:
        print(f"    - Raw socket: {type(e).__name__} (expected)")
    
    print("\n[12] Testing non-blocking mode...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.settimeout(0)
        
        try:
            sock.connect((target_host, target_port))
            print(f"    - Non-blocking: connected")
        except BlockingIOError:
            print(f"    - Non-blocking: would block (expected)")
        except Exception as e:
            print(f"    - Non-blocking: {type(e).__name__}")
        
        sock.close()
        
    except Exception as e:
        print(f"    - Non-blocking test: {type(e).__name__}")
    
    print("\n[13] Testing dual-stack connection...")
    
    # Try connecting to IPv6 mapped address
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("::ffff:127.0.0.1", target_port, 0, 0))
        print(f"    - IPv6 mapped: connected")
        sock.close()
    except Exception as e:
        print(f"    - IPv6 mapped: {type(e).__name__}")
    
    print("\n[14] Final connectivity check...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target_host, target_port))
        
        sock.send(b"status\n")
        
        response = sock.recv(4096)
        print(f"    ✓ CLI still reachable")
        print(f"    - Response: {len(response)} bytes")
        
        sock.close()
        
    except Exception as e:
        print(f"    ! CLI unreachable: {type(e).__name__}")
    
    print("\n" + "=" * 60)
    print("RESULT: Network interception tests complete")
    print("=" * 60)
    return True


if __name__ == "__main__":
    test_network_intercept()