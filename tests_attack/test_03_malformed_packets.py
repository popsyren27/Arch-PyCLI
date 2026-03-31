"""
Attack Test 03: Malformed Packets Test

This test sends malformed packets to test protocol
parsing resilience and error handling.

Run with: python tests_attack/test_03_malformed_packets.py
"""

import socket
import struct
import sys
import os

# For ConnectionRefused
ConnectionRefused = socket.error

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_malformed_packets():
    """Test malformed packet handling."""
    print("=" * 60)
    print("ATTACK TEST 03: Malformed Packets")
    print("=" * 60)
    
    target_host = "127.0.0.1"
    target_port = 8888
    
    print(f"\n[1] Target: {target_host}:{target_port}")
    
    # Malformed packet types
    packets = [
        # Empty packets
        b"",
        b"\x00",
        b"\x00\x00\x00",
        
        # Fragmented packets
        b"HE",
        b"HELO",
        b"INCOMPLETE",
        
        # Null bytes scattered
        b"\x00HELLO\x00",
        b"H\x00E\x00L\x00L\x00O\x00",
        
        # Very long packets
        b"A" * 65535,
        b"B" * 100000,
        
        # Binary/special characters
        b"\xff\xfe\xfd",
        b"\x80\x81\x82",
        b"\x00\x01\x02\x03\x04",
        
        # Mix of valid and invalid
        b"VALID\x00\x00\x00\x00INVALID",
        b"test\r\n\r\n\r\n\r\n",
        
        # Truncated headers
        b"GET",
        b"POST",
        b"PUT ",
        b"HTTP/1.1\x00",
        
        # Special sequences
        b"\r\n\r\n\r\n\r\n",
        b"   \t\t\t   ",
        b"\n\n\n\n\n\n",
        
        # Unicode attempts
        "テスト".encode('utf-8'),
        "测试".encode('utf-8'),
        
        # Protocol confusion
        b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        
        # Partial commands
        b"hel",
        b"helps",
        b"exi",
        b"qui",
        b"eco",
    ]
    
    print(f"\n[2] Testing {len(packets)} malformed packets...")
    
    results = {
        "sent": 0,
        "crashed": 0,
        "handled": 0,
        "errors": 0
    }
    
    for i, packet in enumerate(packets):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            try:
                sock.connect((target_host, target_port))
                
                # Send malformed packet
                sock.send(packet)
                results["sent"] += 1
                
                # Try to get response
                try:
                    response = sock.recv(1024)
                    results["handled"] += 1
                except socket.timeout:
                    results["handled"] += 1
                except Exception:
                    results["crashed"] += 1
                    
            except ConnectionRefused:
                results["errors"] += 1
            except Exception as e:
                results["errors"] += 1
                
            sock.close()
            
        except Exception as e:
            results["errors"] += 1
            
        if (i + 1) % 5 == 0:
            print(f"    - Tested {i+1}/{len(packets)} packets...")
    
    print(f"\n[3] Results:")
    print(f"    - Packets sent: {results['sent']}")
    print(f"    - Handled gracefully: {results['handled']}")
    print(f"    - Caused crashes: {results['crashed']}")
    print(f"    - Connection errors: {results['errors']}")
    
    print("\n[4] Testing with raw socket options...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        sock.settimeout(2)
        sock.connect((target_host, target_port))
        sock.send(b"test")
        print(f"    ✓ Socket with custom options connected")
        sock.close()
    except Exception as e:
        print(f"    ! Socket options test: {type(e).__name__}")
    
    print("\n" + "=" * 60)
    print("RESULT: Malformed packets test complete")
    print("=" * 60)
    return True


if __name__ == "__main__":
    test_malformed_packets()