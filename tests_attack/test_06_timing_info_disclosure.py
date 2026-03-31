"""
Attack Test 06: Timing Attack & Information Disclosure Test

This test attempts to extract information through
timing differences and information leaks.

Run with: python tests_attack/test_06_timing_info_disclosure.py
"""

import socket
import time
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_timing_info_disclosure():
    """Test timing attack and info disclosure resilience."""
    print("=" * 60)
    print("ATTACK TEST 06: Timing & Information Disclosure")
    print("=" * 60)
    
    target_host = "127.0.0.1"
    target_port = 8888
    
    print(f"\n[1] Target: {target_host}:{target_port}")
    
    print("\n[2] Testing response time analysis...")
    
    # Measure response times for different commands
    test_commands = [
        b"help\n",
        b"echo test\n",
        b"invalid_command\n",
        b"exit\n",
        b"status\n",
    ]
    
    timing_results = {}
    
    for cmd in test_commands:
        timings = []
        for _ in range(5):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target_host, target_port))
                
                start = time.perf_counter()
                sock.send(cmd)
                try:
                    sock.recv(4096)
                except:
                    pass
                end = time.perf_counter()
                
                timings.append(end - start)
                sock.close()
                
            except Exception as e:
                timings.append(-1)
            
            time.sleep(0.1)
        
        avg_time = sum(t for t in timings if t > 0) / max(1, sum(1 for t in timings if t > 0))
        timing_results[cmd.decode().strip()] = {
            'avg': avg_time,
            'timings': timings
        }
    
    print(f"    - Command response times:")
    for cmd, data in timing_results.items():
        print(f"      - '{cmd}': {data['avg']*1000:.2f}ms")
    
    print("\n[3] Testing error message differences...")
    
    # Test different error messages
    error_tests = [
        ("help", "Valid command"),
        ("unknown_cmd_12345", "Unknown command"),
        ("echo", "Empty args"),
        ("calc", "Invalid math"),
    ]
    
    for cmd_hint, desc in error_tests:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            # Send something that might produce different error
            if cmd_hint == "echo":
                sock.send(b"echo\n")
            elif cmd_hint == "calc":
                sock.send(b"calc\n")
            else:
                sock.send((cmd_hint + "\n").encode())
            
            time.sleep(0.2)
            
            try:
                response = sock.recv(4096)
                if response:
                    print(f"    - {desc}: Response received ({len(response)} bytes)")
            except:
                print(f"    - {desc}: No response")
            
            sock.close()
            
        except Exception as e:
            print(f"    ! {desc}: {type(e).__name__}")
    
    print("\n[4] Testing connection timing指纹...")
    
    # Test connection establishment timing
    conn_timings = []
    for i in range(10):
        try:
            start = time.perf_counter()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            end = time.perf_counter()
            
            conn_timings.append(end - start)
            sock.close()
            
        except Exception:
            conn_timings.append(-1)
        
        time.sleep(0.05)
    
    valid_timings = [t for t in conn_timings if t > 0]
    if valid_timings:
        avg_conn = sum(valid_timings) / len(valid_timings)
        print(f"    - Avg connection time: {avg_conn*1000:.2f}ms")
        print(f"    - Connection time variance: {max(valid_timings) - min(valid_timings):.4f}s")
    
    print("\n[5] Testing information leakage via port scanning...")
    
    # Test different ports to see if they respond differently
    ports_to_test = [8888, 8889, 8890, 9000, 9001, 80, 443, 22]
    port_results = {}
    
    for port in ports_to_test:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            start = time.perf_counter()
            result = sock.connect_ex((target_host, port))
            end = time.perf_counter()
            
            port_results[port] = {
                'open': result == 0,
                'time': end - start
            }
            
            sock.close()
            
        except Exception:
            port_results[port] = {'open': False, 'time': -1}
    
    print(f"    - Port scan results:")
    for port, data in port_results.items():
        status = "OPEN" if data['open'] else "closed"
        print(f"      - {port}: {status}")
    
    print("\n[6] Testing protocol fingerprinting...")
    
    fingerprints = []
    probes = [
        b"\r\n\r\n",
        b" ",
        b"\x00",
        b"GET",
        b"HTTP",
    ]
    
    for probe in probes:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_host, target_port))
            
            sock.send(probe)
            time.sleep(0.1)
            
            try:
                response = sock.recv(1024)
                fingerprints.append({
                    'probe': repr(probe),
                    'response_len': len(response),
                    'response': response[:50] if response else b''
                })
            except:
                fingerprints.append({
                    'probe': repr(probe),
                    'response_len': 0,
                    'response': b''
                })
            
            sock.close()
            
        except Exception as e:
            fingerprints.append({
                'probe': repr(probe),
                'error': type(e).__name__
            })
    
    print(f"    - Protocol fingerprints collected: {len(fingerprints)}")
    
    print("\n[7] Testing session token generation timing...")
    
    # Try multiple connections and see if there's pattern in responses
    session_tests = []
    for i in range(5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            # Send a simple command
            sock.send(b"status\n")
            
            time.sleep(0.1)
            
            try:
                response = sock.recv(4096)
                session_tests.append({
                    'id': i,
                    'response_len': len(response),
                    'has_unique': len(set(response)) > 10
                })
            except:
                session_tests.append({'id': i, 'response_len': 0, 'has_unique': False})
            
            sock.close()
            
        except Exception as e:
            session_tests.append({'id': i, 'error': type(e).__name__})
        
        time.sleep(0.1)
    
    print(f"    - Session analysis:")
    for t in session_tests:
        if 'error' in t:
            print(f"      - Session {t['id']}: {t['error']}")
        else:
            print(f"      - Session {t['id']}: {t['response_len']} bytes, unique={t['has_unique']}")
    
    print("\n" + "=" * 60)
    print("RESULT: Timing & info disclosure tests complete")
    print("=" * 60)
    return True


if __name__ == "__main__":
    test_timing_info_disclosure()