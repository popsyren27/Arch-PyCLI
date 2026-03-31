"""
Attack Test 08: Fuzzing Test

This test uses random/fuzzed inputs to discover
potential vulnerabilities through automated testing.

Run with: python tests_attack/test_08_fuzzing.py
"""

import socket
import random
import string
import time
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def generate_random_string(length):
    """Generate random string for fuzzing."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def generate_fuzz_payload():
    """Generate various fuzzing payloads."""
    payloads = []
    
    # Random strings
    for _ in range(20):
        payloads.append(generate_random_string(random.randint(5, 100)))
    
    # Random with special chars
    for _ in range(10):
        length = random.randint(10, 50)
        charset = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        payloads.append(''.join(random.choices(charset, k=length)))
    
    # Numbers
    for _ in range(5):
        payloads.append(str(random.randint(0, 999999)))
    
    # Unicode fuzzing
    for _ in range(5):
        payloads.append(chr(random.randint(0x4E00, 0x9FFF)) * random.randint(3, 10))
    
    # Empty and whitespace
    payloads.extend(['', ' ', '\t', '\n', '\r\n', '   ', '\t\t\t'])
    
    # Command-like fuzzing
    for _ in range(10):
        length = random.randint(3, 20)
        cmd = ''.join(random.choices(string.ascii_lowercase, k=length))
        payloads.append(cmd)
    
    return payloads


def test_fuzzing():
    """Test fuzzing resilience."""
    print("=" * 60)
    print("ATTACK TEST 08: Fuzzing")
    print("=" * 60)
    
    target_host = "127.0.0.1"
    target_port = 8888
    
    print(f"\n[1] Target: {target_host}:{target_port}")
    
    print("\n[2] Testing random string fuzzing...")
    
    fuzz_results = {
        "sent": 0,
        "crashes": 0,
        "accepted": 0,
        "rejected": 0,
        "errors": 0
    }
    
    # Generate fuzzing payloads
    payloads = generate_fuzz_payload()
    print(f"    - Generated {len(payloads)} fuzzing payloads")
    
    for i, payload in enumerate(payloads):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            # Send fuzzing payload
            try:
                sock.send((payload + "\n").encode('utf-8', errors='ignore'))
                fuzz_results["sent"] += 1
            except:
                fuzz_results["errors"] += 1
                sock.close()
                continue
            
            # Try to get response
            try:
                response = sock.recv(4096)
                if response:
                    fuzz_results["accepted"] += 1
                else:
                    fuzz_results["rejected"] += 1
            except socket.timeout:
                fuzz_results["rejected"] += 1
            except Exception as e:
                # Check for crash indicators
                if "MemoryError" in str(type(e).__name__):
                    fuzz_results["crashes"] += 1
                fuzz_results["rejected"] += 1
            
            sock.close()
            
        except Exception as e:
            fuzz_results["errors"] += 1
        
        if (i + 1) % 10 == 0:
            print(f"    - Tested {i+1}/{len(payloads)} payloads...")
    
    print(f"\n    - Fuzz results:")
    print(f"      - Sent: {fuzz_results['sent']}")
    print(f"      - Accepted: {fuzz_results['accepted']}")
    print(f"      - Rejected: {fuzz_results['rejected']}")
    print(f"      - Crashes: {fuzz_results['crashes']}")
    print(f"      - Errors: {fuzz_results['errors']}")
    
    print("\n[3] Testing protocol fuzzing...")
    
    protocol_fuzz = [
        # HTTP-like fuzzing
        b"GET " + generate_random_string(20).encode() + b" HTTP/1.1\n",
        b"POST /" + generate_random_string(10).encode() + b" HTTP/1.1\n",
        
        # Header fuzzing
        b"Host: " + generate_random_string(15).encode() + b"\n",
        b"User-Agent: " + generate_random_string(30).encode() + b"\n",
        
        # Binary fuzzing
        bytes([random.randint(0, 255) for _ in range(20)]),
        bytes([random.randint(0, 255) for _ in range(50)]),
        
        # Mixed
        b"\x00" + generate_random_string(10).encode() + b"\xff",
    ]
    
    for proto_payload in protocol_fuzz:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            sock.send(proto_payload)
            
            try:
                response = sock.recv(4096)
                print(f"    - Protocol fuzz: response={len(response)}")
            except:
                pass
            
            sock.close()
            
        except Exception:
            pass
    
    print("\n[4] Testing mutation fuzzing...")
    
    # Take valid commands and mutate them
    base_commands = ["help", "echo", "status", "calc", "exit"]
    mutations = []
    
    for cmd in base_commands:
        for _ in range(5):
            # Random character insertion
            pos = random.randint(0, len(cmd))
            char = random.choice(string.ascii_letters)
            mutation = cmd[:pos] + char + cmd[pos:]
            mutations.append(mutation)
        
        for _ in range(3):
            # Random character deletion
            if len(cmd) > 2:
                pos = random.randint(0, len(cmd) - 1)
                mutation = cmd[:pos] + cmd[pos+1:]
                mutations.append(mutation)
        
        for _ in range(3):
            # Random character replacement
            pos = random.randint(0, len(cmd) - 1)
            char = random.choice(string.ascii_letters)
            mutation = cmd[:pos] + char + cmd[pos+1:]
            mutations.append(mutation)
    
    mutation_results = {"tested": 0, "accepted": 0}
    
    for mutation in mutations:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_host, target_port))
            
            sock.send((mutation + "\n").encode())
            mutation_results["tested"] += 1
            
            try:
                response = sock.recv(4096)
                if response:
                    mutation_results["accepted"] += 1
            except:
                pass
            
            sock.close()
            
        except Exception:
            pass
    
    print(f"    - Mutations tested: {mutation_results['tested']}")
    print(f"    - Accepted: {mutation_results['accepted']}")
    
    print("\n[5] Testing length-based fuzzing...")
    
    # Test with varying lengths
    length_tests = [1, 2, 5, 10, 50, 100, 500, 1000, 5000, 10000]
    
    for length in length_tests:
        try:
            payload = "A" * length
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_host, target_port))
            
            sock.send((payload + "\n").encode())
            
            try:
                response = sock.recv(4096)
                print(f"    - Length {length}: response={len(response)}")
            except socket.timeout:
                print(f"    - Length {length}: timeout")
            except Exception as e:
                print(f"    - Length {length}: {type(e).__name__}")
            
            sock.close()
            
        except Exception as e:
            print(f"    - Length {length}: connect failed - {type(e).__name__}")
    
    print("\n[6] Testing boundary value fuzzing...")
    
    boundary_tests = [
        # Max values
        str(2**31 - 1),
        str(2**32 - 1),
        str(2**63 - 1),
        str(2**64 - 1),
        
        # Negative values
        "-1",
        "-999999999",
        "-9223372036854775808",
        
        # Special floats
        "0.0",
        "-0.0",
        "1e10",
        "1e100",
        "inf",
        "-inf",
        "nan",
        
        # Empty-ish
        "None",
        "null",
        "undefined",
        "NaN",
        "undefined",
    ]
    
    for boundary in boundary_tests:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_host, target_port))
            
            sock.send((boundary + "\n").encode())
            
            try:
                response = sock.recv(4096)
            except:
                pass
            
            sock.close()
            
        except Exception:
            pass
    
    print(f"    - Boundary tests completed")
    
    print("\n[7] Testing recursive fuzzing...")
    
    # Send multiple commands in sequence without waiting
    recursive_tests = [
        ["help", "help", "help"],
        ["echo", "test", "echo", "test"],
        ["status", "echo", "status"],
        ["help", "exit", "help"],
    ]
    
    for seq in recursive_tests:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_host, target_port))
            
            for cmd in seq:
                sock.send((cmd + "\n").encode())
                time.sleep(0.05)
            
            try:
                responses = b""
                for _ in range(len(seq)):
                    try:
                        responses += sock.recv(4096)
                    except:
                        break
                print(f"    - Sequence {seq}: {len(responses)} bytes total")
            except:
                pass
            
            sock.close()
            
        except Exception:
            pass
    
    print("\n[8] Testing format string fuzzing...")
    
    format_strings = [
        "%s",
        "%d",
        "%x",
        "%n",
        "%10s",
        "%-10s",
        "%10d",
        "%08x",
        "%c",
        "%p",
        "{}",
        "{0}",
        "{0}{1}{2}",
        "{{}}",
        "{{0}}",
        "${ENV}",
        "$PATH",
        "$(ls)",
        "`ls`",
        "{{.Env}}",
    ]
    
    for fmt in format_strings:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_host, target_port))
            
            sock.send((fmt + "\n").encode())
            
            try:
                response = sock.recv(4096)
            except:
                pass
            
            sock.close()
            
        except Exception:
            pass
    
    print(f"    - Format string tests completed")
    
    print("\n[9] Final CLI availability check...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target_host, target_port))
        
        sock.send(b"help\n")
        
        response = sock.recv(4096)
        print(f"    ✓ CLI still functional after fuzzing")
        print(f"    - Response length: {len(response)} bytes")
        
        sock.close()
        
    except Exception as e:
        print(f"    ! CLI may be unavailable: {type(e).__name__}")
    
    print("\n" + "=" * 60)
    print("RESULT: Fuzzing test complete")
    print("=" * 60)
    return True


if __name__ == "__main__":
    test_fuzzing()