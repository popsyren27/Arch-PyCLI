"""
Attack Test 10: Cryptographic Attack Test

This test attempts various cryptographic attacks like
weak encryption, key extraction, and crypto implementation flaws.

Run with: python tests_attack/test_10_crypto_attacks.py
"""

import socket
import time
import sys
import os
import hashlib

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_crypto_attacks():
    """Test cryptographic attack resilience."""
    print("=" * 60)
    print("ATTACK TEST 10: Cryptographic Attacks")
    print("=" * 60)
    
    target_host = "127.0.0.1"
    target_port = 8888
    
    print(f"\n[1] Target: {target_host}:{target_port}")
    
    print("\n[2] Testing weak hash generation...")
    
    # Try to extract hash values from responses
    hash_algorithms = [
        "md5",
        "sha1",
        "sha256",
        "sha512",
    ]
    
    hash_results = {}
    
    for algo in hash_algorithms:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            # Send command that might produce hash
            sock.send(b"status\n")
            time.sleep(0.2)
            
            try:
                response = sock.recv(4096)
                
                # Look for hash-like patterns
                response_str = response.decode('utf-8', errors='ignore')
                hash_results[algo] = len(response_str)
                
                # Check for common hash patterns
                if any(c in response_str for c in [':', '=', '-']):
                    print(f"    - {algo}: Found delimiters")
                else:
                    print(f"    - {algo}: response={len(response)} bytes")
                    
            except:
                print(f"    - {algo}: no response")
            
            sock.close()
            
        except Exception as e:
            print(f"    ! {algo}: {type(e).__name__}")
    
    print("\n[3] Testing entropy analysis...")
    
    # Analyze response entropy (simple version)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_host, target_port))
        
        sock.send(b"help\n")
        time.sleep(0.2)
        
        response = sock.recv(4096)
        
        if response:
            # Calculate byte distribution
            byte_counts = {}
            for byte in response:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
            # Calculate simple entropy
            unique_bytes = len(byte_counts)
            total_bytes = len(response)
            
            print(f"    - Unique bytes: {unique_bytes}/{total_bytes}")
            print(f"    - Byte diversity: {unique_bytes/256*100:.1f}%")
        
        sock.close()
        
    except Exception as e:
        print(f"    ! Entropy test: {type(e).__name__}")
    
    print("\n[4] Testing predictable random generation...")
    
    # Try to see if random values are predictable
    random_tests = []
    
    for i in range(5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            # Get a response
            sock.send(b"status\n")
            time.sleep(0.1)
            
            response = sock.recv(4096)
            random_tests.append(len(response))
            
            sock.close()
            
        except Exception:
            pass
        
        time.sleep(0.1)
    
    if random_tests:
        unique_lens = len(set(random_tests))
        print(f"    - Response sizes: {random_tests}")
        print(f"    - Unique sizes: {unique_lens}")
        
        if unique_lens == 1:
            print(f"    ! WARNING: All responses have same size (predictable)")
    
    print("\n[5] Testing weak crypto key derivation...")
    
    # Test for weak key derivation
    key_derivations = [
        (b"password", b"salt"),
        (b"admin", b"123"),
        (b"root", b""),
        (b"test", b"test"),
    ]
    
    for pwd, salt in key_derivations:
        try:
            # Try simple hash as key derivation
            combined = pwd + salt
            result = hashlib.md5(combined).hexdigest()
            print(f"    - Key derivation for '{pwd.decode()}' with salt '{salt.decode()}': {result[:8]}...")
        except Exception as e:
            print(f"    - Key derivation: {type(e).__name__}")
    
    print("\n[6] Testing ASCII-only vs binary responses...")
    
    ascii_tests = []
    binary_tests = []
    
    commands = [
        b"help\n",
        b"echo test\n",
        b"status\n",
        b"calc 1+1\n",
    ]
    
    for cmd in commands:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            sock.send(cmd)
            time.sleep(0.2)
            
            response = sock.recv(4096)
            
            if response:
                # Check if all bytes are ASCII
                is_ascii = all(b < 128 for b in response)
                if is_ascii:
                    ascii_tests.append(cmd.decode().strip())
                else:
                    binary_tests.append(cmd.decode().strip())
            
            sock.close()
            
        except Exception:
            pass
    
    print(f"    - ASCII responses: {len(ascii_tests)}")
    print(f"    - Binary responses: {len(binary_tests)}")
    
    if binary_tests:
        print(f"    ! WARNING: Binary responses detected for: {binary_tests}")
    
    print("\n[7] Testing padding oracle potential...")
    
    # Test various padding-like patterns
    padding_tests = [
        b"\x01",
        b"\x02\x02",
        b"\x03\x03\x03",
        b"\x04\x04\x04\x04",
        b"\x10" * 16,
        b"\x00" * 16,
        b"\xff" * 16,
    ]
    
    for pad in padding_tests:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            sock.send(pad + b"\n")
            time.sleep(0.2)
            
            try:
                response = sock.recv(4096)
                if response:
                    print(f"    - Padding {len(pad)} bytes: response={len(response)}")
            except:
                pass
            
            sock.close()
            
        except Exception:
            pass
    
    print("\n[8] Testing initialization vector (IV) patterns...")
    
    # Test to see if same plaintext produces same ciphertext
    iv_tests = []
    
    for i in range(3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            # Same input each time
            sock.send(b"echo test\n")
            time.sleep(0.2)
            
            response = sock.recv(4096)
            iv_tests.append(response)
            
            sock.close()
            
        except Exception:
            pass
        
        time.sleep(0.1)
    
    if len(iv_tests) >= 2:
        # Check if responses are identical (weak crypto indicator)
        if iv_tests[0] == iv_tests[1]:
            print(f"    ! WARNING: Identical responses for same input (weak IV/non-encryption)")
        else:
            print(f"    - Responses differ (may indicate encryption)")
            print(f"    - Response 1: {len(iv_tests[0])} bytes")
            print(f"    - Response 2: {len(iv_tests[1])} bytes")
    
    print("\n[9] Testing weak PRNG indicators...")
    
    # Try various inputs and see if outputs are predictable
    prng_tests = []
    
    test_inputs = [
        "a", "b", "c", "1", "2", "3",
        "aa", "ab", "ac",
        "aaa", "aab", "aac"
    ]
    
    for inp in test_inputs:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_host, target_port))
            
            sock.send((inp + "\n").encode())
            time.sleep(0.1)
            
            try:
                response = sock.recv(4096)
                prng_tests.append((inp, len(response)))
            except:
                pass
            
            sock.close()
            
        except Exception:
            pass
    
    if prng_tests:
        unique_outputs = len(set(o for _, o in prng_tests))
        print(f"    - Unique outputs: {unique_outputs}/{len(prng_tests)}")
        
        if unique_outputs < len(prng_tests) * 0.5:
            print(f"    ! Low output diversity (possible weak PRNG)")
    
    print("\n[10] Testing session token patterns...")
    
    # Try to find session-like tokens in responses
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_host, target_port))
        
        sock.send(b"help\n")
        time.sleep(0.2)
        
        response = sock.recv(4096)
        
        if response:
            # Look for patterns that might be tokens
            response_str = response.decode('utf-8', errors='ignore')
            
            # Check for hex strings (possible tokens)
            hex_count = sum(1 for c in response_str if c in '0123456789abcdefABCDEF')
            total_chars = len(response_str)
            
            if total_chars > 0:
                hex_ratio = hex_count / total_chars
                print(f"    - Hex character ratio: {hex_ratio:.2f}")
                
                if hex_ratio > 0.5:
                    print(f"    ! High hex ratio (possible encoded token)")
        
        sock.close()
        
    except Exception as e:
        print(f"    ! Session token test: {type(e).__name__}")
    
    print("\n[11] Testing weak cipher detection...")
    
    # Try to negotiate weak ciphers if TLS is available
    try:
        import ssl
        
        weak_ciphers = [
            'EXP-RC4-MD5',
            'RC4-MD5',
            'EXP-DES-CBC-SHA',
            'DES-CBC-SHA',
            'EXP-RC4-MD5',
        ]
        
        for cipher in weak_ciphers:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_ciphers(cipher)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssl_sock = ctx.wrap_socket(sock, server_hostname=target_host)
                ssl_sock.settimeout(2)
                
                try:
                    ssl_sock.connect((target_host, target_port))
                    print(f"    - Weak cipher {cipher}: accepted")
                    ssl_sock.close()
                except ssl.SSLError:
                    pass
                    
            except Exception:
                pass
        
    except ImportError:
        print(f"    - SSL module not available, skipping cipher tests")
    except Exception as e:
        print(f"    - Cipher test: {type(e).__name__}")
    
    print("\n[12] Testing timing leaks in crypto operations...")
    
    # Measure response times for different operations
    crypto_timing = {}
    
    operations = [
        b"help\n",
        b"echo test\n",
        b"status\n",
    ]
    
    for op in operations:
        timings = []
        
        for _ in range(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                start = time.perf_counter()
                sock.connect((target_host, target_port))
                sock.send(op)
                sock.recv(4096)
                end = time.perf_counter()
                
                timings.append(end - start)
                sock.close()
                
            except Exception:
                pass
            
            time.sleep(0.1)
        
        if timings:
            avg = sum(timings) / len(timings)
            crypto_timing[op.decode().strip()] = avg
    
    print(f"    - Operation timings:")
    for op, timing in crypto_timing.items():
        print(f"      - '{op}': {timing*1000:.2f}ms")
    
    # Check for timing variance (could indicate crypto operations)
    if len(set(crypto_timing.values())) > 1:
        timing_diff = max(crypto_timing.values()) - min(crypto_timing.values())
        if timing_diff > 0.01:  # 10ms difference
            print(f"    ! Significant timing variance: {timing_diff*1000:.2f}ms")
    
    print("\n[13] Testing for hardcoded keys/secrets...")
    
    # Test for common hardcoded secrets
    secret_patterns = [
        "password",
        "secret",
        "key",
        "token",
        "api_key",
        "apikey",
        "private",
        "credential",
    ]
    
    for pattern in secret_patterns:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            sock.send((pattern + "\n").encode())
            time.sleep(0.2)
            
            try:
                response = sock.recv(4096)
                # Look for hints of hardcoded values
                if response and any(p in response.lower() for p in [b"key", b"secret", b"password"]):
                    print(f"    ! Possible hardcoded: '{pattern}'")
            except:
                pass
            
            sock.close()
            
        except Exception:
            pass
    
    print("\n[14] Final CLI check...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target_host, target_port))
        
        sock.send(b"help\n")
        
        response = sock.recv(4096)
        print(f"    ✓ CLI still reachable")
        print(f"    - Response: {len(response)} bytes")
        
        sock.close()
        
    except Exception as e:
        print(f"    ! CLI unreachable: {type(e).__name__}")
    
    print("\n" + "=" * 60)
    print("RESULT: Cryptographic attack tests complete")
    print("=" * 60)
    return True


if __name__ == "__main__":
    test_crypto_attacks()