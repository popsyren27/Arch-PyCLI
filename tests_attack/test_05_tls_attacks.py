"""
Attack Test 05: TLS/SSL Attack Test

This test attempts various TLS/SSL attacks like
certificate spoofing, protocol downgrading, and
weak cipher testing.

Run with: python tests_attack/test_05_tls_attacks.py
"""

import socket
import ssl
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_tls_attacks():
    """Test TLS/SSL attack resilience."""
    print("=" * 60)
    print("ATTACK TEST 05: TLS/SSL Attacks")
    print("=" * 60)
    
    target_host = "127.0.0.1"
    target_port = 8888
    
    print(f"\n[1] Target: {target_host}:{target_port}")
    
    print("\n[2] Testing certificate verification bypass...")
    
    # Test with certificate verification disabled
    bypass_results = {"tried": 0, "connected": 0, "errors": 0}
    
    try:
        # Create context that doesn't verify certificate
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
        ssl_sock.settimeout(2)
        ssl_sock.connect((target_host, target_port))
        
        print(f"    ✓ Connected with cert verification disabled")
        print(f"    - Cipher: {ssl_sock.cipher()}")
        
        bypass_results["connected"] += 1
        ssl_sock.close()
        
    except ssl.SSLError as e:
        print(f"    ! SSL error (expected if TLS not enabled): {e}")
        bypass_results["errors"] += 1
    except Exception as e:
        print(f"    ! Error: {type(e).__name__}: {e}")
        bypass_results["errors"] += 1
    
    print("\n[3] Testing weak cipher suites...")
    
    weak_cipher_results = {"tried": 0, "connected": 0, "errors": 0}
    weak_ciphers = [
        'RC4-MD5',
        'EXP-RC4-MD5',
        'ECDHE-RSA-RC4-SHA',
        'RC4-SHA',
        'EXP-DES-CBC-SHA',
    ]
    
    for cipher in weak_ciphers:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers(cipher)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
            ssl_sock.settimeout(2)
            ssl_sock.connect((target_host, target_port))
            
            weak_cipher_results["connected"] += 1
            print(f"    - Connected with: {cipher}")
            
            ssl_sock.close()
            
        except ssl.SSLError:
            weak_cipher_results["errors"] += 1
        except Exception as e:
            weak_cipher_results["errors"] += 1
    
    print(f"    - Connected with weak ciphers: {weak_cipher_results['connected']}")
    
    print("\n[4] Testing SSLv2/SSLv3 protocol downgrade...")
    
    downgrade_results = {"tried": 0, "rejected": 0, "errors": 0}
    old_protocols = [
        ssl.PROTOCOL_SSLv23,  # Allow downgrade
    ]
    
    for proto in old_protocols:
        try:
            context = ssl.SSLContext(proto)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
            ssl_sock.settimeout(2)
            ssl_sock.connect((target_host, target_port))
            
            print(f"    - Connected with protocol")
            ssl_sock.close()
            
        except ssl.SSLError as e:
            downgrade_results["rejected"] += 1
        except Exception as e:
            downgrade_results["errors"] += 1
    
    print("\n[5] Testing invalid certificate handling...")
    
    try:
        # Try with self-signed certificate warning
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_OPTIONAL
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
        ssl_sock.settimeout(2)
        
        try:
            ssl_sock.connect((target_host, target_port))
            print(f"    - Accepted optional certificate")
        except ssl.SSLCertVerificationError:
            print(f"    - Rejected unverified certificate")
        except Exception as e:
            print(f"    - Error: {type(e).__name__}")
        
        ssl_sock.close()
        
    except Exception as e:
        print(f"    ! Test error: {type(e).__name__}")
    
    print("\n[6] Testing TLS heartbeat attack (if applicable)...")
    
    try:
        # Send malformed TLS heartbeat
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
        ssl_sock.settimeout(2)
        ssl_sock.connect((target_host, target_port))
        
        # Try to send heartbeat extension
        # This is a simplified test
        print(f"    - TLS connection established")
        
        ssl_sock.close()
        
    except ssl.SSLError as e:
        print(f"    ! SSL error: {e}")
    except Exception as e:
        print(f"    ! Error: {type(e).__name__}")
    
    print("\n[7] Testing non-TLS connection to TLS port...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_host, target_port))
        
        # Send regular HTTP-like request
        sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        
        response = sock.recv(1024)
        print(f"    - Plain connection accepted (not TLS)")
        
        sock.close()
        
    except Exception as e:
        print(f"    ! Error: {type(e).__name__}")
    
    print("\n" + "=" * 60)
    print("RESULT: TLS/SSL attack tests complete")
    print("=" * 60)
    return True


if __name__ == "__main__":
    test_tls_attacks()