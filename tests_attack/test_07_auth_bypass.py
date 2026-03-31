"""
Attack Test 07: Authentication Bypass Test

This test attempts various authentication bypass
techniques to test auth mechanisms.

Run with: python tests_attack/test_07_auth_bypass.py
"""

import socket
import time
import sys
import os
import hashlib

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_auth_bypass():
    """Test authentication bypass resilience."""
    print("=" * 60)
    print("ATTACK TEST 07: Authentication Bypass")
    print("=" * 60)
    
    target_host = "127.0.0.1"
    target_port = 8888
    
    print(f"\n[1] Target: {target_host}:{target_port}")
    
    print("\n[2] Testing empty credentials...")
    
    auth_tests = [
        ("empty_user", b""),
        ("null_user", b"\x00"),
        ("space_user", b" "),
        ("tab_user", b"\t"),
    ]
    
    for name, payload in auth_tests:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            # Try sending empty username
            sock.send(payload + b"\n")
            time.sleep(0.2)
            
            try:
                response = sock.recv(4096)
                print(f"    - {name}: response={len(response)} bytes")
            except:
                print(f"    - {name}: no response")
            
            sock.close()
            
        except Exception as e:
            print(f"    ! {name}: {type(e).__name__}")
    
    print("\n[3] Testing default/builtin accounts...")
    
    default_users = [
        "admin",
        "root",
        "user",
        "guest",
        "system",
        "Administrator",
        "root",
    ]
    
    for user in default_users:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            sock.send((user + "\n").encode())
            time.sleep(0.2)
            
            try:
                response = sock.recv(4096)
                print(f"    - user '{user}': {len(response)} bytes")
            except:
                print(f"    - user '{user}': no response")
            
            sock.close()
            
        except Exception as e:
            print(f"    ! {user}: {type(e).__name__}")
    
    print("\n[4] Testing SQL injection style auth bypass...")
    
    sql_bypass = [
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or '1'='1",
        "' or '1'='1' --",
        "admin' or '1'='1",
        "admin' or 1=1--",
        "1' or '1'='1",
    ]
    
    for payload in sql_bypass:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            sock.send((payload + "\n").encode())
            time.sleep(0.2)
            
            try:
                response = sock.recv(4096)
                if response and (b"OK" in response or b"Welcome" in response or b"success" in response.lower()):
                    print(f"    ! POTENTIAL BYPASS: {payload}")
                else:
                    print(f"    - {payload}: rejected")
            except:
                print(f"    - {payload}: no response")
            
            sock.close()
            
        except Exception as e:
            print(f"    ! {payload}: {type(e).__name__}")
    
    print("\n[5] Testing session hijacking...")
    
    # Try to capture session tokens
    session_tokens = []
    for i in range(5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            # Send some commands to generate session
            sock.send(b"help\n")
            time.sleep(0.2)
            
            try:
                response = sock.recv(4096)
                # Look for potential session tokens
                if b"SESSION" in response.upper() or b"TOKEN" in response.upper():
                    print(f"    - Session token found in response")
                session_tokens.append(len(response))
            except:
                pass
            
            sock.close()
            
        except Exception:
            pass
        
        time.sleep(0.1)
    
    print(f"    - Collected {len(session_tokens)} session responses")
    
    print("\n[6] Testing brute force simulation...")
    
    # Try common commands rapidly
    common_commands = [
        "help", "status", "echo", "calc", "exit", "quit",
        "whoami", "id", "uname", "ls", "dir", "pwd"
    ]
    
    brute_force_results = {"attempted": 0, "accepted": 0, "rejected": 0}
    
    for cmd in common_commands:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_host, target_port))
            
            sock.send((cmd + "\n").encode())
            time.sleep(0.1)
            
            try:
                response = sock.recv(4096)
                if response:
                    brute_force_results["accepted"] += 1
            except:
                brute_force_results["rejected"] += 1
            
            brute_force_results["attempted"] += 1
            sock.close()
            
        except Exception:
            brute_force_results["attempted"] += 1
    
    print(f"    - Commands attempted: {brute_force_results['attempted']}")
    print(f"    - Accepted: {brute_force_results['accepted']}")
    print(f"    - Rejected: {brute_force_results['rejected']}")
    
    print("\n[7] Testing cookie/session manipulation...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_host, target_port))
        
        # Try to set cookies or session headers
        cookie_payloads = [
            b"Cookie: session=1234567890\n",
            b"X-Session-Token: test123\n",
            b"Authorization: Basic YWRtaW46YWRtaW4=\n",
        ]
        
        for cookie in cookie_payloads:
            try:
                sock.send(cookie)
                time.sleep(0.1)
                
                response = sock.recv(4096)
                print(f"    - Cookie attempt: {len(response)} bytes")
                
            except Exception:
                pass
        
        sock.close()
        
    except Exception as e:
        print(f"    ! Cookie test: {type(e).__name__}")
    
    print("\n[8] Testing privilege escalation commands...")
    
    priv_esc = [
        "sudo su",
        "su root",
        "enable",
        "spawn sh",
        "/bin/sh",
        "/bin/bash",
        "chmod 777 /",
    ]
    
    for cmd in priv_esc:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, target_port))
            
            sock.send((cmd + "\n").encode())
            time.sleep(0.2)
            
            try:
                response = sock.recv(4096)
                if response:
                    print(f"    - '{cmd}': response={len(response)} bytes")
            except:
                pass
            
            sock.close()
            
        except Exception:
            pass
    
    print("\n" + "=" * 60)
    print("RESULT: Auth bypass tests complete")
    print("=" * 60)
    return True


if __name__ == "__main__":
    test_auth_bypass()