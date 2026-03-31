"""
Attack Test Runner Script

This script runs all attack test files in sequence.
These tests are designed to be run against a running CLI instance.

Run with: python tests_attack/run_all_attack_tests.py
"""

import subprocess
import sys
import os

def run_attack_tests():
    """Run all attack test files."""
    test_files = [
        "test_01_connection_flood.py",
        "test_02_payload_injection.py",
        "test_03_malformed_packets.py",
        "test_04_resource_exhaustion.py",
        "test_05_tls_attacks.py",
        "test_06_timing_info_disclosure.py",
        "test_07_auth_bypass.py",
        "test_08_fuzzing.py",
        "test_09_network_intercept.py",
        "test_10_crypto_attacks.py",
    ]
    
    print("=" * 60)
    print("RUNNING ALL ATTACK TESTS")
    print("NOTE: Start CLI first: python main.py")
    print("=" * 60)
    print()
    
    for i, test_file in enumerate(test_files, 1):
        test_path = os.path.join("tests_attack", test_file)
        print(f"[{i}/10] Running {test_file}...")
        
        try:
            result = subprocess.run(
                [sys.executable, test_path],
                capture_output=False,
                text=True,
                timeout=120
            )
            print(f"    - Exit code: {result.returncode}")
                
        except subprocess.TimeoutExpired:
            print(f"    ! TIMEOUT")
        except Exception as e:
            print(f"    ! ERROR: {e}")
        
        print()
    
    print("=" * 60)
    print("ATTACK TESTS COMPLETED")
    print("=" * 60)
    print()
    print("Note: These tests require the CLI to be running first.")
    print("Start the CLI with: python main.py")
    print("Then run: python tests_attack/run_all_attack_tests.py")


if __name__ == "__main__":
    run_attack_tests()