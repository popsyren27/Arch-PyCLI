"""
Test Runner Script

This script runs all test files in sequence.
Each test is run as a subprocess so they have fresh state.

Run with: python tests/run_all_tests.py
"""

import subprocess
import sys
import os

def run_tests():
    """Run all test files."""
    test_files = [
        "test_01_basic_boot.py",
        "test_02_plugin_loading.py",
        "test_03_command_dispatch.py",
        "test_04_echo_command.py",
        "test_05_help_command.py",
        "test_06_hal_health.py",
        "test_07_network_node.py",
        "test_08_security_module.py",
        "test_09_config_module.py",
        "test_10_cli_mode.py",
    ]
    
    results = []
    
    print("=" * 60)
    print("RUNNING ALL TESTS")
    print("=" * 60)
    print()
    
    for i, test_file in enumerate(test_files, 1):
        test_path = os.path.join("tests", test_file)
        print(f"[{i}/10] Running {test_file}...")
        
        try:
            result = subprocess.run(
                [sys.executable, test_path],
                capture_output=False,
                text=True,
                timeout=60
            )
            passed = result.returncode == 0
            results.append((test_file, passed))
            
            if passed:
                print(f"    ✓ PASSED")
            else:
                print(f"    ❌ FAILED (exit code: {result.returncode})")
                
        except subprocess.TimeoutExpired:
            print(f"    ❌ TIMEOUT")
            results.append((test_file, False))
        except Exception as e:
            print(f"    ❌ ERROR: {e}")
            results.append((test_file, False))
        
        print()
    
    # Summary
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed_count = sum(1 for _, p in results if p)
    total_count = len(results)
    
    for test_file, passed in results:
        status = "✓ PASSED" if passed else "❌ FAILED"
        print(f"  {status}: {test_file}")
    
    print()
    print(f"Total: {passed_count}/{total_count} tests passed")
    print("=" * 60)
    
    return passed_count == total_count


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)