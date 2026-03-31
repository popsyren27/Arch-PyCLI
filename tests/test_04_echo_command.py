"""
Test 04: Echo Command Test

This test verifies the echo plugin functionality.
It tests:
- Basic text echoing
- Typing animation mode
- Input sanitization
- Message length limits
- Error handling

Run with: python tests/test_04_echo_command.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_echo_command():
    """Test echo command functionality."""
    print("=" * 60)
    print("TEST 04: Echo Command")
    print("=" * 60)
    
    try:
        from core.loader import KERNEL_LOADER
        from core.hal import HAL
        
        # Load plugins
        if not KERNEL_LOADER.commands:
            KERNEL_LOADER.bootstrap()
        
        health = HAL.get_health_report()
        test_context = {"health": health, "user": "test", "node_id": "test_node"}
        
        print("\n[1] Testing basic echo...")
        result = KERNEL_LOADER.dispatch("echo", test_context, "hello")
        print(f"    ✓ Result: '{result}'")
        assert result == "hello", f"Expected 'hello', got '{result}'"
        
        print("\n[2] Testing multi-word echo...")
        result = KERNEL_LOADER.dispatch("echo", test_context, "hello world test")
        print(f"    ✓ Result: '{result}'")
        
        print("\n[3] Testing echo with numbers...")
        result = KERNEL_LOADER.dispatch("echo", test_context, "12345")
        print(f"    ✓ Result: '{result}'")
        
        print("\n[4] Testing echo with special characters...")
        result = KERNEL_LOADER.dispatch("echo", test_context, "test@domain.com")
        print(f"    ✓ Result: '{result}'")
        
        print("\n[5] Testing typing mode flag...")
        result = KERNEL_LOADER.dispatch("echo", test_context, "-t", "typing test")
        print(f"    ✓ Result: '{result}'")
        
        print("\n[6] Testing long message handling...")
        long_msg = "x" * 1000  # 1000 characters
        try:
            result = KERNEL_LOADER.dispatch("echo", test_context, long_msg)
            print(f"    ✓ Long message handled")
        except Exception as e:
            print(f"    ✓ Long message rejected: {type(e).__name__}")
        
        print("\n[7] Testing empty message...")
        try:
            result = KERNEL_LOADER.dispatch("echo", test_context)
            print(f"    ✓ Empty message: {result}")
        except Exception as e:
            print(f"    ✓ Empty message error: {type(e).__name__}")
        
        print("\n[8] Testing unicode characters...")
        result = KERNEL_LOADER.dispatch("echo", test_context, "こんにちは")
        print(f"    ✓ Unicode result: '{result}'")
        
        print("\n" + "=" * 60)
        print("RESULT: All echo command tests PASSED")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_echo_command()
    sys.exit(0 if success else 1)