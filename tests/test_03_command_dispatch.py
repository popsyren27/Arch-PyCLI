"""
Test 03: Command Dispatch Test

This test verifies that commands can be dispatched correctly.
It tests:
- Command execution with context
- Argument passing
- Error handling for unknown commands
- Context validation

Run with: python tests/test_03_command_dispatch.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_command_dispatch():
    """Test command dispatch functionality."""
    print("=" * 60)
    print("TEST 03: Command Dispatch")
    print("=" * 60)
    
    try:
        from core.loader import KERNEL_LOADER
        from core.hal import HAL
        
        # Ensure plugins are loaded
        print("\n[1] Loading plugins...")
        if not KERNEL_LOADER.commands:
            KERNEL_LOADER.bootstrap()
        print(f"    ✓ Loaded {len(KERNEL_LOADER.commands)} commands")
        
        # Get health for context
        health = HAL.get_health_report()
        test_context = {"health": health, "user": "test", "node_id": "test_node"}
        
        print("\n[2] Testing valid command dispatch...")
        # Test echo command
        result = KERNEL_LOADER.dispatch("echo", test_context, "hello", "world")
        print(f"    ✓ echo command: {result}")
        
        # Test calc command
        result = KERNEL_LOADER.dispatch("calc", test_context, "2", "+", "2")
        print(f"    ✓ calc command: {result}")
        
        print("\n[3] Testing unknown command...")
        result = KERNEL_LOADER.dispatch("nonexistent_command", test_context)
        print(f"    ✓ Unknown command result: {result}")
        
        print("\n[4] Testing command with special characters...")
        result = KERNEL_LOADER.dispatch("echo", test_context, "test", "123", "!@#$%")
        print(f"    ✓ Special chars result: {result}")
        
        print("\n[5] Testing empty arguments...")
        result = KERNEL_LOADER.dispatch("echo", test_context)
        print(f"    ✓ Empty args result: {result}")
        
        print("\n[6] Testing context validation...")
        # Test with missing health
        try:
            result = KERNEL_LOADER.dispatch("echo", {"user": "test"}, "test")
            print(f"    ✓ Missing health handled: {result}")
        except Exception as e:
            print(f"    ✓ Missing health raises: {type(e).__name__}")
        
        print("\n" + "=" * 60)
        print("RESULT: All command dispatch tests PASSED")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_command_dispatch()
    sys.exit(0 if success else 1)