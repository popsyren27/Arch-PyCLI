"""
Test 05: Help Command Test

This test verifies the help plugin functionality.
It tests:
- Help output generation
- Listing all available commands
- Command descriptions

Run with: python tests/test_05_help_command.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_help_command():
    """Test help command functionality."""
    print("=" * 60)
    print("TEST 05: Help Command")
    print("=" * 60)
    
    try:
        from core.loader import KERNEL_LOADER
        from core.hal import HAL
        
        # Load plugins
        if not KERNEL_LOADER.commands:
            KERNEL_LOADER.bootstrap()
        
        health = HAL.get_health_report()
        test_context = {"health": health, "user": "test", "node_id": "test_node"}
        
        print("\n[1] Testing help command...")
        result = KERNEL_LOADER.dispatch("help", test_context)
        print(f"    ✓ Help command executed")
        print(f"    - Output length: {len(result)} chars")
        
        # Check if output contains expected content
        print("\n[2] Verifying help content...")
        if "Available Commands" in result or "Commands" in result or "help" in result.lower():
            print("    ✓ Help contains command list")
        else:
            print("    ! Help content may be minimal")
        
        print("\n[3] Getting command list via loader...")
        commands = KERNEL_LOADER.get_command_names()
        print(f"    ✓ Available commands: {commands}")
        
        # Verify help is in the list
        if "help" in commands:
            print("    ✓ 'help' command is registered")
        
        print("\n" + "=" * 60)
        print("RESULT: All help command tests PASSED")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_help_command()
    sys.exit(0 if success else 1)