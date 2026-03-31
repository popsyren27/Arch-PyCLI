"""
Test 01: Basic Boot Sequence Test

This test verifies that the CLI can boot up without crashing.
It tests:
- Configuration loading
- HAL (Hardware Abstraction Layer) initialization
- Plugin loader bootstrap
- Basic system health

Run with: python tests/test_01_basic_boot.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_basic_boot():
    """Test that the kernel can boot up."""
    print("=" * 60)
    print("TEST 01: Basic Boot Sequence")
    print("=" * 60)
    
    try:
        # Import required modules
        from core.config import PyArchConfig
        from core.hal import HAL
        from core.loader import KERNEL_LOADER
        from core.security import SEC_KERNEL
        
        print("\n[1] Testing configuration...")
        config = PyArchConfig.from_env(node_id="test_node_001")
        print(f"    ✓ Config loaded: node_id={config.node_id}")
        
        print("\n[2] Testing HAL (Hardware Abstraction Layer)...")
        health = HAL.get_health_report(force_refresh=True)
        print(f"    ✓ HAL health: {health.get('status', 'UNKNOWN')}")
        print(f"    - CPU Cores: {HAL.CPU_CORES}")
        print(f"    - Memory Pressure: {health.get('memory_pressure', 0)}%")
        
        print("\n[3] Testing plugin loader bootstrap...")
        loaded_count = KERNEL_LOADER.bootstrap()
        print(f"    ✓ Plugins loaded: {loaded_count}")
        
        commands = KERNEL_LOADER.get_command_names()
        print(f"    - Available commands: {commands}")
        
        print("\n[4] Testing command dispatch...")
        test_context = {"health": health, "user": "test", "node_id": "test_node_001"}
        
        # Try to dispatch 'help' command
        result = KERNEL_LOADER.dispatch("help", test_context)
        print(f"    ✓ Help command result: {result[:50]}...")
        
        print("\n" + "=" * 60)
        print("RESULT: All basic boot tests PASSED")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_basic_boot()
    sys.exit(0 if success else 1)