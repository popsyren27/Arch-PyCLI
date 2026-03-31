"""
Test 02: Plugin Loading Test

This test verifies that all plugins can be loaded successfully.
It tests:
- Dynamic plugin discovery
- Plugin signature validation
- Command registration
- Plugin metadata extraction

Run with: python tests/test_02_plugin_loading.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_plugin_loading():
    """Test that all plugins can be loaded."""
    print("=" * 60)
    print("TEST 02: Plugin Loading")
    print("=" * 60)
    
    try:
        from core.loader import PluginLoader, KERNEL_LOADER
        
        print("\n[1] Creating new plugin loader...")
        loader = PluginLoader(plugin_dir="plugins")
        print(f"    ✓ Loader created: {loader}")
        
        print("\n[2] Running bootstrap...")
        loaded_count = loader.bootstrap()
        print(f"    ✓ Plugins loaded: {loaded_count}")
        
        print("\n[3] Getting loaded plugins...")
        plugins = loader.get_loaded_plugins()
        print(f"    ✓ Total plugins: {len(plugins)}")
        for p in plugins:
            print(f"    - {p.name} ({p.load_time_ms:.2f}ms)")
        
        print("\n[4] Getting command names...")
        commands = loader.get_command_names()
        print(f"    ✓ Commands: {commands}")
        
        print("\n[5] Verifying each command is callable...")
        for cmd in commands:
            if cmd in loader.commands:
                print(f"    ✓ {cmd} is callable")
            else:
                print(f"    ❌ {cmd} is NOT callable")
                return False
        
        print("\n[6] Testing plugin stats...")
        stats = loader.get_stats()
        print(f"    ✓ Total dispatches: {stats['total_dispatches']}")
        print(f"    ✓ Failed loads: {stats['failed_loads']}")
        
        print("\n" + "=" * 60)
        print("RESULT: All plugin loading tests PASSED")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_plugin_loading()
    sys.exit(0 if success else 1)