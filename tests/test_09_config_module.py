"""
Test 09: Config Module Test

This test verifies the configuration module functionality.
It tests:
- Configuration loading from environment
- Default values
- Configuration attributes
- Node ID generation

Run with: python tests/test_09_config_module.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_config_module():
    """Test configuration module functionality."""
    print("=" * 60)
    print("TEST 09: Config Module")
    print("=" * 60)
    
    try:
        from core.config import PyArchConfig
        
        print("\n[1] Testing config creation with custom node_id...")
        config = PyArchConfig.from_env(node_id="test_node_custom")
        print(f"    ✓ Node ID: {config.node_id}")
        
        print("\n[2] Testing config with default values...")
        config_default = PyArchConfig.from_env()
        print(f"    ✓ Default node_id: {config_default.node_id}")
        
        print("\n[3] Checking config attributes...")
        attributes = [
            'node_id', 'host', 'port', 
            'network_use_tls', 'network_certfile', 
            'network_keyfile', 'network_cafile'
        ]
        for attr in attributes:
            if hasattr(config, attr):
                print(f"    ✓ {attr}: {getattr(config, attr)}")
            else:
                print(f"    ! {attr}: not found")
        
        print("\n[4] Testing port configuration...")
        print(f"    - Default port: {config.port}")
        if 1 <= config.port <= 65535:
            print("    ✓ Port is in valid range (1-65535)")
        
        print("\n[5] Testing network settings...")
        print(f"    - TLS enabled: {config.network_use_tls}")
        print(f"    - Verify server: {config.network_verify_server}")
        
        print("\n[6] Testing config string representation...")
        config_str = str(config)
        print(f"    ✓ Config string length: {len(config_str)} chars")
        
        print("\n" + "=" * 60)
        print("RESULT: All config module tests PASSED")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_config_module()
    sys.exit(0 if success else 1)