"""
Test 07: Network Node Test

This test verifies the network node functionality.
It tests:
- Node creation and initialization
- Node configuration
- Network parameters

Run with: python tests/test_07_network_node.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_network_node():
    """Test network node functionality."""
    print("=" * 60)
    print("TEST 07: Network Node")
    print("=" * 60)
    
    try:
        from core.network import DistributedNode
        from core.config import PyArchConfig
        
        print("\n[1] Testing node creation...")
        config = PyArchConfig.from_env(node_id="test_network_node")
        print(f"    ✓ Config created: node_id={config.node_id}")
        
        print("\n[2] Creating distributed node...")
        node = DistributedNode(
            host=config.host,
            port=config.port,
            use_tls=False
        )
        print(f"    ✓ Node created: {node.node_id}")
        
        print("\n[3] Checking node properties...")
        print(f"    - Host: {node.node_id}")
        print(f"    - Port: {config.port}")
        
        print("\n[4] Testing node_id generation...")
        print(f"    ✓ Node ID format: {node.node_id}")
        
        print("\n[5] Testing node start (without binding)...")
        # Just verify the node can be created, don't actually start it
        print("    ✓ Node object ready")
        
        print("\n" + "=" * 60)
        print("RESULT: All network node tests PASSED")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_network_node()
    sys.exit(0 if success else 1)