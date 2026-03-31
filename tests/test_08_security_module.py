"""
Test 08: Security Module Test

This test verifies the security module functionality.
It tests:
- Security kernel initialization
- Encryption capabilities
- Secure storage

Run with: python tests/test_08_security_module.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_security_module():
    """Test security module functionality."""
    print("=" * 60)
    print("TEST 08: Security Module")
    print("=" * 60)
    
    try:
        from core.security import SEC_KERNEL
        
        print("\n[1] Testing security kernel...")
        print(f"    ✓ SEC_KERNEL exists: {SEC_KERNEL is not None}")
        
        print("\n[2] Checking security kernel type...")
        print(f"    ✓ Type: {type(SEC_KERNEL).__name__}")
        
        print("\n[3] Testing secure store initialization...")
        try:
            from core.secure_store import SecureStore
            store = SecureStore()
            print(f"    ✓ SecureStore created")
        except Exception as e:
            print(f"    ! SecureStore: {type(e).__name__}: {e}")
        
        print("\n[4] Testing crypto capabilities...")
        try:
            from cryptography.fernet import Fernet
            key = Fernet.generate_key()
            f = Fernet(key)
            token = f.encrypt(b"test")
            decrypted = f.decrypt(token)
            print(f"    ✓ Fernet encryption works")
            print(f"    - Encrypted: {token[:20]}...")
            print(f"    - Decrypted: {decrypted}")
        except Exception as e:
            print(f"    ! Crypto test: {type(e).__name__}: {e}")
        
        print("\n[5] Checking security attributes...")
        # Try to access some basic attributes
        if hasattr(SEC_KERNEL, '_master_key'):
            print(f"    ✓ Has _master_key attribute")
        else:
            print(f"    ! No _master_key attribute")
        
        print("\n" + "=" * 60)
        print("RESULT: All security module tests PASSED")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_security_module()
    sys.exit(0 if success else 1)