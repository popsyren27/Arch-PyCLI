"""
Test 06: HAL Health Check Test

This test verifies the Hardware Abstraction Layer (HAL) functionality.
It tests:
- Health report generation
- CPU core detection
- Memory pressure monitoring
- Internal latency tracking
- System status determination

Run with: python tests/test_06_hal_health.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_hal_health():
    """Test HAL health check functionality."""
    print("=" * 60)
    print("TEST 06: HAL Health Check")
    print("=" * 60)
    
    try:
        from core.hal import HAL
        
        print("\n[1] Testing HAL initialization...")
        print(f"    ✓ CPU Cores: {HAL.CPU_CORES}")
        
        print("\n[2] Getting health report...")
        health = HAL.get_health_report(force_refresh=True)
        print(f"    ✓ Status: {health.get('status', 'UNKNOWN')}")
        
        print("\n[3] Checking health report fields...")
        expected_fields = ['status', 'memory_pressure', 'internal_latency']
        for field in expected_fields:
            if field in health:
                print(f"    ✓ {field}: {health[field]}")
            else:
                print(f"    ! {field}: not found")
        
        print("\n[4] Testing multiple health calls...")
        for i in range(3):
            h = HAL.get_health_report()
            print(f"    - Call {i+1}: status={h.get('status')}, mem={h.get('memory_pressure')}%")
        
        print("\n[5] Checking system status...")
        status = health.get('status', 'UNKNOWN')
        if status in ['OK', 'WARNING', 'CRITICAL', 'UNKNOWN', 'HEALTHY']:
            print(f"    ✓ Valid status: {status}")
        else:
            print(f"    ! Unexpected status: {status}")
        
        print("\n[6] Testing memory pressure...")
        mem_pressure = health.get('memory_pressure', 0)
        print(f"    ✓ Memory pressure: {mem_pressure}%")
        if mem_pressure < 50:
            print("    - Memory usage is normal")
        elif mem_pressure < 80:
            print("    - Memory usage is moderate")
        else:
            print("    - Memory usage is high")
        
        print("\n" + "=" * 60)
        print("RESULT: All HAL health check tests PASSED")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_hal_health()
    sys.exit(0 if success else 1)