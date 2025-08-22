#!/usr/bin/env python3
"""
Test runner for pyPANA project
Runs all test suites and reports results
"""

import sys
import os
import importlib
import importlib.util
import traceback
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_test_file(test_file):
    """Run a single test file"""
    print(f"\n{'='*70}")
    print(f"  Running: {test_file}")
    print(f"{'='*70}")
    
    try:
        # Import the test module
        module_name = test_file.stem
        spec = importlib.util.spec_from_file_location(module_name, test_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Look for test functions or run_all_tests
        if hasattr(module, 'run_all_tests'):
            module.run_all_tests()
        else:
            # Run all functions starting with 'test_'
            test_count = 0
            for name in dir(module):
                if name.startswith('test_'):
                    func = getattr(module, name)
                    if callable(func):
                        print(f"\nRunning {name}...")
                        func()
                        test_count += 1
            
            if test_count == 0:
                print(f"  ⚠️ No test functions found in {test_file.name}")
                return False
        
        print(f"\n✅ {test_file.name} completed successfully")
        return True
        
    except Exception as e:
        print(f"\n❌ Error in {test_file.name}:")
        print(f"   {str(e)}")
        traceback.print_exc()
        return False


def main():
    """Main test runner"""
    print("\n" + "="*70)
    print("  pyPANA TEST SUITE RUNNER")
    print("="*70)
    
    # Get all test files
    tests_dir = Path(__file__).parent / "tests"
    
    # Define test groups - only essential tests
    test_groups = {
        "Core Tests": [
            "test_basic.py",
            "test_pana.py",
            "test_structure.py",
        ],
        "Phase 1 - Security": [
            "test_cert_validation.py",
            "test_phase1_validation.py",
        ],
        "Phase 2 - Integration": [
            "test_pana_eap_integration.py",
            "test_phase2_encapsulation.py",
            "test_eap_tls_integration.py",
        ],
        "Phase 3 - Enterprise": [
            "test_phase3_enterprise.py",
            "test_eap_fragmentation.py",
            "test_tls_session_cache.py",
        ],
        "Key Functionality": [
            "test_tls_keyexport.py",
            "test_revised_comprehensive.py",
        ]
    }
    
    # Track results
    total_tests = 0
    passed_tests = 0
    failed_tests = []
    
    # Run test groups
    for group_name, test_files in test_groups.items():
        print(f"\n\n{'#'*70}")
        print(f"  {group_name}")
        print(f"{'#'*70}")
        
        for test_file in test_files:
            test_path = tests_dir / test_file
            if test_path.exists():
                total_tests += 1
                if run_test_file(test_path):
                    passed_tests += 1
                else:
                    failed_tests.append(test_file)
            else:
                print(f"\n⚠️ Test file not found: {test_file}")
    
    # Print summary
    print("\n\n" + "="*70)
    print("  TEST SUMMARY")
    print("="*70)
    print(f"\nTotal test files: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {len(failed_tests)}")
    
    if failed_tests:
        print(f"\nFailed tests:")
        for test in failed_tests:
            print(f"  ❌ {test}")
        return 1
    else:
        print(f"\n✅ ALL TESTS PASSED!")
        return 0


if __name__ == "__main__":
    sys.exit(main())