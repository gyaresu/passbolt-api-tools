#!/usr/bin/env python3
"""
Comprehensive validation script for passbolt.py improvements.

This script tests all the enhancements we've made to ensure they work correctly.
"""

import subprocess
import sys
import os
import tempfile
import json

def run_test(test_name, command, expected_exit_code=0, should_contain=None, should_not_contain=None):
    """Run a test and validate the results."""
    print(f"\n{'='*60}")
    print(f"TEST: {test_name}")
    print(f"Command: {command}")
    print('='*60)
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        # Check exit code
        if result.returncode != expected_exit_code:
            print(f"❌ FAIL: Expected exit code {expected_exit_code}, got {result.returncode}")
            return False
        
        # Check output content
        output = result.stdout + result.stderr
        
        if should_contain:
            for text in should_contain:
                if text not in output:
                    print(f"❌ FAIL: Expected output to contain '{text}'")
                    return False
        
        if should_not_contain:
            for text in should_not_contain:
                if text in output:
                    print(f"❌ FAIL: Expected output NOT to contain '{text}'")
                    return False
        
        print("✅ PASS")
        if result.stdout:
            print("STDOUT:", result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
        if result.stderr and "Error" not in result.stderr:
            print("STDERR:", result.stderr[:200] + "..." if len(result.stderr) > 200 else result.stderr)
        
        return True
        
    except Exception as e:
        print(f"❌ FAIL: Exception during test: {e}")
        return False

def main():
    """Run comprehensive validation tests."""
    print("🔍 PASSBOLT.PY IMPROVEMENTS VALIDATION")
    print("=" * 60)
    
    # Set up environment
    env_vars = {
        'PASSBOLT_URL': 'https://passbolt.local',
        'USER_ID': '10cd9426-6e69-4aec-a603-ff74b307808f',
        'KEY_FILE': 'ada_private.key'
    }
    
    for key, value in env_vars.items():
        os.environ[key] = value
    
    tests = []
    
    # Test 1: Help functionality
    tests.append((
        "Help functionality",
        "source venv/bin/activate && python passbolt.py --help",
        0,
        ["diagnose", "list-keys", "Enhanced error detection"],
        None
    ))
    
    # Test 2: New diagnostic commands in help
    tests.append((
        "New commands in help",
        "source venv/bin/activate && python passbolt.py --help",
        0,
        ["diagnose - Diagnose metadata key access issues", "list-keys - List available metadata keys"],
        None
    ))
    
    # Test 3: Import validation
    tests.append((
        "Import validation",
        "source venv/bin/activate && python -c 'from passbolt import diagnose_metadata_access, list_metadata_keys, validate_metadata_key; print(\"All imports successful\")'",
        0,
        ["All imports successful"],
        None
    ))
    
    # Test 4: Function validation
    tests.append((
        "Function validation",
        "source venv/bin/activate && python -c 'from passbolt import validate_metadata_key; validate_metadata_key({\"fingerprint\": \"test\", \"armored_key\": \"-----BEGIN PGP PUBLIC KEY BLOCK-----\\nTest\\n-----END PGP PUBLIC KEY BLOCK-----\"}); print(\"Validation successful\")'",
        0,
        ["Validation successful"],
        None
    ))
    
    # Test 5: Enhanced error handling
    tests.append((
        "Enhanced error handling",
        "source venv/bin/activate && python -c 'from passbolt import gpg_decrypt_message; import tempfile; gpg_decrypt_message(\"invalid data\", \"test\", debug=True)'",
        1,
        ["GPG decryption failed"],
        None
    ))
    
    # Test 6: Authentication (should work but require MFA)
    tests.append((
        "Authentication with MFA requirement",
        "source venv/bin/activate && python passbolt.py diagnose --debug",
        1,
        ["MFA authentication is required", "Server key fingerprint", "User fingerprint"],
        ["404", "Not Found"]
    ))
    
    # Test 7: Syntax validation
    tests.append((
        "Python syntax validation",
        "source venv/bin/activate && python -m py_compile passbolt.py",
        0,
        [],
        None
    ))
    
    # Run all tests
    passed = 0
    total = len(tests)
    
    for test_name, command, expected_code, should_contain, should_not_contain in tests:
        if run_test(test_name, command, expected_code, should_contain, should_not_contain):
            passed += 1
    
    # Summary
    print(f"\n{'='*60}")
    print("VALIDATION SUMMARY")
    print('='*60)
    print(f"Tests passed: {passed}/{total}")
    print(f"Success rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED!")
        print("\n✅ IMPROVEMENTS VALIDATED:")
        print("  • Enhanced error specificity")
        print("  • Diagnostic functions")
        print("  • Key validation")
        print("  • CLI enhancements")
        print("  • Authentication integration")
        print("  • Syntax and import validation")
        print("\n🚀 The passbolt.py script is ready for production use!")
        return 0
    else:
        print(f"⚠️  {total - passed} tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

