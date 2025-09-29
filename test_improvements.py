#!/usr/bin/env python3
"""
Test script for the improved passbolt.py functionality.

This script demonstrates the new diagnostic and key management features
with the local Docker instance.
"""

import subprocess
import sys
import os

def run_command(cmd, description):
    """Run a command and display results."""
    print(f"\n{'='*60}")
    print(f"Testing: {description}")
    print(f"Command: {cmd}")
    print('='*60)
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print("STDOUT:")
        print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        print(f"Return code: {result.returncode}")
        return result.returncode == 0
    except Exception as e:
        print(f"Error running command: {e}")
        return False

def main():
    """Test the improved passbolt.py functionality."""
    
    # Set up environment for local Docker instance
    env_vars = {
        'PASSBOLT_URL': 'https://passbolt.local',
        'USER_ID': '10cd9426-6e69-4aec-a603-ff74b307808f',
        'KEY_FILE': 'ada_private_key.asc',  # Assuming this exists
        'PASSPHRASE': 'test123'  # Assuming this is the passphrase
    }
    
    # Set environment variables
    for key, value in env_vars.items():
        os.environ[key] = value
    
    print("Testing Improved Passbolt.py Functionality")
    print("=" * 50)
    print(f"Target: {env_vars['PASSBOLT_URL']}")
    print(f"User: ada@passbolt.com ({env_vars['USER_ID']})")
    
    # Test 1: List metadata keys
    success1 = run_command(
        "python passbolt.py list-keys --debug",
        "List available metadata keys"
    )
    
    # Test 2: Diagnose metadata access
    success2 = run_command(
        "python passbolt.py diagnose --debug",
        "Diagnose metadata key access issues"
    )
    
    # Test 3: List resources (should show improved error messages)
    success3 = run_command(
        "python passbolt.py list --debug",
        "List resources with enhanced error messages"
    )
    
    # Test 4: Decrypt resources (should show specific error messages)
    success4 = run_command(
        "python passbolt.py decrypt --debug",
        "Decrypt resources with enhanced error reporting"
    )
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print('='*60)
    print(f"List Keys: {'✅ PASS' if success1 else '❌ FAIL'}")
    print(f"Diagnose: {'✅ PASS' if success2 else '❌ FAIL'}")
    print(f"List Resources: {'✅ PASS' if success3 else '❌ FAIL'}")
    print(f"Decrypt Resources: {'✅ PASS' if success4 else '❌ FAIL'}")
    
    total_tests = 4
    passed_tests = sum([success1, success2, success3, success4])
    
    print(f"\nOverall: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 All tests passed! The improvements are working correctly.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
    
    return 0 if passed_tests == total_tests else 1

if __name__ == "__main__":
    sys.exit(main())

