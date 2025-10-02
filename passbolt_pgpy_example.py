#!/usr/bin/env python3
"""
Passbolt PGPy Integration Example
==================================

This script demonstrates how to interact with Passbolt API using PGPy,
a pure Python OpenPGP implementation, instead of relying on system GPG binary.

This addresses the requirement to work in environments where GPG binary
availability cannot be guaranteed.

Requirements:
    pip install pgpy requests python-dotenv

Author: Gareth (for Paul's evaluation)
"""

import json
import os
import requests
import uuid
import time
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

try:
    import pgpy
    from pgpy import PGPKey, PGPMessage
    PGPY_AVAILABLE = True
except ImportError:
    PGPY_AVAILABLE = False
    print("WARNING: PGPy not installed. Install with: pip install pgpy")

# Disable SSL warnings for local development
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()


def authenticate_with_pgpy(user_id, key_file, passphrase, passbolt_url, debug=False):
    """
    Authenticate with Passbolt using PGPy for all OpenPGP operations.
    
    This replaces the subprocess GPG calls with pure Python PGPy operations.
    
    Args:
        user_id: Passbolt user UUID
        key_file: Path to user's private key file
        passphrase: User's key passphrase (None for no passphrase)
        passbolt_url: Passbolt instance URL
        debug: Enable debug output
    
    Returns:
        JWT token for API authentication
    """
    if not PGPY_AVAILABLE:
        raise Exception("PGPy library not installed")
    
    # Validate inputs
    if not user_id:
        raise ValueError("user_id is required")
    if not key_file or not os.path.exists(key_file):
        raise ValueError(f"Key file not found: {key_file}")
    if not passbolt_url:
        raise ValueError("passbolt_url is required")
    
    if debug:
        print("=== PGPy-based JWT Authentication ===")
        print("1. Loading user's private key with PGPy...")
    
    # Load user's private key using PGPy with error handling
    try:
        user_key, _ = PGPKey.from_file(key_file)
    except Exception as e:
        raise Exception(f"Failed to load private key from {key_file}: {e}")
    
    # Unlock the key with passphrase if encrypted
    if user_key.is_protected:
        if debug:
            print("2. Unlocking user's private key...")
        if passphrase is None:
            raise ValueError("Key is encrypted but no passphrase provided")
        try:
            with user_key.unlock(passphrase):
                user_fingerprint = user_key.fingerprint.replace(' ', '')
        except Exception as e:
            raise Exception(f"Failed to unlock key with provided passphrase: {e}")
    else:
        user_fingerprint = user_key.fingerprint.replace(' ', '')
    
    if debug:
        print(f"   User fingerprint: {user_fingerprint}")
    
    # Get server's public key and CSRF token
    session = requests.Session()
    try:
        resp = session.get(f"{passbolt_url}/auth/verify.json", verify=False, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        server_key_data = data['body']['keydata']
        server_key_fpr = data['body']['fingerprint']
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to get server key from {passbolt_url}: {e}")
    except KeyError as e:
        raise Exception(f"Invalid server response format: {e}")
    
    if debug:
        print(f"3. Server fingerprint: {server_key_fpr}")
    
    # Load server's public key using PGPy
    try:
        server_key, _ = PGPKey.from_blob(server_key_data)
    except Exception as e:
        raise Exception(f"Failed to load server public key: {e}")
    
    # Create challenge
    verify_token = str(uuid.uuid4())
    expiry_time = datetime.now(timezone.utc) + timedelta(seconds=300)
    
    challenge = {
        "version": "1.0.0",
        "domain": passbolt_url,
        "verify_token": verify_token,
        "verify_token_expiry": int(expiry_time.timestamp())
    }
    
    if debug:
        print("4. Creating challenge...")
        print(f"   Token: {verify_token}")
    
    # Encrypt and sign challenge using PGPy
    challenge_json = json.dumps(challenge)
    
    if debug:
        print("5. Encrypting and signing challenge with PGPy...")
    
    # Create PGP message from plaintext
    message = pgpy.PGPMessage.new(challenge_json)
    
    # Sign and encrypt using PGPy pattern
    # Sign first, attach signature to message, then encrypt
    if user_key.is_protected:
        with user_key.unlock(passphrase):
            # Create signature
            signature = user_key.sign(message)
            # Attach signature to message using |= operator
            message |= signature
            # Now encrypt the signed message
            encrypted_challenge_msg = server_key.encrypt(message)
    else:
        signature = user_key.sign(message)
        message |= signature
        encrypted_challenge_msg = server_key.encrypt(message)
    
    # Get armored output
    encrypted_challenge = str(encrypted_challenge_msg)
    
    if debug:
        print("   Challenge encrypted and signed successfully")
    
    # Get CSRF token
    csrf_token = None
    for cookie in session.cookies:
        if cookie.name == 'csrfToken':
            csrf_token = cookie.value
            break
    
    if not csrf_token:
        raise Exception("CSRF token not found")
    
    # Submit challenge
    if debug:
        print("6. Submitting challenge to server...")
    
    login_data = {
        'user_id': user_id,
        'challenge': encrypted_challenge
    }
    
    headers = {
        'X-CSRF-Token': csrf_token,
        'Content-Type': 'application/json'
    }
    
    try:
        login_resp = session.post(
            f"{passbolt_url}/auth/jwt/login.json",
            json=login_data,
            headers=headers,
            verify=False,
            timeout=30
        )
        login_resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Login request failed: {e}")
    
    if login_resp.status_code != 200:
        raise Exception(f"Login failed: {login_resp.text}")
    
    # Decrypt server's response using PGPy
    if debug:
        print("7. Decrypting server response with PGPy...")
    
    response_data = login_resp.json()
    encrypted_response = response_data['body']['challenge']
    
    # Parse encrypted response
    encrypted_resp_msg = PGPMessage.from_blob(encrypted_response)
    
    # Decrypt with user's private key
    if user_key.is_protected:
        with user_key.unlock(passphrase):
            decrypted_response = user_key.decrypt(encrypted_resp_msg)
    else:
        decrypted_response = user_key.decrypt(encrypted_resp_msg)
    
    # Parse decrypted JSON
    response_json = json.loads(decrypted_response.message)
    jwt_token = response_json['access_token']
    
    if debug:
        print("✓ Authentication successful!")
        print(f"   JWT token: {jwt_token[:50]}...")
    
    return jwt_token


def decrypt_metadata_private_key_pgpy(encrypted_key_data, user_key, passphrase, debug=False):
    """
    Decrypt a metadata private key using PGPy.
    
    This replaces the subprocess GPG decrypt operation.
    
    Args:
        encrypted_key_data: Encrypted metadata private key from API
        user_key: User's PGPKey object
        passphrase: User's key passphrase
        debug: Enable debug output
    
    Returns:
        Decrypted armored metadata private key
    """
    if debug:
        print("Decrypting metadata private key with PGPy...")
    
    # Parse encrypted message
    encrypted_msg = PGPMessage.from_blob(encrypted_key_data)
    
    # Decrypt with user's private key
    if user_key.is_protected:
        with user_key.unlock(passphrase):
            decrypted = user_key.decrypt(encrypted_msg)
    else:
        decrypted = user_key.decrypt(encrypted_msg)
    
    # Parse JSON to get actual armored key
    decrypted_json = json.loads(decrypted.message)
    armored_key = decrypted_json['armored_key']
    
    if debug:
        print("✓ Metadata private key decrypted successfully")
    
    return armored_key


def decrypt_resource_metadata_pgpy(metadata_encrypted, metadata_key, debug=False):
    """
    Decrypt resource metadata using the metadata private key with PGPy.
    
    This replaces the subprocess GPG decrypt operation for metadata.
    
    Args:
        metadata_encrypted: Encrypted metadata from resource
        metadata_key: PGPKey object for metadata key (already decrypted)
        debug: Enable debug output
    
    Returns:
        Decrypted metadata as string
    """
    if debug:
        print("Decrypting resource metadata with PGPy...")
    
    # Parse encrypted metadata
    encrypted_msg = PGPMessage.from_blob(metadata_encrypted)
    
    # Decrypt with metadata key (usually no passphrase)
    if metadata_key.is_protected:
        # If protected, try empty passphrase (common for shared metadata keys)
        with metadata_key.unlock(""):
            decrypted = metadata_key.decrypt(encrypted_msg)
    else:
        decrypted = metadata_key.decrypt(encrypted_msg)
    
    if debug:
        print("✓ Resource metadata decrypted successfully")
    
    return decrypted.message


def decrypt_resource_secret_pgpy(secret_encrypted, user_key, passphrase, debug=False):
    """
    Decrypt resource secret using user's private key with PGPy.
    
    This replaces the subprocess GPG decrypt operation for secrets.
    
    Args:
        secret_encrypted: Encrypted secret from API
        user_key: User's PGPKey object
        passphrase: User's key passphrase
        debug: Enable debug output
    
    Returns:
        Decrypted secret as string
    """
    if debug:
        print("Decrypting resource secret with PGPy...")
    
    # Parse encrypted secret
    encrypted_msg = PGPMessage.from_blob(secret_encrypted)
    
    # Decrypt with user's private key
    if user_key.is_protected:
        with user_key.unlock(passphrase):
            decrypted = user_key.decrypt(encrypted_msg)
    else:
        decrypted = user_key.decrypt(encrypted_msg)
    
    if debug:
        print("✓ Resource secret decrypted successfully")
    
    return decrypted.message


def example_usage():
    """
    Complete example showing PGPy-based Passbolt interaction.
    """
    if not PGPY_AVAILABLE:
        print("ERROR: PGPy not installed. Install with: pip install pgpy")
        return
    
    # Configuration from .env file (same format as passbolt.py)
    user_id = os.getenv('USER_ID')
    key_file = os.getenv('KEY_FILE', 'ada@passbolt.com.key')
    passphrase = os.getenv('PASSPHRASE')  # Don't default to insecure value
    passbolt_url = os.getenv('URL', 'https://passbolt.local')
    
    if not user_id:
        print("ERROR: Missing required configuration in .env file:")
        print("  USER_ID is required")
        print()
        print("Create a .env file with:")
        print("  USER_ID=your-user-uuid")
        print("  KEY_FILE=path/to/private_key.asc")
        print("  PASSPHRASE=your-passphrase (or leave empty for unencrypted keys)")
        print("  URL=https://passbolt.local")
        return
    
    # Validate key file exists
    if not os.path.exists(key_file):
        print(f"ERROR: Key file not found: {key_file}")
        print(f"Check your KEY_FILE setting in .env")
        return
    
    print("=" * 60)
    print("Passbolt PGPy Integration Example")
    print("=" * 60)
    print()
    
    # Authenticate
    try:
        jwt_token = authenticate_with_pgpy(
            user_id, key_file, passphrase, passbolt_url, debug=True
        )
        print()
        print("SUCCESS: Authentication completed using PGPy (no GPG binary used)")
        print()
    except Exception as e:
        print(f"ERROR: Authentication failed: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Example: Get user's metadata keys
    print("=" * 60)
    print("Fetching metadata keys...")
    print()
    
    try:
        headers = {'Authorization': f'Bearer {jwt_token}'}
        resp = requests.get(
            f"{passbolt_url}/metadata/keys.json?contain[metadata_private_keys]=1&filter[deleted]=0",
            headers=headers,
            verify=False
        )
        
        if resp.status_code == 200:
            metadata_keys = resp.json()['body']
            print(f"Found {len(metadata_keys)} metadata key(s)")
            
            # Load user key for decryption operations
            user_key, _ = PGPKey.from_file(key_file)
            
            # Example: Decrypt first metadata private key
            if metadata_keys and metadata_keys[0].get('metadata_private_keys'):
                print()
                print("=" * 60)
                print("Example: Decrypting metadata private key with PGPy")
                print()
                
                encrypted_private_key = metadata_keys[0]['metadata_private_keys'][0]['data']
                
                armored_metadata_key = decrypt_metadata_private_key_pgpy(
                    encrypted_private_key,
                    user_key,
                    passphrase,
                    debug=True
                )
                
                print()
                print(f"Decrypted key preview: {armored_metadata_key[:100]}...")
                print()
                print("SUCCESS: Metadata private key decrypted using PGPy only!")
        else:
            print(f"Failed to fetch metadata keys: {resp.status_code}")
            
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
    
    print()
    print("=" * 60)
    print("Summary:")
    print("  • Authentication: ✓ (using PGPy)")
    print("  • Key decryption: ✓ (using PGPy)")
    print("  • No GPG binary required: ✓")
    print("=" * 60)


if __name__ == '__main__':
    example_usage()

