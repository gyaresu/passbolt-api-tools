#!/usr/bin/env python3
"""
Passbolt JWT Authentication Client

A command-line tool for authenticating with the Passbolt API using JWT tokens.
Supports both local key files and GPG keyring keys.

Authentication Flow:
1. Get CSRF token and server public key
2. Create and encrypt authentication challenge
3. Submit challenge to server
4. Decrypt server response
5. Extract JWT tokens

Usage:
    python3 jwt_auth_with_api_test.py --url URL --user-id ID [options]

Required Arguments:
    --url URL                 Passbolt server URL
    --user-id ID              Your Passbolt user ID
    --key-file FILE           Path to GPG private key file
    --fingerprint FPR         GPG key fingerprint to use from keyring

Optional Arguments:
    --passphrase PASS        Passphrase for the GPG key
    --output FILE            Save tokens to a JSON file
    --full-token            Display the full access token
    --bruno-format          Output token in Bruno-compatible format
    --curl-format           Output token in curl command format
    --test                  Test API access after authentication
    --debug                 Enable debug output
    --no-cleanup            Don't remove temporary files
    --insecure              Disable SSL certificate verification

Examples:
    # Using a key file
    python3 jwt_auth_with_api_test.py --url https://passbolt.example.com \
        --user-id YOUR_USER_ID --key-file /path/to/private.key \
        --passphrase "your-passphrase" --insecure

    # Using a key from GPG keyring
    python3 jwt_auth_with_api_test.py --url https://passbolt.example.com \
        --user-id YOUR_USER_ID --fingerprint "YOUR_KEY_FINGERPRINT" \
        --passphrase "your-passphrase" --insecure

    # Test API access after authentication
    python3 jwt_auth_with_api_test.py --url https://passbolt.example.com \
        --user-id YOUR_USER_ID --fingerprint "YOUR_KEY_FINGERPRINT" \
        --passphrase "your-passphrase" --insecure --test

Security Notes:
- Always use HTTPS for the Passbolt server URL
- Keep your GPG private key secure
- Use a strong passphrase for your GPG key
- Don't share your tokens or passphrases
- Clean up temporary files after use
"""

import os
import sys
import json
import uuid
import time
import argparse
import subprocess
import requests
import tempfile
import atexit
import signal
import shutil
import base64
from getpass import getpass


# =============================================================================
# GLOBAL VARIABLES
# =============================================================================
TEMP_FILES = []  # List of temporary files to clean up
DEBUG = False    # Debug mode flag
temp_gpg_home = None  # Temporary GPG home directory


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def debug_print(message):
    """Print debug messages if debug mode is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}")


def print_file_contents(file_path, max_length=500):
    """Print the contents of a file with a maximum length."""
    if not os.path.exists(file_path):
        debug_print(f"File does not exist: {file_path}")
        return
    
    try:
        with open(file_path, "r") as f:
            content = f.read()
        
        if len(content) > max_length:
            debug_print(f"Contents of {file_path} (truncated to {max_length} chars):")
            debug_print(content[:max_length] + "...")
        else:
            debug_print(f"Contents of {file_path}:")
            debug_print(content)
    except Exception as e:
        debug_print(f"Error reading file {file_path}: {e}")


def cleanup_files():
    """Clean up temporary files created during script execution."""
    global temp_gpg_home
    
    if args.no_cleanup:
        print("\n[*] Skipping cleanup as requested.")
        if temp_gpg_home:
            print(f"[*] Temporary GPG home directory: {temp_gpg_home}")
        if TEMP_FILES:
            print(f"[*] Temporary files: {', '.join(TEMP_FILES)}")
        return
    
    print("\n[*] Cleaning up temporary files...")
    
    # Remove temporary files
    for file_path in TEMP_FILES:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                debug_print(f"Removed: {file_path}")
            except Exception as e:
                debug_print(f"Failed to remove {file_path}: {e}")
    
    # Remove temporary GPG home directory if it exists
    if temp_gpg_home and os.path.exists(temp_gpg_home):
        try:
            shutil.rmtree(temp_gpg_home)
            debug_print(f"Removed temporary GPG home: {temp_gpg_home}")
        except Exception as e:
            debug_print(f"Failed to remove temporary GPG home: {e}")


def signal_handler(sig, frame):
    """Handle interruption signals."""
    print(f"\n[!] Received signal {sig}, exiting...")
    cleanup_files()
    sys.exit(1)


def setup_temporary_gpg_home():
    """Create a temporary GPG home directory to isolate operations."""
    global temp_gpg_home
    temp_gpg_home = tempfile.mkdtemp(prefix="tmp_gpg_home_")
    debug_print(f"Created temporary GPG home directory: {temp_gpg_home}")
    return temp_gpg_home


def get_gpg_env():
    """Return environment variables for GPG with temporary home."""
    env = os.environ.copy()
    if temp_gpg_home:
        env["GNUPGHOME"] = temp_gpg_home
    return env


def import_key(key_path):
    """Import a GPG key from file and return its fingerprint."""
    if not os.path.exists(key_path):
        print(f"[!] Error: Key file not found: {key_path}")
        sys.exit(1)
    
    # Import the key
    import_result = subprocess.run(
        ["gpg", "--batch", "--yes", "--import", key_path],
        env=get_gpg_env(),
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        text=True
    )
    
    debug_print(f"Import stdout: {import_result.stdout}")
    debug_print(f"Import stderr: {import_result.stderr}")
    
    if import_result.returncode != 0:
        print(f"[!] Error: Failed to import key: {import_result.stderr}")
        sys.exit(1)
    
    # Get the key fingerprint
    if args.key_file:
        list_result = subprocess.run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            env=get_gpg_env(),
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        
        # Parse the output to extract the fingerprint
        fingerprint = None
        for line in list_result.stdout.splitlines():
            if line.startswith("fpr:"):
                fingerprint = line.split(":")[9]
                break
        
        if not fingerprint:
            print("[!] Error: Could not extract fingerprint from imported key")
            sys.exit(1)
        
        debug_print(f"Extracted fingerprint from key: {fingerprint}")
        return fingerprint
    
    return None


def check_gpg_key_validity(fingerprint):
    """Check if the GPG key is valid and can be used for signing."""
    debug_print(f"Checking GPG key validity for fingerprint: {fingerprint}")
    
    # Check if key exists
    list_result = subprocess.run(
        ["gpg", "--list-keys", fingerprint],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    
    if list_result.returncode != 0:
        print(f"[!] Error: GPG key not found: {list_result.stderr}")
        print("\nAvailable keys in your keyring:")
        subprocess.run(["gpg", "--list-keys", "--keyid-format", "long"])
        print("\nPlease use one of the above key fingerprints.")
        sys.exit(1)
    
    debug_print(f"GPG key info: {list_result.stdout}")
    
    # Check if key can be used for signing
    check_result = subprocess.run(
        ["gpg", "--list-secret-keys", fingerprint],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    
    if check_result.returncode != 0:
        print(f"[!] Error: GPG secret key not found: {check_result.stderr}")
        print("\nAvailable secret keys in your keyring:")
        subprocess.run(["gpg", "--list-secret-keys", "--keyid-format", "long"])
        print("\nPlease use one of the above key fingerprints.")
        sys.exit(1)
    
    debug_print(f"GPG secret key info: {check_result.stdout}")
    return True


def get_server_key(session, url):
    """Get the server's public key and CSRF token."""
    print("\n[*] Step 1: Getting CSRF token and server public key...")
    
    try:
        response = session.get(f"{url}/auth/verify.json", verify=not args.insecure)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[!] Error connecting to Passbolt server: {e}")
        sys.exit(1)
    
    debug_print(f"Server response headers: {response.headers}")
    
    try:
        data = response.json()
        debug_print(f"Server response data: {json.dumps(data, indent=2)}")
    except json.JSONDecodeError:
        print("[!] Error: Server did not return valid JSON")
        debug_print(f"Raw response: {response.text}")
        sys.exit(1)
    
    # Get CSRF token from cookies
    csrf_token = None
    for cookie in session.cookies:
        if cookie.name == "csrfToken":
            csrf_token = cookie.value
            break
    
    if not csrf_token:
        print("[!] Error: Failed to get CSRF token")
        sys.exit(1)
    
    print(f"[+] Got CSRF token: {csrf_token[:20]}...")
    
    # Extract server key
    try:
        server_key_data = data["body"]["keydata"]
        server_key_fpr = data["body"]["fingerprint"]
    except KeyError:
        print("[!] Error: Server response does not contain the expected key data")
        debug_print(f"Response data: {json.dumps(data, indent=2)}")
        sys.exit(1)
    
    print(f"[+] Got server public key (fingerprint: {server_key_fpr})")
    
    # Save server key to file and import
    server_key_path = os.path.abspath("serverkey.asc")
    TEMP_FILES.append(server_key_path)
    
    with open(server_key_path, "w") as f:
        f.write(server_key_data)
    
    import_result = subprocess.run(
        ["gpg", "--batch", "--yes", "--import", server_key_path],
        env=get_gpg_env(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    
    debug_print(f"Import stdout: {import_result.stdout}")
    debug_print(f"Import stderr: {import_result.stderr}")
    
    print("[+] Server public key imported successfully")
    return csrf_token, server_key_fpr


def create_challenge(server_key_fpr, fingerprint):
    """Create and encrypt an authentication challenge."""
    print("\n[*] Step 2: Creating authentication challenge...")
    
    # Create UUID token
    challenge_token = str(uuid.uuid4()).lower()
    debug_print(f"Using verify_token: {challenge_token}")
    
    # Create challenge payload
    challenge_payload = {
        "version": "1.0.0",
        "domain": args.url,
        "verify_token": challenge_token,
        "verify_token_expiry": int(time.time()) + 300
    }
    
    # Write challenge as compact JSON (no whitespace)
    challenge_path = os.path.abspath("challenge.json")
    TEMP_FILES.append(challenge_path)
    
    with open(challenge_path, "w") as f:
        json.dump(challenge_payload, f, separators=(',', ':'))
    
    print("[+] Challenge created")
    debug_print(f"Challenge payload: {json.dumps(challenge_payload, indent=2)}")
    
    # Encrypt challenge with server's public key
    encrypted_path = os.path.abspath("challenge.asc")
    TEMP_FILES.append(encrypted_path)
    
    print("[*] Signing and encrypting challenge...")
    
    # One-step sign and encrypt with passphrase
    gpg_command = [
        "gpg", "--batch", "--yes", "--verbose",
        "--trust-model", "always",
        "--sign", "--encrypt", "--armor",
        "--recipient", server_key_fpr,
        "--local-user", fingerprint,
        "--output", encrypted_path, challenge_path
    ]
    
    # Add passphrase if provided
    if args.passphrase:
        gpg_command.insert(4, "--pinentry-mode")
        gpg_command.insert(5, "loopback")
        gpg_command.insert(6, "--passphrase")
        gpg_command.insert(7, args.passphrase)
    
    encrypt_result = subprocess.run(
        gpg_command,
        env=get_gpg_env(),
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        text=True
    )
    
    debug_print(f"Sign+Encrypt stdout: {encrypt_result.stdout}")
    debug_print(f"Sign+Encrypt stderr: {encrypt_result.stderr}")
    
    if encrypt_result.returncode != 0:
        print(f"[!] Error: Sign+Encrypt failed: {encrypt_result.stderr}")
        sys.exit(1)
    
    print("[+] Challenge signed and encrypted")
    return challenge_path, encrypted_path


def submit_challenge(session, url, csrf_token, encrypted_path, fingerprint):
    """Submit the encrypted challenge to the server."""
    print("\n[*] Step 3: Submitting challenge to server...")
    
    # Read encrypted challenge
    try:
        with open(encrypted_path, "r") as f:
            encrypted_challenge = f.read()
            
        # Validate that we have a proper PGP message
        if not encrypted_challenge.startswith("-----BEGIN PGP MESSAGE-----"):
            print("[!] Error: Encrypted challenge is not in the expected PGP format")
            debug_print(f"Challenge data: {encrypted_challenge[:100]}...")
            sys.exit(1)
    except Exception as e:
        print(f"[!] Error reading encrypted challenge: {e}")
        sys.exit(1)
    
    debug_print(f"Challenge length: {len(encrypted_challenge)} characters")
    
    # Create request body
    request_body = {
        "user_id": args.user_id,
        "challenge": encrypted_challenge
    }
    
    debug_print(f"Login request data: {json.dumps(request_body, indent=2)}")
    debug_print(f"CSRF token: {csrf_token}")
    
    print("[*] Sending JWT login request...")
    
    # Send request
    try:
        response = session.post(
            f"{url}/auth/jwt/login.json",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf_token
            },
            json=request_body,
            verify=not args.insecure
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[!] Error sending JWT login request: {e}")
        if hasattr(e, 'response') and e.response is not None:
            debug_print(f"Response status code: {e.response.status_code}")
            debug_print(f"Response headers: {e.response.headers}")
            debug_print(f"Response content: {e.response.text}")
        sys.exit(1)
    
    debug_print(f"JWT response status code: {response.status_code}")
    debug_print(f"JWT response headers: {response.headers}")
    
    try:
        data = response.json()
        debug_print(f"JWT response data: {json.dumps(data, indent=2)}")
    except json.JSONDecodeError:
        print("[!] Error: Server did not return valid JSON")
        debug_print(f"Raw response: {response.text}")
        sys.exit(1)
    
    # Check if authentication was successful
    if data.get("header", {}).get("status") != "success":
        print("[!] Authentication failed")
        error_message = data.get("header", {}).get("message", "Unknown error")
        print(f"[!] Error message: {error_message}")
        sys.exit(1)
    
    print("[+] Authentication successful")
    
    # Extract encrypted response
    try:
        encrypted_response = data["body"]["challenge"]
        if not encrypted_response.startswith("-----BEGIN PGP MESSAGE-----"):
            print("[!] Error: Server response is not a valid PGP message")
            debug_print(f"Response data: {encrypted_response[:100]}...")
            sys.exit(1)
    except KeyError:
        print("[!] Error: Server response does not contain the expected challenge")
        debug_print(f"Response data: {json.dumps(data, indent=2)}")
        sys.exit(1)
    
    print("[+] Got encrypted response from server")
    return encrypted_response


def decrypt_response(encrypted_response):
    """Decrypt and verify the server's response."""
    print("\n[*] Step 4: Decrypting server response...")
    
    # Save encrypted response
    challenge_response_path = os.path.abspath("challenge_response.asc")
    TEMP_FILES.append(challenge_response_path)
    
    with open(challenge_response_path, "w") as f:
        f.write(encrypted_response)
    
    print("[+] Saved encrypted response to file")
    
    # Decrypt response
    decrypted_response_path = os.path.abspath("decrypted_response.json")
    TEMP_FILES.append(decrypted_response_path)
    
    # Build decrypt command
    gpg_decrypt_command = [
        "gpg", "--batch", "--yes", "--verbose",
        "--decrypt", "--output", decrypted_response_path,
        challenge_response_path
    ]
    
    # Add passphrase if provided
    if args.passphrase:
        gpg_decrypt_command.insert(4, "--pinentry-mode")
        gpg_decrypt_command.insert(5, "loopback")
        gpg_decrypt_command.insert(6, "--passphrase")
        gpg_decrypt_command.insert(7, args.passphrase)
    
    decrypt_result = subprocess.run(
        gpg_decrypt_command,
        env=get_gpg_env(),
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        text=True
    )
    
    debug_print(f"Decrypt stdout: {decrypt_result.stdout}")
    debug_print(f"Decrypt stderr: {decrypt_result.stderr}")
    
    if decrypt_result.returncode != 0:
        print(f"[!] Error: Decryption failed: {decrypt_result.stderr}")
        sys.exit(1)
    
    print("[+] Server response decrypted")
    
    # Parse the decrypted JSON
    try:
        with open(decrypted_response_path, "r") as f:
            decrypted_data = json.load(f)
        
        debug_print(f"Decrypted data: {json.dumps(decrypted_data, indent=2)}")
        
        # Extract tokens
        if "access_token" in decrypted_data and "refresh_token" in decrypted_data:
            access_token = decrypted_data["access_token"]
            refresh_token = decrypted_data["refresh_token"]
            return access_token, refresh_token
        else:
            print("[!] Error: Decrypted response does not contain expected tokens")
            debug_print(f"Decrypted data: {json.dumps(decrypted_data, indent=2)}")
            sys.exit(1)
    except json.JSONDecodeError:
        print("[!] Error: Decrypted response is not valid JSON")
        debug_print(f"Decrypted content: {open(decrypted_response_path, 'r').read()}")
        sys.exit(1)


# =============================================================================
# MAIN FUNCTION
# =============================================================================
def main():
    global DEBUG, TEMP_FILES
    
    # Set debug flag based on args
    DEBUG = args.debug
    
    # Print configuration
    print("\n[*] Passbolt JWT Authentication Client")
    print(f"[*] Server URL: {args.url}")
    print(f"[*] User ID: {args.user_id}")
    
    # Create session
    session = requests.Session()
    
    # Set up authentication method
    if args.key_file:
        print(f"[*] Using private key file: {args.key_file}")
        # Create a temporary GPG home directory for isolation
        setup_temporary_gpg_home()
        # Import the private key and get fingerprint
        fingerprint = import_key(args.key_file)
        print(f"[+] Key fingerprint: {fingerprint}")
    elif args.fingerprint:
        print(f"[*] Using fingerprint from keyring: {args.fingerprint}")
        fingerprint = args.fingerprint
    else:
        print("[!] Error: You must specify either a key file or a fingerprint")
        sys.exit(1)
    
    # Verify the key is valid
    check_gpg_key_validity(fingerprint)
    
    # Get server key and CSRF token
    csrf_token, server_key_fpr = get_server_key(session, args.url)
    
    # Initialize file paths
    challenge_path, encrypted_path = create_challenge(server_key_fpr, fingerprint)
    
    # Submit challenge and get response
    encrypted_response = submit_challenge(session, args.url, csrf_token, encrypted_path, fingerprint)
    
    # Decrypt the response
    access_token, refresh_token = decrypt_response(encrypted_response)
    
    # Display tokens
    print("\n[*] Step 5: Displaying authentication tokens")
    if args.full_token:
        print(f"[+] Access token (full):")
        print(access_token)
    else:
        # Truncate token for display
        display_token = access_token[:40] + "..." if len(access_token) > 40 else access_token
        print(f"[+] Access token: {display_token}")
    
    print(f"[+] Refresh token: {refresh_token}")
    
    # Output in Bruno-compatible format
    if args.bruno_format:
        print("\n=== Bruno Authorization Header ===")
        print("Authorization: Bearer " + access_token)
        print("=================================\n")
    
    # Output in curl format
    if args.curl_format:
        print("\n=== curl Command Example ===")
        print(f'curl -X GET "{args.url}/users/me.json" \\')
        print('  -H "Accept: application/json" \\')
        print(f'  -H "Authorization: Bearer {access_token}"')
        print("============================\n")
    
    # Save tokens to file if requested
    if args.output:
        token_data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "obtained_at": int(time.time()),
            "user_id": args.user_id,
            "server_url": args.url
        }
        
        with open(args.output, "w") as f:
            json.dump(token_data, f, indent=2)
        
        print(f"[+] Tokens saved to {args.output}")
    
    # Test API access if requested
    if args.test:
        print("\n[*] Step 6: Testing API access...")
        print(f"[*] Making test request to {args.url}/users/me.json")
        
        try:
            test_response = requests.get(
                f"{args.url}/users/me.json",
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {access_token}"
                },
                verify=not args.insecure
            )
            test_response.raise_for_status()
            
            user_data = test_response.json()
            username = user_data.get("body", {}).get("username", "Unknown")
            user_role = user_data.get("body", {}).get("role", {}).get("name", "Unknown")
            user_email = user_data.get("body", {}).get("username", "Unknown")
            
            print(f"[+] API test successful!")
            print(f"[+] User details:")
            print(f"    - Username: {username}")
            print(f"    - Email: {user_email}")
            print(f"    - Role: {user_role}")
            
            # Show additional user information if available
            if "body" in user_data:
                user_info = user_data["body"]
                if "profile" in user_info:
                    profile = user_info["profile"]
                    if "first_name" in profile or "last_name" in profile:
                        print(f"    - Name: {profile.get('first_name', '')} {profile.get('last_name', '')}")
                    if "created" in profile:
                        print(f"    - Created: {profile['created']}")
                    if "modified" in profile:
                        print(f"    - Last modified: {profile['modified']}")
        except requests.exceptions.RequestException as e:
            print(f"[!] API test failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                debug_print(f"Response status code: {e.response.status_code}")
                debug_print(f"Response content: {e.response.text}")
    
    print("\n[+] JWT authentication completed successfully")


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================
if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Passbolt JWT Authentication Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Required arguments
    parser.add_argument("--url", required=True, help="Passbolt server URL")
    parser.add_argument("--user-id", required=True, help="Your Passbolt user ID")
    
    # Authentication options (mutually exclusive)
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("--key-file", help="Path to GPG private key file")
    auth_group.add_argument("--fingerprint", help="GPG key fingerprint to use from keyring")
    
    # Optional arguments
    parser.add_argument("--passphrase", help="Passphrase for the GPG key")
    parser.add_argument("--output", help="Save tokens to a JSON file")
    parser.add_argument("--full-token", action="store_true", help="Display the full access token")
    parser.add_argument("--bruno-format", action="store_true", help="Output token in Bruno-compatible format")
    parser.add_argument("--curl-format", action="store_true", help="Output token in curl command format")
    parser.add_argument("--test", action="store_true", help="Test API access after authentication")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--no-cleanup", action="store_true", help="Don't remove temporary files")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")
    
    args = parser.parse_args()
    
    # Register cleanup and signal handlers
    atexit.register(cleanup_files)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the main function
    main()