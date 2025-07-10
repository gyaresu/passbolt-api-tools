#!/usr/bin/env python3
"""
Passbolt JWT Authentication Example with Bruno Support

This script demonstrates how to authenticate with the Passbolt API using
JWT authentication and integrates with Bruno API client. It supports:

1. JWT Authentication:
   - Using a local private key file
   - Using a GPG key from your keyring
   - Automatic token refresh
   - Secure token storage

2. Bruno Integration:
   - Environment variable management
   - Secret encryption and injection
   - Request template updates
   - Multiple output formats

Authentication Process:
1. Get CSRF token and server public key
2. Create and encrypt authentication challenge
3. Submit JWT login request
4. Process server response and extract tokens
5. Update Bruno environment with tokens

Security Features:
- GPG-based challenge/response authentication
- Secure token handling
- Temporary file cleanup
- SSL verification (optional)
- Passphrase protection

Usage:
    python3 jwt_api_with_bruno_support.py --url https://passbolt.example.com --user-id YOUR_USER_ID [options]

Options:
    --url URL                 Passbolt server URL
    --user-id ID              Your Passbolt user ID
    --key-file FILE           Path to GPG private key file
    --fingerprint FPR         GPG key fingerprint to use from keyring
    --passphrase PASS         Passphrase for the GPG key
    --output FILE             Save tokens to a JSON file
    --debug                   Enable debug output
    --no-cleanup              Don't remove temporary files
    --bruno-env-path PATH     Path to Bruno environment directory
    --bruno-env-name NAME     Name of Bruno environment
    --bruno-format            Output in Bruno-compatible format
    --curl-format             Output in curl-compatible format
    --test                    Test API access after authentication
    --insecure                Skip SSL verification
    --help                    Show this help message

Examples:
    # Basic authentication with key file
    python3 jwt_api_with_bruno_support.py --url https://passbolt.example.com --user-id YOUR_USER_ID --key-file private.key

    # Authentication with Bruno integration
    python3 jwt_api_with_bruno_support.py --url https://passbolt.example.com --user-id YOUR_USER_ID --fingerprint YOUR_FINGERPRINT --bruno-env-path .bruno --bruno-env-name docker

    # Encrypt a secret for Bruno
    python3 jwt_api_with_bruno_support.py --encrypt-secret "my-secret" --fingerprint YOUR_FINGERPRINT --bruno-request-path path/to/request.bru

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
from getpass import getpass
from typing import Optional, Dict, Any, List


# =============================================================================
# GLOBAL VARIABLES
# =============================================================================
TEMP_FILES: List[str] = []
DEBUG: bool = False


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def debug_print(message: str) -> None:
    """Print debug messages if debug mode is enabled"""
    if DEBUG:
        print(f"[DEBUG] {message}")


def print_file_contents(file_path: str, max_length: int = 500) -> None:
    """Print the contents of a file with a maximum length"""
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


def cleanup_files() -> None:
    """Clean up temporary files created during the script execution"""
    if args.no_cleanup:
        print("\n[*] Skipping cleanup as requested.")
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


def signal_handler(sig: int, frame: Any) -> None:
    """Handle interruption signals"""
    print(f"\n[!] Received signal {sig}, exiting...")
    cleanup_files()
    sys.exit(1)


def import_key(key_path: str) -> Optional[str]:
    """Import a GPG key from file and return its fingerprint"""
    if not os.path.exists(key_path):
        print(f"[!] Error: Key file not found: {key_path}")
        sys.exit(1)

    # Import the key
    import_result = subprocess.run(
        ["gpg", "--batch", "--yes", "--import", key_path],
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


def check_gpg_key_validity(fingerprint: str) -> bool:
    """Check if the GPG key is valid and can be used for signing"""
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


def update_bruno_env(env_path: str, environment_name: str, access_token: str) -> None:
    """Update Bruno environment file with authentication tokens"""
    env_file = os.path.join(env_path, f"{environment_name}.bru")
    host_url = args.url.rstrip('/')
    user_id = args.user_id

    # If the environment file doesn't exist, create it fresh
    if not os.path.exists(env_file):
        print(f"[!] Bruno environment file not found, creating: {env_file}")
        os.makedirs(env_path, exist_ok=True)
        with open(env_file, "w") as f:
            f.write("vars {\n")
            f.write(f"  host: {host_url}\n")
            f.write(f"  jwt_token: {access_token}\n")
            f.write(f"  user_id: {user_id}\n")
            f.write("}\n")
        return

    # Read existing lines
    with open(env_file, "r") as f:
        lines = f.readlines()

    in_vars_block = False
    host_written = False
    token_written = False
    user_written = False
    updated_lines = []

    for line in lines:
        stripped = line.strip()

        if stripped == "vars {":
            in_vars_block = True
            updated_lines.append(line)
            continue

        if in_vars_block and stripped.startswith("}"):
            if not host_written:
                updated_lines.append(f"  host: {host_url}\n")
            if not token_written:
                updated_lines.append(f"  jwt_token: {access_token}\n")
            if not user_written:
                updated_lines.append(f"  user_id: {user_id}\n")
            in_vars_block = False
            updated_lines.append(line)
            continue

        if in_vars_block:
            if stripped.startswith("host:"):
                updated_lines.append(f"  host: {host_url}\n")
                host_written = True
                continue
            elif stripped.startswith("jwt_token:"):
                updated_lines.append(f"  jwt_token: {access_token}\n")
                token_written = True
                continue
            elif stripped.startswith("user_id:"):
                updated_lines.append(f"  user_id: {user_id}\n")
                user_written = True
                continue

        updated_lines.append(line)

    with open(env_file, "w") as f:
        f.writelines(updated_lines)

    print(f"[+] Updated Bruno environment: {env_file}")


def encrypt_secret(plaintext: str, recipient_fpr: str) -> str:
    """Encrypt a secret string using the recipient's GPG key"""
    try:
        result = subprocess.run(
            [
                "gpg", "--armor", "--batch", "--yes",
                "--trust-model", "always",
                "--encrypt", "--recipient", recipient_fpr
            ],
            input=plaintext.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return result.stdout.decode()
    except subprocess.CalledProcessError as e:
        print("[!] GPG encryption failed")
        print(e.stderr)
        sys.exit(1)


def inject_secret_fields(bruno_file_path: str, encrypted_data: str, name: Optional[str] = None,
                        username: Optional[str] = None, uri: Optional[str] = None,
                        description: Optional[str] = None) -> None:
    """Inject encrypted secret and update fields in a Bruno request file"""
    if not os.path.exists(bruno_file_path):
        print(f"[!] Bruno request file not found: {bruno_file_path}")
        sys.exit(1)

    with open(bruno_file_path, "r") as f:
        lines = f.readlines()

    escaped_data = json.dumps(encrypted_data.strip())
    updated_lines = []
    for line in lines:
        stripped = line.strip()

        if "data:" in stripped:
            updated_lines.append(f'        data: {escaped_data},\n')
        elif stripped.startswith("name:"):
            updated_lines.append(f'    name: "{name or "My Bruno Secret"}"\n')
        elif stripped.startswith("username:"):
            updated_lines.append(f'    username: "{username or "admin"}"\n')
        elif stripped.startswith("uri:"):
            updated_lines.append(f'    uri: "{uri or "https://example.com"}"\n')
        elif stripped.startswith("description:"):
            updated_lines.append(f'    description: "{description or "Created via Script"}"\n')
        else:
            updated_lines.append(line)

    with open(bruno_file_path, "w") as f:
        f.writelines(updated_lines)

    print(f"[+] Injected encrypted secret and updated fields in {bruno_file_path}")


# =============================================================================
# MAIN FUNCTION
# =============================================================================
def main():
    global DEBUG, TEMP_FILES

    # Set debug flag based on args
    DEBUG = args.debug

    # Optional standalone encryption feature
    if args.encrypt_secret:
        encrypted = encrypt_secret(args.encrypt_secret, args.fingerprint)

        print("\n=== Encrypted OpenPGP Secret ===")
        print(encrypted)

        if args.bruno_request_path:
            inject_secret_fields(
                args.bruno_request_path,
                encrypted,
                name=args.secret_name,
                username=args.secret_username,
                uri=args.secret_uri,
                description=args.secret_description
            )

        sys.exit(0)

    if not args.encrypt_secret:
        if not args.url or not args.user_id:
            print("[!] Error: --url and --user-id are required unless using --encrypt-secret only.")
            sys.exit(1)

    # Initialize file paths
    challenge_path = os.path.abspath("challenge.json")
    TEMP_FILES.append(challenge_path)
    encrypted_path = os.path.abspath("challenge.enc")
    TEMP_FILES.append(encrypted_path)
    server_key_path = os.path.abspath("serverkey.asc")
    TEMP_FILES.append(server_key_path)
    challenge_response_path = os.path.abspath("challenge_response.asc")
    TEMP_FILES.append(challenge_response_path)
    decrypted_response_path = os.path.abspath("decrypted_response.json")
    TEMP_FILES.append(decrypted_response_path)

    # Print configuration
    print("[*] Passbolt JWT Authentication Client")
    print(f"[*] Server URL: {args.url}")
    print(f"[*] User ID: {args.user_id}")

    # Set up authentication method
    if args.key_file:
        print(f"[*] Using private key file: {args.key_file}")
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

    # Get passphrase
    passphrase = args.passphrase
    if not passphrase:
        passphrase = getpass("Enter passphrase for GPG key: ")

    # =============================================================================
    # STEP 1: Get CSRF token and Server Public Key
    # =============================================================================
    print("[*] Getting CSRF token and server public key...")
    session = requests.Session()

    try:
        response = session.get(f"{args.url}/auth/verify.json", verify=not args.insecure)
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

    debug_print(f"Server key fingerprint: {server_key_fpr}")

    # Save server key to file and import
    with open(server_key_path, "w") as f:
        f.write(server_key_data)

    import_result = subprocess.run(
        ["gpg", "--batch", "--yes", "--import", server_key_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    debug_print(f"Import stdout: {import_result.stdout}")
    debug_print(f"Import stderr: {import_result.stderr}")

    if import_result.returncode != 0:
        print(f"[!] Error: Failed to import server key: {import_result.stderr}")
        sys.exit(1)

    print("[+] Imported server public key")

    # Trust the server's key (level 6 = ultimate)
    trust_input = f"{server_key_fpr}:6:\n"
    trust_process = subprocess.run(
        ["gpg", "--import-ownertrust"],
        input=trust_input,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    debug_print(f"Trust stdout: {trust_process.stdout}")
    debug_print(f"Trust stderr: {trust_process.stderr}")

    if trust_process.returncode != 0:
        print(f"[!] Error: Failed to set trust on server key: {trust_process.stderr}")
        sys.exit(1)

    # =============================================================================
    # STEP 2: Create Challenge
    # =============================================================================
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
    with open(challenge_path, "w") as f:
        json.dump(challenge_payload, f, separators=(',', ':'))

    print("[+] Challenge created")
    debug_print(f"Challenge payload: {json.dumps(challenge_payload, indent=2)}")

    # =============================================================================
    # STEP 3: Sign and Encrypt Challenge
    # =============================================================================
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
    if passphrase:
        gpg_command.insert(4, "--pinentry-mode")
        gpg_command.insert(5, "loopback")
        gpg_command.insert(6, "--passphrase")
        gpg_command.insert(7, passphrase)

    encrypt_result = subprocess.run(
        gpg_command,
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

    # =============================================================================
    # STEP 4: Submit JWT Login Request
    # =============================================================================
    with open(encrypted_path, "r") as f:
        encrypted_challenge = f.read()

    debug_print(f"Challenge length: {len(encrypted_challenge)} characters")

    # Create request body
    request_body = {
        "user_id": args.user_id,
        "challenge": encrypted_challenge
    }

    print("[*] Sending JWT login request...")

    # Send request
    try:
        jwt_response = session.post(
            f"{args.url}/auth/jwt/login.json",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf_token
            },
            json=request_body,
            verify=not args.insecure
        )
        jwt_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[!] Error sending JWT login request: {e}")
        if hasattr(e, 'response') and e.response is not None:
            debug_print(f"Response status code: {e.response.status_code}")
            debug_print(f"Response headers: {e.response.headers}")
            debug_print(f"Response content: {e.response.text}")
        sys.exit(1)

    debug_print(f"JWT response status code: {jwt_response.status_code}")
    debug_print(f"JWT response headers: {jwt_response.headers}")

    try:
        jwt_data = jwt_response.json()
        debug_print(f"JWT response data: {json.dumps(jwt_data, indent=2)}")
    except json.JSONDecodeError:
        print("[!] Error: Server did not return valid JSON")
        debug_print(f"Raw response: {jwt_response.text}")
        sys.exit(1)

    # Check if authentication was successful
    if jwt_data.get("header", {}).get("status") != "success":
        print("[!] Authentication failed")
        error_message = jwt_data.get("header", {}).get("message", "Unknown error")
        print(f"[!] Error message: {error_message}")
        sys.exit(1)

    print("[+] Authentication successful")

    # =============================================================================
    # STEP 5: Process Server Response
    # =============================================================================
    # Check if response contains challenge
    if "challenge" in jwt_data.get("body", {}):
        encrypted_response = jwt_data["body"]["challenge"]

        # Write encrypted response to file
        with open(challenge_response_path, "w") as f:
            f.write(encrypted_response)

        print("[*] Decrypting server response...")

        # Decrypt the response
        gpg_decrypt_command = [
            "gpg", "--batch", "--yes", "--verbose",
            "--decrypt", "--output", decrypted_response_path,
            challenge_response_path
        ]

        # Add passphrase if provided
        if passphrase:
            gpg_decrypt_command.insert(4, "--pinentry-mode")
            gpg_decrypt_command.insert(5, "loopback")
            gpg_decrypt_command.insert(6, "--passphrase")
            gpg_decrypt_command.insert(7, passphrase)

        decrypt_result = subprocess.run(
            gpg_decrypt_command,
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

                # Save token in bruno environment variable
                if args.bruno_env_path and args.bruno_env_name:
                    update_bruno_env(args.bruno_env_path, args.bruno_env_name, access_token)

                # Display tokens
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
                        "verify_token": decrypted_data.get("verify_token"),
                        "obtained_at": int(time.time()),
                        "user_id": args.user_id,
                        "server_url": args.url
                    }

                    with open(args.output, "w") as f:
                        json.dump(token_data, f, indent=2)

                    print(f"[+] Tokens saved to {args.output}")

                # =============================================================================
                # STEP 6: Test API Access (Optional)
                # =============================================================================
                if args.test:
                    print("[*] Testing API access...")

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

                        print(f"[+] API test successful: Logged in as {username} ({user_role})")
                    except requests.exceptions.RequestException as e:
                        print(f"[!] API test failed: {e}")
                        if hasattr(e, 'response') and e.response is not None:
                            debug_print(f"Response status code: {e.response.status_code}")
                            debug_print(f"Response content: {e.response.text}")
            else:
                print("[!] Error: Decrypted response does not contain expected tokens")
                debug_print(f"Decrypted data: {json.dumps(decrypted_data, indent=2)}")
                sys.exit(1)
        except json.JSONDecodeError:
            print("[!] Error: Decrypted response is not valid JSON")
            debug_print(f"Decrypted content: {open(decrypted_response_path, 'r').read()}")
            sys.exit(1)
    else:
        print("[!] Error: Server response does not contain the expected challenge")
        debug_print(f"Response body: {json.dumps(jwt_data.get('body', {}), indent=2)}")
        sys.exit(1)

    print("[+] JWT authentication completed successfully")


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================
if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Passbolt JWT Authentication Client")

    # Encrypt secrets
    parser.add_argument("--encrypt-secret", help="Encrypt a secret and output OpenPGP block")

    # Add encrypted secret to bruno file
    parser.add_argument("--bruno-request-path", help="Path to Bruno .bru file to inject the encrypted secret into")

    # Add bruno token options
    parser.add_argument("--bruno-env-path", help="Path to Bruno .bruno folder (e.g., ~/my-bruno/.bruno)")
    parser.add_argument("--bruno-env-name", help="Name of the Bruno environment to update (e.g., dev)")

    parser.add_argument("--url", required=False, help="Passbolt server URL")
    parser.add_argument("--user-id", required=False, help="Your Passbolt user ID")
    parser.add_argument("--full-token", action="store_true", help="Display the full access token")
    parser.add_argument("--bruno-format", action="store_true", help="Output token in Bruno-compatible format")
    parser.add_argument("--curl-format", action="store_true", help="Output token in curl command format")

    # Add bruno secret-generation options
    parser.add_argument("--secret-name", help="Name of the resource to inject into Bruno")
    parser.add_argument("--secret-username", help="Username for the resource")
    parser.add_argument("--secret-uri", help="URI for the resource")
    parser.add_argument("--secret-description", help="Description of the resource")

    # Authentication options (mutually exclusive)
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("--key-file", help="Path to GPG private key file")
    auth_group.add_argument("--fingerprint", help="GPG key fingerprint to use from keyring")

    # Additional options
    parser.add_argument("--passphrase", help="Passphrase for the GPG key (omit for prompt)")
    parser.add_argument("--output", help="Save tokens to a JSON file")
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
