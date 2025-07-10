import os
import json
import uuid
import time
import subprocess
import requests
import atexit
import signal
import sys

# =============================================================================
# CONFIGURATION
# =============================================================================
# Server configuration
API_URL = "https://passbolt.local"  # Replace with your Passbolt server URL

# User credentials
USER_ID = "b4a148d8-4f97-410e-8874-5c070648f9f9"  # Replace with your actual user ID
USER_KEY_FINGERPRINT = "03F60E958F4CB29723ACDF761353B5B15D9B054F"  # Replace with your GPG key fingerprint
USER_KEY_PASSPHRASE = "ada@passbolt.com"  # Your actual passphrase 

# File paths
TEMP_FILES = []
challenge_path = os.path.abspath("challenge.json")
TEMP_FILES.append(challenge_path)
signed_path = os.path.abspath("challenge.asc")
TEMP_FILES.append(signed_path)
encrypted_path = os.path.abspath("challenge.enc")
TEMP_FILES.append(encrypted_path)
server_key_path = os.path.abspath("serverkey.asc")
TEMP_FILES.append(server_key_path)

# =============================================================================
# DEBUGGING OPTIONS
# =============================================================================
DEBUG = True  # Set to True to enable verbose debugging

def debug_print(message):
    if DEBUG:
        print(f"[DEBUG] {message}")

# =============================================================================
# CLEANUP FUNCTION
# =============================================================================
def cleanup_files():
    """Clean up temporary files created during the script execution"""
    print("\n[*] Cleaning up temporary files...")
    for file_path in TEMP_FILES:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"[+] Removed: {file_path}")
            except Exception as e:
                print(f"[!] Failed to remove {file_path}: {e}")

# Register the cleanup function to run on normal exit and signals
atexit.register(cleanup_files)

def signal_handler(sig, frame):
    print(f"\n[!] Received signal {sig}, exiting...")
    cleanup_files()
    sys.exit(1)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
signal.signal(signal.SIGTERM, signal_handler)  # Termination

# =============================================================================
# DEBUGGING HELPER FUNCTIONS
# =============================================================================
def print_file_contents(file_path, max_length=500):
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

def check_gpg_key_validity():
    """Check if the GPG key is valid and can be used for signing"""
    debug_print("Checking GPG key validity...")
    
    # Check if key exists
    list_result = subprocess.run(
        ["gpg", "--list-keys", USER_KEY_FINGERPRINT],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    
    if list_result.returncode != 0:
        debug_print(f"GPG key not found: {list_result.stderr}")
        return False
    
    debug_print(f"GPG key info: {list_result.stdout}")
    
    # Check if key can be used for signing
    check_result = subprocess.run(
        ["gpg", "--list-secret-keys", USER_KEY_FINGERPRINT],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    
    if check_result.returncode != 0:
        debug_print(f"GPG secret key not found: {check_result.stderr}")
        return False
    
    debug_print(f"GPG secret key info: {check_result.stdout}")
    return True

# =============================================================================
# MAIN FUNCTION
# =============================================================================
def main():
    print("[*] Configuration:")
    print(f"[DEBUG] API URL: {API_URL}")
    print(f"[DEBUG] User ID: {USER_ID}")
    print(f"[DEBUG] User Key Fingerprint: {USER_KEY_FINGERPRINT}")
    
    # Check GPG key validity
    if not check_gpg_key_validity():
        raise RuntimeError("GPG key validation failed")
    
    # =============================================================================
    # STEP 1: Get CSRF token and Server Public Key
    # =============================================================================
    print("[*] Getting CSRF token and server public key...")
    session = requests.Session()
    response = session.get(f"{API_URL}/auth/verify.json", verify=False)
    debug_print(f"Server response headers: {response.headers}")
    data = response.json()
    debug_print(f"Server response data: {json.dumps(data, indent=2)}")

    csrf_token = None
    for cookie in session.cookies:
        if cookie.name == "csrfToken":
            csrf_token = cookie.value
            break

    if not csrf_token:
        raise RuntimeError("Failed to get CSRF token")

    print(f"[+] Got CSRF token: {csrf_token}")

    server_key_data = data["body"]["keydata"]
    server_key_fpr = data["body"]["fingerprint"]
    debug_print(f"Server key fingerprint: {server_key_fpr}")

    # Save key to file and import
    with open(server_key_path, "w") as f:
        f.write(server_key_data)

    import_result = subprocess.run(
        ["gpg", "--batch", "--yes", "--import", server_key_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    debug_print(f"Import stdout: {import_result.stdout}")
    debug_print(f"Import stderr: {import_result.stderr}")
    print("[+] Imported server public key.")

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
        raise RuntimeError("Failed to set trust on server key")

    # =============================================================================
    # STEP 2: Create and CLEARSIGN the Challenge (not just detach-sign)
    # =============================================================================
    # Use lowercase UUID for verify_token (standard format)
    challenge_token = str(uuid.uuid4()).lower()
    debug_print(f"Using lowercase verify_token: {challenge_token}")
    
    # Create challenge payload with exact format
    challenge_payload = {
        "version": "1.0.0",
        "domain": API_URL,
        "verify_token": challenge_token,
        "verify_token_expiry": int(time.time()) + 300
    }
    
    # Write challenge as compact JSON (no whitespace)
    with open(challenge_path, "w") as f:
        json.dump(challenge_payload, f, separators=(',', ':'))
    print("[+] Challenge written.")
    print_file_contents(challenge_path)

    # Use clearsign instead of detach-sign
    print("[*] Clearsigning challenge...")
    sign_result = subprocess.run([
        "gpg", "--batch", "--yes", "--verbose",
        "--pinentry-mode", "loopback",
        "--passphrase", USER_KEY_PASSPHRASE,
        "--default-key", USER_KEY_FINGERPRINT,
        "--clearsign",  # Use clearsign 
        "--output", signed_path, challenge_path
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    debug_print(f"Sign stdout: {sign_result.stdout}")
    debug_print(f"Sign stderr: {sign_result.stderr}")
    
    if sign_result.returncode != 0:
        raise RuntimeError("Signing failed:\n" + sign_result.stderr)
    print("[+] Challenge clearsigned.")
    print_file_contents(signed_path)

    # =============================================================================
    # STEP 3: Encrypt the Clearsigned Challenge to Server Key
    # =============================================================================
    print("[*] Encrypting clearsigned challenge to server key...")
    encrypt_result = subprocess.run([
        "gpg", "--batch", "--yes", "--verbose",
        "--trust-model", "always",
        "--encrypt", "--armor",
        "--recipient", server_key_fpr,
        "--output", encrypted_path, signed_path  # Encrypt the clearsigned file
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    debug_print(f"Encrypt stdout: {encrypt_result.stdout}")
    debug_print(f"Encrypt stderr: {encrypt_result.stderr}")
    
    if encrypt_result.returncode != 0:
        raise RuntimeError(f"Encryption failed:\n{encrypt_result.stderr}")
    print("[+] Challenge encrypted.")
    print_file_contents(encrypted_path)
    
    # =============================================================================
    # STEP 4: Submit JWT Login Request
    # =============================================================================
    with open(encrypted_path, "r") as f:
        encrypted_challenge = f.read()

    # Ensure proper format of request body
    request_body = {
        "user_id": USER_ID,
        "challenge": encrypted_challenge  # Use 'challenge' as the field name
    }
    
    debug_print(f"Request body size: {len(json.dumps(request_body))} characters")

    print("[*] Sending JWT login request...")
    jwt_response = session.post(
        f"{API_URL}/auth/jwt/login.json",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf_token
        },
        json=request_body,
        verify=False
    )
    
    debug_print(f"JWT response status code: {jwt_response.status_code}")
    debug_print(f"JWT response headers: {jwt_response.headers}")
    
    try:
        jwt_data = jwt_response.json()
        print("[*] JWT response:")
        print(json.dumps(jwt_data, indent=2))
    except Exception as e:
        debug_print(f"Failed to parse JSON response: {e}")
        debug_print(f"Raw response: {jwt_response.text}")
        raise RuntimeError(f"Failed to parse JWT response: {e}")

    if jwt_data.get("header", {}).get("status") != "success":
        debug_print("Authentication failed! Attempting to diagnose the issue...")
        
        # Check if there are any specific error details
        error_message = jwt_data.get("header", {}).get("message", "")
        debug_print(f"Error message: {error_message}")
        
        # Additional diagnostics
        debug_print("Possible issues:")
        debug_print("1. The user ID doesn't match the GPG key in Passbolt")
        debug_print("2. The GPG key doesn't have proper permissions in Passbolt")
        debug_print("3. The JWT authentication plugin might not be enabled correctly on the server")
        debug_print("4. Your API endpoint might be incorrect; confirm the exact path with the server admin")
        
        raise RuntimeError(f"JWT login failed: {jwt_data['header'].get('message')}")

    access_token = jwt_data["body"]["access_token"]
    refresh_token = jwt_data["body"]["refresh_token"]
    print(f"[+] Access token: {access_token}")
    print(f"[+] Refresh token: {refresh_token}")

    # =============================================================================
    # STEP 5: Test API Access
    # =============================================================================
    print("[*] Testing protected endpoint...")
    test_response = requests.get(
        f"{API_URL}/users/me.json?api-version=v5",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {access_token}"
        },
        verify=False
    )

    print("[*] Test response:")
    print(json.dumps(test_response.json(), indent=2))
    print("[+] JWT authentication test completed successfully!")
    
    # Files will be automatically cleaned up by the atexit handler

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)