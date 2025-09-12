#!/usr/bin/env python3
"""
Passbolt Resource Metadata Demo

Demonstrates Passbolt API integration including JWT authentication, resource decryption,
and metadata parsing. Shows how to handle both user_key and shared_key encryption scenarios.
Supports JSON output for monitoring expired and near-expiry resources.

Key technical concepts:
- JWT authentication with GPG challenge/response
- Metadata encryption types: user_key vs shared_key
- GPG decryption of both metadata and secrets
- Resource data parsing and expiry date extraction
- Expiry filtering for monitoring expired and near-expiry resources

Authentication flow:
1. Create isolated GPG keyring
2. Authenticate via JWT challenge/response
3. Fetch user resources
4. For each resource:
   a. Determine encryption type from metadata_key_type
   b. Decrypt metadata using appropriate key
   c. Decrypt secret data
   d. Parse and display fields including expiry dates

Usage:
    python3 metadata_demo.py --user-id <USER_ID> [OPTIONS]
    python3 metadata_demo.py --env-file .env

Configuration Sources (in order of precedence):
    1. Command line arguments
    2. Environment variables
    3. .env file (automatically loaded if present, or via --env-file)
    4. Default values

Required Arguments:
    --user-id USER_ID         Passbolt user ID to authenticate as
                              (or set USER_ID environment variable)

Optional Arguments:
    --env-file PATH           Path to .env file with configuration
    --url URL                 Passbolt server URL (default: https://passbolt.local)
    --key-file PATH           Path to user's GPG private key file (default: ada_private.key)
    --passphrase PASSPHRASE   User's GPG key passphrase (default: ada@passbolt.com)
    -v, --verbose             Show detailed educational explanations
    --debug                   Show API requests/responses and debug info
    --json                    Output results as JSON file (expired and near-expiry resources only)
    --expiry-days DAYS        Days before expiry to include in JSON output (default: 30)

Examples:
    # Using command line arguments
    python3 metadata_demo.py --user-id 33c6ef32-c367-4287-9721-be6845231688
    
    # Using .env file (automatically loaded if present)
    python3 metadata_demo.py
    
    # Using specific .env file
    python3 metadata_demo.py --env-file my-config.env
    
    # Using environment variables
    export USER_ID=33c6ef32-c367-4287-9721-be6845231688
    export URL=https://passbolt.example.com
    python3 metadata_demo.py
    
    # Mix of .env file and CLI overrides
    python3 metadata_demo.py --url https://passbolt.example.com
    
    # Educational mode with detailed explanations
    python3 metadata_demo.py -v
    
    # Debug mode with API request/response details
    python3 metadata_demo.py --debug
    
    # JSON output mode - saves to passbolt_resources.json
    python3 metadata_demo.py --json
    
    # JSON output with custom expiry threshold (7 days)
    python3 metadata_demo.py --json --expiry-days 7

Notes:
- Requires Python 3.6+, requests, tabulate, and GPG 2.1+
- Requires Passbolt Pro Edition with password expiry feature enabled in administration settings (/app/administration/password-expiry)
- Intended for educational/demo use with test data
- Skips resources that cannot be decrypted
- Output is a table with key resource fields including expiry dates
- User ID and GPG fingerprint are retrieved dynamically from the API
- Expiry dates are displayed in ISO 8601 format when available
- JSON output filters for expired and near-expiry resources only
- JSON output includes resource ID, name, owner, owner email, expiration date, and status
- JSON data sources: resources table (ID, expiration), users table (owner info), decrypted metadata (name)
"""

import requests
import json
import warnings
import subprocess
import os
import tempfile
import argparse
import sys
from tabulate import tabulate
from dotenv import load_dotenv

# =============================================================================
# CONFIGURATION
# =============================================================================
# Configuration hierarchy: CLI args > Environment variables > .env file > defaults
DEFAULT_PASSBOLT_URL = "https://passbolt.local"
DEFAULT_KEY_FILE = "ada_private.key"
DEFAULT_PASSPHRASE = "ada@passbolt.com"

# Suppress SSL warnings for self-signed certificates (development only)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def get_user_info(jwt_token, passbolt_url, debug=False):
    """
    Get user information from Passbolt API.
    
    Passbolt API responses are wrapped in a "body" object. The GPG fingerprint
    is required for subsequent decryption operations.
    
    Args:
        jwt_token (str): JWT access token
        passbolt_url (str): Passbolt server URL
        debug (bool): Show request/response details
        
    Returns:
        dict: User information including ID and GPG fingerprint
        
    API Endpoint: GET /users/me.json
    """
    data = api_get("/users/me.json", jwt_token, passbolt_url, debug)
    user_info = data["body"]
    
    return {
        "user_id": user_info["id"],
        "gpg_fingerprint": user_info["gpgkey"]["fingerprint"],
        "username": user_info["username"],
        "full_name": f"{user_info['profile']['first_name']} {user_info['profile']['last_name']}",
        "email": user_info["username"]  # Username is typically the email in Passbolt
    }

def get_jwt_token_with_config(user_id, passbolt_url, key_file, passphrase, gpg_home):
    """
    Authenticate with Passbolt using JWT challenge/response.
    
    Authentication flow:
    1. Get server public key and CSRF token from /auth/verify.json
    2. Import server key and user private key into isolated GPG keyring
    3. Create challenge with random token and 5-minute expiry (300 seconds)
    4. Encrypt and sign challenge with user's private key
    5. Submit to /auth/jwt/login.json
    6. Decrypt response to get JWT token
    
    Args:
        user_id (str): Passbolt user ID
        passbolt_url (str): Passbolt server URL
        key_file (str): Path to private key file
        passphrase (str): Private key passphrase
        gpg_home (str): Isolated GPG home directory
        
    Returns:
        str: JWT access token
    """
    import tempfile, os, uuid, time
    print("Creating session...")
    session = requests.Session()
    
    # Use the provided GPG home directory
    print(f"Using GPG home: {gpg_home}")
    
    # Get CSRF token and server public key
    print("Getting server public key...")
    resp = session.get(f"{passbolt_url}/auth/verify.json", verify=False)
    print(f"Response status: {resp.status_code}")
    resp.raise_for_status()
    data = resp.json()
    print("Server public key retrieved successfully")
    csrf_token = None
    for cookie in session.cookies:
        if cookie.name == "csrfToken":
            csrf_token = cookie.value
            break
    server_key_data = data["body"]["keydata"]
    server_key_fpr = data["body"]["fingerprint"]
    print(f"Server key fingerprint: {server_key_fpr}")
    
    # Import server public key to temporary keyring
    print("Importing server public key...")
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        f.write(server_key_data)
        server_key_path = f.name
    subprocess.run([
        "gpg", "--homedir", gpg_home, "--batch", "--yes", "--import", server_key_path
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.unlink(server_key_path)
    print("Server public key imported")
    
    # Import user's private key to temporary keyring
    print("Importing user's private key...")
    subprocess.run([
        "gpg", "--homedir", gpg_home, "--batch", "--yes", "--import", key_file
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("User's private key imported")

    # Get user's GPG fingerprint from the imported key
    result = subprocess.run([
        "gpg", "--homedir", gpg_home, "--list-secret-keys", "--fingerprint", "--with-colons"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    user_fingerprint = None
    
    # Look for the first key in the temporary keyring (should be the user's key)
    for line in result.stdout.split('\n'):
        if line.startswith('fpr:'):
            user_fingerprint = line.split(':')[9]
            break
    
    if not user_fingerprint:
        print("Error: Could not find user's GPG fingerprint")
        print("Available keys:")
        for line in result.stdout.split('\n'):
            if line.startswith('uid:'):
                print(f"  {line}")
        exit(1)
    
    print(f"User's GPG fingerprint: {user_fingerprint}")

    # Create and encrypt challenge
    print("Creating challenge...")
    challenge_token = str(uuid.uuid4()).lower()
    challenge_payload = {
        "version": "1.0.0",
        "domain": passbolt_url,
        "verify_token": challenge_token,
        "verify_token_expiry": int(time.time()) + 300
    }
    print("Challenge created, encrypting...")
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        json.dump(challenge_payload, f, separators=(',', ':'))
        challenge_path = f.name
    encrypted_path = challenge_path + ".asc"
    gpg_cmd = [
        "gpg", "--homedir", gpg_home, "--batch", "--yes", "--trust-model", "always", "--pinentry-mode", "loopback", "--passphrase", passphrase,
        "--sign", "--encrypt", "--armor",
        "--recipient", server_key_fpr,
        "--local-user", user_fingerprint,
        "--output", encrypted_path, challenge_path
    ]
    print(f"Running GPG command: {' '.join(gpg_cmd[:5])}...")
    result = subprocess.run(gpg_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"GPG return code: {result.returncode}")
    if result.stderr:
        print(f"GPG stderr: {result.stderr.decode()}")
    if result.returncode != 0 or not os.path.exists(encrypted_path):
        print("GPG encryption failed")
        if os.path.exists(encrypted_path):
            os.unlink(encrypted_path)
        os.unlink(challenge_path)
        exit(1)
    with open(encrypted_path, "r") as f:
        encrypted_challenge = f.read()
    os.unlink(challenge_path)
    os.unlink(encrypted_path)
    
    # Submit challenge with the provided user ID
    print(f"Submitting challenge for user ID: {user_id}")
    login_body = {"user_id": user_id, "challenge": encrypted_challenge}
    headers = {"Accept": "application/json", "Content-Type": "application/json", "X-CSRF-Token": csrf_token}
    resp = session.post(f"{passbolt_url}/auth/jwt/login.json", headers=headers, json=login_body, verify=False)
    resp.raise_for_status()
    data = resp.json()
    encrypted_response = data["body"]["challenge"]
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        f.write(encrypted_response)
        enc_resp_path = f.name
    dec_resp_path = enc_resp_path + ".json"
    gpg_dec_cmd = [
        "gpg", "--homedir", gpg_home, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", passphrase,
        "--decrypt", "--output", dec_resp_path, enc_resp_path
    ]
    subprocess.run(gpg_dec_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with open(dec_resp_path, "r") as f:
        decrypted = json.load(f)
    os.unlink(enc_resp_path)
    os.unlink(dec_resp_path)
    return decrypted["access_token"]


def gpg_decrypt_message(encrypted_message, passphrase, gpg_home=None):
    """Decrypt a PGP message using GPG and the given passphrase.
    Args:
        encrypted_message (str): The PGP-encrypted message
        passphrase (str): The passphrase for the private key
        gpg_home (str, optional): GPG home directory to use
    Returns:
        str: Decrypted message as plaintext
    """
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        f.write(encrypted_message)
        enc_file = f.name
    dec_file = enc_file + ".decrypted"
    gpg_cmd = [
        "gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", passphrase,
        "--decrypt", "--output", dec_file, enc_file
    ]
    if gpg_home:
        gpg_cmd.insert(1, "--homedir")
        gpg_cmd.insert(2, gpg_home)
    result = subprocess.run(gpg_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if not os.path.exists(dec_file) or os.path.getsize(dec_file) == 0:
        raise Exception(f"GPG decryption failed: {result.stderr}")
    with open(dec_file, "r") as f:
        decrypted = f.read()
    os.unlink(enc_file)
    os.unlink(dec_file)
    return decrypted

def api_get(path, jwt_token=None, passbolt_url=None, debug=False):
    """GET request to Passbolt API with optional JWT auth.
    Args:
        path (str): API path (e.g., '/resources.json')
        jwt_token (str, optional): JWT token for Authorization header
        passbolt_url (str, optional): Passbolt server URL
        debug (bool): Show request/response details
    Returns:
        dict: Parsed JSON response
    """
    if passbolt_url is None:
        passbolt_url = DEFAULT_PASSBOLT_URL
    url = f"{passbolt_url}{path}"
    headers = {"Authorization": f"Bearer {jwt_token}"} if jwt_token else {}
    
    if debug:
        print(f"🔍 DEBUG: GET {url}")
        print(f"🔍 DEBUG: Headers: {headers}")
    
    resp = requests.get(url, headers=headers, verify=False)
    
    if debug:
        print(f"🔍 DEBUG: Response Status: {resp.status_code}")
        print(f"🔍 DEBUG: Response Headers: {dict(resp.headers)}")
        if resp.status_code == 200:
            try:
                response_data = resp.json()
                print(f"🔍 DEBUG: Response Body (first 200 chars): {str(response_data)[:200]}...")
            except:
                print(f"🔍 DEBUG: Response Body (first 200 chars): {resp.text[:200]}...")
        else:
            print(f"🔍 DEBUG: Error Response: {resp.text}")
    
    resp.raise_for_status()
    return resp.json()

# =============================================================================
# MAIN LOGIC
# =============================================================================
def main():
    """
    Main execution: authenticate, fetch, decrypt, and display resources with expiry information.
    
    Supports two output modes:
    - Table format: Shows all resources in a formatted table
    - JSON format: Filters and outputs only expired and near-expiry resources
    
    JSON output includes:
    - Resource ID (from resources table)
    - Resource name (from decrypted metadata)
    - Owner (authenticated user from users table)
    - Owner email (from users.username field)
    - Expiration date (from resources.expired field)
    - Status (expired or expires_in_X_days)
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Passbolt Resource Metadata Demo - includes expiry date information and JSON output for monitoring')
    
    # Config file support
    parser.add_argument('--env-file', help="Optional .env file with key=value pairs")
    
    # CLI arguments
    parser.add_argument('--user-id', help='Passbolt user ID to authenticate as')
    parser.add_argument('--url', help='Passbolt server URL')
    parser.add_argument('--key-file', help='Path to private key file')
    parser.add_argument('--passphrase', help='Private key passphrase')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed educational explanations')
    parser.add_argument('--debug', action='store_true', help='Show API requests/responses and debug info')
    parser.add_argument('--json', action='store_true', help='Output results as JSON (expired and near-expiry resources only)')
    parser.add_argument('--expiry-days', type=int, default=30, help='Days before expiry to include in JSON output (default: 30)')
    
    args = parser.parse_args()
    
    # Load from .env if provided or if .env exists in current directory
    if args.env_file:
        load_dotenv(dotenv_path=args.env_file)
    elif os.path.exists('.env'):
        load_dotenv()  # Load from .env in current directory
    
    # Merge values from CLI args or env vars (CLI takes precedence)
    config = {}
    config["user_id"] = args.user_id or os.getenv("USER_ID")
    config["url"] = args.url or os.getenv("URL") or DEFAULT_PASSBOLT_URL
    config["key_file"] = args.key_file or os.getenv("KEY_FILE") or DEFAULT_KEY_FILE
    config["passphrase"] = args.passphrase or os.getenv("PASSPHRASE") or DEFAULT_PASSPHRASE
    
    # Check required fields
    if not config["user_id"]:
        print("Error: USER_ID is required. Provide via --user-id argument, .env file, or USER_ID environment variable.")
        sys.exit(1)
    
    # Use configuration values
    passbolt_url = config["url"]
    key_file = config["key_file"]
    passphrase = config["passphrase"]
    user_id = config["user_id"]
    verbose = args.verbose
    debug = args.debug
    json_output = args.json
    expiry_days = args.expiry_days
    
    # Create temporary GPG home directory for the entire session
    import tempfile, shutil
    temp_gpg_home = tempfile.mkdtemp(prefix="passbolt_gpg_")
    print(f"Using temporary GPG home: {temp_gpg_home}")
    
    try:
        if verbose:
            print("🔐 JWT Authentication Process:")
            print("  1. Create isolated GPG keyring for security")
            print("  2. Get server public key and CSRF token")
            print("  3. Import server key and user private key")
            print("  4. Create challenge with random token + 5-minute expiry")
            print("  5. Encrypt and sign challenge with user's private key")
            print("  6. Submit challenge to Passbolt")
            print("  7. Decrypt response to get JWT token")
            print()
        
        print("🔐 Authenticating with Passbolt...")
        jwt_token = get_jwt_token_with_config(user_id, passbolt_url, key_file, passphrase, temp_gpg_home)
        
        if verbose:
            print("📡 API Call: GET /users/me.json - Fetching user information")
        
        # Get user information dynamically from the API
        user_info = get_user_info(jwt_token, passbolt_url, debug)
        print(f"✅ Authenticated as: {user_info['full_name']} ({user_info['username']})")
        
        if verbose:
            print(f"User ID: {user_info['user_id']}")
            print(f"GPG Fingerprint: {user_info['gpg_fingerprint']}")
            print("✅ Authentication successful - JWT token valid for API calls")
            print()
        
        if verbose:
            print("📡 API Call: GET /resources.json - Fetching all accessible resources")
        
        # Fetch all resources the user can access
        resources_response = api_get("/resources.json", jwt_token=jwt_token, passbolt_url=passbolt_url, debug=debug)
        resources = resources_response.get('body', resources_response)
        
        print(f"📊 Found {len(resources)} resources to process")
        
        if verbose:
            print("🔄 Processing each resource:")
            print("  1. Fetch resource details and metadata")
            print("  2. Determine encryption type (user_key vs shared_key)")
            print("  3. Decrypt metadata using appropriate key")
            print("  4. Fetch and decrypt secret data")
            print("  5. Parse and combine metadata + secret data")
            print()
        
        table = []
        json_data = []
        headers = [
            "Name", "ID", "Password", "TOTP", "Custom Fields", "Username", "URL", "Description", "Icon", "Expiry"
        ]

        for res in resources:
            resource_id = res.get('id')
            password = ""
            totp = ""
            custom_fields = ""
            username = ""
            meta_name = ""
            url = ""
            description = ""
            icon = ""
            expiry = ""
            try:
                if verbose:
                    print(f"🔍 Processing resource {resource_id[:8]}...")
                
                # Fetch resource details - includes encrypted metadata and key information
                if debug:
                    print(f"📡 API Call: GET /resources/{resource_id}.json")
                resource = api_get(f"/resources/{resource_id}.json", jwt_token=jwt_token, passbolt_url=passbolt_url, debug=debug)
                if 'body' in resource:
                    resource = resource['body']
                elif 'data' in resource:
                    resource = resource['data']

                # Resource structure contains:
                # - metadata: encrypted resource metadata (name, username, URL, etc.)
                # - metadata_key_id: ID of the key used to encrypt metadata
                # - metadata_key_type: "user_key" or "shared_key" - determines decryption method
                metadata = resource.get('metadata')
                metadata_key_id = resource.get('metadata_key_id')
                metadata_key_type = resource.get('metadata_key_type')
                
                # Extract expiry date directly from resource (not encrypted)
                # Note: 'expired' field contains the actual expiry date, not a boolean
                # Note: Password expiry feature must be enabled in Passbolt Pro Edition administration (/app/administration/password-expiry)
                expiry = resource.get('expired', '')

                # Import user's private key to the temporary keyring
                subprocess.run([
                    "gpg", "--homedir", temp_gpg_home, "--batch", "--yes", "--import", key_file
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # Decrypt metadata based on encryption type
                if verbose:
                    print(f"  🔓 Encryption type: {metadata_key_type}")
                
                # user_key: encrypted with user's public key, decrypt with user's private key
                if metadata_key_type == "user_key":
                    if verbose:
                        print("  🔑 Using user_key - encrypted with user's public key")
                    cleartext = gpg_decrypt_message(metadata, passphrase, temp_gpg_home)
                    secret_decrypt_passphrase = passphrase
                # shared_key: encrypted with shared key, need to decrypt shared key first
                elif metadata_key_type == "shared_key":
                    if verbose:
                        print("  🔑 Using shared_key - need to decrypt shared key first")
                    # Get shared key metadata - contains the shared key encrypted for each user
                    keys_response = api_get("/metadata/keys.json?contain[metadata_private_keys]=1", jwt_token=jwt_token, passbolt_url=passbolt_url, debug=debug)
                    key_entry = None
                    for k in keys_response.get('body', []):
                        if k.get('id') == metadata_key_id:
                            key_entry = k
                            break
                    if not key_entry:
                        raise Exception(f"Could not find metadata key {metadata_key_id} in API response.")
                    
                    # Find the user's encrypted copy of the shared key
                    user_private_key_entry = None
                    for pk in key_entry.get('metadata_private_keys', []):
                        if pk.get('user_id', '').strip().lower() == user_info['user_id'].strip().lower():
                            user_private_key_entry = pk
                            break
                    if not user_private_key_entry:
                        raise Exception("Could not find user's encrypted private key for shared key in metadata_private_keys.")
                    
                    # Decrypt the shared key using user's private key
                    encrypted_private_key = user_private_key_entry.get('data')
                    if not encrypted_private_key:
                        raise Exception("User's encrypted private key entry is missing 'data'.")
                    shared_key_clear = gpg_decrypt_message(encrypted_private_key, passphrase, temp_gpg_home)
                    shared_key_json = json.loads(shared_key_clear)
                    armored_shared_private_key = shared_key_json["armored_key"].replace("\\n", "\n")
                    
                    # Import the decrypted shared key into temporary keyring
                    with tempfile.NamedTemporaryFile("w", delete=False) as f:
                        shared_key_path = f.name
                        f.write(armored_shared_private_key)
                    import_result = subprocess.run([
                        "gpg", "--homedir", temp_gpg_home, "--batch", "--yes", "--import", shared_key_path
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if import_result.returncode != 0:
                        raise Exception(f"GPG import of shared key failed: {import_result.stderr}")
                    os.unlink(shared_key_path)
                    
                    # Now decrypt metadata using the shared key (shared keys typically have no passphrase)
                    cleartext = gpg_decrypt_message(metadata, "", temp_gpg_home)
                    
                    # Clean up shared key from keyring for security
                    import re
                    m = re.search(r'key ([A-F0-9]{40})', import_result.stderr)
                    if m:
                        shared_fpr = m.group(1)
                        subprocess.run([
                            "gpg", "--homedir", temp_gpg_home, "--batch", "--yes", "--delete-secret-keys", shared_fpr
                        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    secret_decrypt_passphrase = passphrase
                else:
                    raise Exception(f"Unknown metadata_key_type: {metadata_key_type}")

                # Fetch and decrypt the secret (password) - separate API call
                if debug:
                    print(f"📡 API Call: GET /secrets/resource/{resource_id}.json")
                secret_response = api_get(f"/secrets/resource/{resource_id}.json", jwt_token=jwt_token, passbolt_url=passbolt_url, debug=debug)
                secret_data = secret_response.get('body', secret_response)
                encrypted_secret = secret_data.get('data')
                
                if verbose:
                    print("  🔓 Decrypting secret data...")
                decrypted_secret_raw = gpg_decrypt_message(encrypted_secret, secret_decrypt_passphrase, temp_gpg_home).strip()
                
                # Parse secret data - can be JSON with multiple fields or plain text
                try:
                    secret_obj = json.loads(decrypted_secret_raw)
                    password = secret_obj.get('password', decrypted_secret_raw)
                    # Format TOTP data more readably
                    if 'totp' in secret_obj and secret_obj['totp']:
                        totp_data = secret_obj['totp']
                        if isinstance(totp_data, dict):
                            totp = f"Key: {totp_data.get('secret_key', 'N/A')[:8]}..."
                        else:
                            totp = str(totp_data)
                    else:
                        totp = ''
                except Exception:
                    # If not JSON, treat as plain password
                    password = decrypted_secret_raw

                # Extract metadata fields for table
                try:
                    meta = json.loads(cleartext)
                    meta_name = meta.get('name', '')
                    username = meta.get('username', '')
                    # Handle multiple URIs if present (list of strings or dicts)
                    if 'uris' in meta and isinstance(meta['uris'], list):
                        if all(isinstance(u, str) for u in meta['uris']):
                            url = ', '.join(u for u in meta['uris'] if u)
                        else:
                            url = ', '.join(u.get('uri', '') for u in meta['uris'] if isinstance(u, dict) and u.get('uri'))
                    else:
                        url = meta.get('uri', '') or meta.get('url', '')
                    description = meta.get('description', '')
                    # Extract icon summary if present
                    if 'icon' in meta:
                        icon_data = meta['icon']
                        if isinstance(icon_data, dict):
                            icon = icon_data.get('type', '')
                            if icon_data.get('background_color'):
                                icon += f" ({icon_data['background_color']})"
                            elif icon_data:
                                icon = str(icon_data)
                        else:
                            icon = str(icon_data)
                    
                    # Process custom fields - match metadata field names with secret values by ID
                    if 'custom_fields' in secret_obj and 'custom_fields' in meta:
                        if verbose:
                            print(f"  📝 Processing {len(secret_obj['custom_fields'])} custom fields...")
                            print("  🔗 Data Flow: Metadata (field names) + Secret (field values) → Match by ID")
                        
                        # Create lookup dict: field_id -> field_name from metadata
                        field_names = {f['id']: f.get('metadata_key', f.get('name', 'unnamed')) 
                                     for f in meta['custom_fields']}
                        
                        # Match secret values with field names
                        custom_fields = ", ".join(
                            f"{field_names.get(f['id'], 'unnamed')}: {f.get('secret_value', '')}" 
                            for f in secret_obj['custom_fields']
                        )
                        
                        if verbose:
                            print(f"  ✅ Custom fields: {custom_fields}")
                except Exception:
                    pass

            except Exception as e:
                continue  # Skip resource on error

            table.append([
                meta_name or "",
                resource_id[:8] if resource_id else "",
                password or "",
                totp or "",
                custom_fields or "",
                username or "",
                url or "",
                description or "",
                icon or "",
                expiry or ""
            ])
            
            # Collect JSON data for --json output (expired and near-expiry only)
            if json_output and expiry:
                from datetime import datetime, timezone
                try:
                    # Parse expiry date from ISO 8601 format
                    expiry_dt = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
                    now = datetime.now(timezone.utc)
                    
                    # Calculate days until expiry and determine status
                    days_until_expiry = (expiry_dt - now).days
                    is_expired = days_until_expiry < 0
                    is_near_expiry = 0 <= days_until_expiry <= expiry_days
                    
                    # Include resource if expired or within configured days of expiry
                    if is_expired or is_near_expiry:
                        json_data.append({
                            "resource_id": resource_id,  # From resources table
                            "name": meta_name,
                            "owner": user_info['full_name'],  # Current user owns accessible resources
                            "owner_email": user_info['email'],
                            "expiration": expiry,  # From resources.expired field
                            "status": "expired" if is_expired else f"expires_in_{days_until_expiry}_days"
                        })
                except (ValueError, TypeError):
                    # Skip resources with invalid or unparseable expiry dates
                    pass

        # Output results based on format
        if json_output:
            # Create JSON output with metadata and filtered resources
            # Data sources: resources table (ID, expiration), users table (owner info), decrypted metadata (name)
            output_data = {
                "metadata": {
                    "processed_at": __import__('datetime').datetime.now().isoformat(),
                    "total_resources": len(json_data),
                    "authenticated_user": user_info['full_name'],
                    "filter": {
                        "expired_resources": True,
                        "near_expiry_days": expiry_days
                    }
                },
                "resources": json_data
            }
            
            # Write JSON output to file
            output_file = "passbolt_resources.json"
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            print(f"JSON output written to: {output_file}")
            print(f"Processed {len(json_data)} resources successfully")
        else:
            # Print the results as a table with better formatting
            print("\n📋 Resource Summary:")
            print(tabulate(table, headers=headers, tablefmt='grid', maxcolwidths=[20, 10, 20, 30, 20, 15, 30, 20, 15, 25]))
            
            # Always show basic summary
            print(f"\n✅ Processed {len(table)} resources successfully")
        
        if verbose:
            print()
            print("📊 Detailed Summary:")
            print(f"  • Total resources processed: {len(table)}")
            print(f"  • Resources with custom fields: {sum(1 for row in table if row[4])}")
            print(f"  • Resources with TOTP: {sum(1 for row in table if row[3])}")
            print(f"  • Resources with expiry dates: {sum(1 for row in table if row[9])}")
            print()
            print("ℹ️  Note: Password expiry feature must be enabled in Passbolt Pro Edition")
            print("   administration (/app/administration/password-expiry) for expiry dates to be displayed.")
            print()
            print("🔐 Security Notes:")
            print("  • All data encrypted with GPG")
            print("  • Temporary GPG keyring used for isolation")
            print("  • JWT tokens provide API access")
            print("  • Custom fields split between metadata and secret")
    
    finally:
        # Clean up temporary GPG home directory
        shutil.rmtree(temp_gpg_home, ignore_errors=True)
        print(f"Cleaned up temporary GPG home: {temp_gpg_home}")

if __name__ == "__main__":
    main()
