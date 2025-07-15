#!/usr/bin/env python3
"""
Passbolt Resource Metadata & Secret Decryptor

A command-line tool to authenticate with a Passbolt v5 API using JWT and Ada's private key,
fetch all resources accessible to Ada, decrypt their metadata and passwords, and display the results in a table.

Authentication & Decryption Flow:
1. Authenticate using JWT challenge/response with Ada's private key
2. Fetch all resources Ada can access
3. For each resource:
   a. Fetch resource details and metadata
   b. Decrypt metadata (with user key or shared key)
   c. Fetch and decrypt the resource secret (password)
   d. Extract and display key fields (name, password, username, URL, TOTP, custom fields, icon, etc.)

Usage:
    python3 passbolt_api_metadata_client.py

Arguments:
    (Edit the script to set these at the top)
    PASSBOLT_URL              Passbolt server URL
    ADA_PRIVATE_KEY_PATH      Path to Ada's GPG private key file
    ADA_PRIVATE_KEY_PASSPHRASE Ada's GPG key passphrase
    PASSBOLT_USER_ID          Ada's Passbolt user ID
    PASSBOLT_USER_FPR         Ada's GPG key fingerprint

Notes:
- Requires Python 3.6+, requests, tabulate, and GPG 2.1+
- Intended for educational/demo use with test data
- Skips resources that cannot be decrypted
- Output is a table with key resource fields
"""

import requests
import json
import warnings
import subprocess
import os
import tempfile
from tabulate import tabulate

# =============================================================================
# CONFIGURATION
# =============================================================================
PASSBOLT_URL = "https://passbolt.local"
ADA_PRIVATE_KEY_PATH = "ada_private.key"
ADA_PRIVATE_KEY_PASSPHRASE = "ada@passbolt.com"
PASSBOLT_USER_ID = "0460d687-f393-490a-b710-79f333aae3b1"
PASSBOLT_USER_FPR = "03F60E958F4CB29723ACDF761353B5B15D9B054F"

# Ignore SSL warnings for self-signed certs
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def get_jwt_token():
    """Authenticate with Passbolt and return a JWT access token.
    Returns:
        str: JWT access token
    """
    import tempfile, os, uuid, time
    session = requests.Session()
    # Get CSRF token and server public key
    resp = session.get(f"{PASSBOLT_URL}/auth/verify.json", verify=False)
    resp.raise_for_status()
    data = resp.json()
    csrf_token = None
    for cookie in session.cookies:
        if cookie.name == "csrfToken":
            csrf_token = cookie.value
            break
    server_key_data = data["body"]["keydata"]
    server_key_fpr = data["body"]["fingerprint"]
    # Import server public key
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        f.write(server_key_data)
        server_key_path = f.name
    subprocess.run(["gpg", "--batch", "--yes", "--import", server_key_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.unlink(server_key_path)
    # Import Ada's private key
    import_private_key(ADA_PRIVATE_KEY_PATH)
    # Create and encrypt challenge
    challenge_token = str(uuid.uuid4()).lower()
    challenge_payload = {
        "version": "1.0.0",
        "domain": PASSBOLT_URL,
        "verify_token": challenge_token,
        "verify_token_expiry": int(time.time()) + 300
    }
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        json.dump(challenge_payload, f, separators=(',', ':'))
        challenge_path = f.name
    encrypted_path = challenge_path + ".asc"
    gpg_cmd = [
        "gpg", "--batch", "--yes", "--trust-model", "always", "--pinentry-mode", "loopback", "--passphrase", ADA_PRIVATE_KEY_PASSPHRASE,
        "--sign", "--encrypt", "--armor",
        "--recipient", server_key_fpr,
        "--local-user", PASSBOLT_USER_FPR,
        "--output", encrypted_path, challenge_path
    ]
    result = subprocess.run(gpg_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0 or not os.path.exists(encrypted_path):
        if os.path.exists(encrypted_path):
            os.unlink(encrypted_path)
        os.unlink(challenge_path)
        exit(1)
    with open(encrypted_path, "r") as f:
        encrypted_challenge = f.read()
    os.unlink(challenge_path)
    os.unlink(encrypted_path)
    # Submit challenge and decrypt response
    login_body = {"user_id": PASSBOLT_USER_ID, "challenge": encrypted_challenge}
    headers = {"Accept": "application/json", "Content-Type": "application/json", "X-CSRF-Token": csrf_token}
    resp = session.post(f"{PASSBOLT_URL}/auth/jwt/login.json", headers=headers, json=login_body, verify=False)
    resp.raise_for_status()
    data = resp.json()
    encrypted_response = data["body"]["challenge"]
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        f.write(encrypted_response)
        enc_resp_path = f.name
    dec_resp_path = enc_resp_path + ".json"
    gpg_dec_cmd = [
        "gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ADA_PRIVATE_KEY_PASSPHRASE,
        "--decrypt", "--output", dec_resp_path, enc_resp_path
    ]
    subprocess.run(gpg_dec_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with open(dec_resp_path, "r") as f:
        decrypted = json.load(f)
    os.unlink(enc_resp_path)
    os.unlink(dec_resp_path)
    return decrypted["access_token"]

def import_private_key(path):
    """Import a private key into the GPG keyring.
    Args:
        path (str): Path to the private key file
    """
    result = subprocess.run([
        "gpg", "--batch", "--yes", "--import", path
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        exit(1)

def gpg_decrypt_message(encrypted_message, passphrase):
    """Decrypt a PGP message using GPG and the given passphrase.
    Args:
        encrypted_message (str): The PGP-encrypted message
        passphrase (str): The passphrase for the private key
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
    result = subprocess.run(gpg_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if not os.path.exists(dec_file) or os.path.getsize(dec_file) == 0:
        raise Exception(f"GPG decryption failed: {result.stderr}")
    with open(dec_file, "r") as f:
        decrypted = f.read()
    os.unlink(enc_file)
    os.unlink(dec_file)
    return decrypted

def api_get(path, jwt_token=None):
    """GET request to Passbolt API with optional JWT auth.
    Args:
        path (str): API path (e.g., '/resources.json')
        jwt_token (str, optional): JWT token for Authorization header
    Returns:
        dict: Parsed JSON response
    """
    url = f"{PASSBOLT_URL}{path}"
    headers = {"Authorization": f"Bearer {jwt_token}"} if jwt_token else {}
    resp = requests.get(url, headers=headers, verify=False)
    resp.raise_for_status()
    return resp.json()

# =============================================================================
# MAIN LOGIC
# =============================================================================
def main():
    """Main execution: authenticate, fetch, decrypt, and display resources."""
    jwt_token = get_jwt_token()
    # Fetch all resources Ada can access
    resources_response = api_get("/resources.json", jwt_token=jwt_token)
    resources = resources_response.get('body', resources_response)
    table = []
    headers = [
        "Name", "ID", "Password", "TOTP", "Custom Fields", "Username", "URL", "Description", "Icon"
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
        try:
            # Fetch resource details
            resource = api_get(f"/resources/{resource_id}.json", jwt_token=jwt_token)
            if 'body' in resource:
                resource = resource['body']
            elif 'data' in resource:
                resource = resource['data']

            metadata = resource.get('metadata')
            metadata_key_id = resource.get('metadata_key_id')
            metadata_key_type = resource.get('metadata_key_type')

            import_private_key(ADA_PRIVATE_KEY_PATH)

            # Decrypt metadata (user_key or shared_key)
            if metadata_key_type == "user_key":
                cleartext = gpg_decrypt_message(metadata, ADA_PRIVATE_KEY_PASSPHRASE)
                secret_decrypt_passphrase = ADA_PRIVATE_KEY_PASSPHRASE
            elif metadata_key_type == "shared_key":
                keys_response = api_get("/metadata/keys.json?contain[metadata_private_keys]=1", jwt_token=jwt_token)
                key_entry = None
                for k in keys_response.get('body', []):
                    if k.get('id') == metadata_key_id:
                        key_entry = k
                        break
                if not key_entry:
                    raise Exception(f"Could not find metadata key {metadata_key_id} in API response.")
                armored_shared_key = key_entry.get('armored_key')
                if not armored_shared_key:
                    raise Exception("Could not find armored shared key in API response.")
                ada_private_key_entry = None
                for pk in key_entry.get('metadata_private_keys', []):
                    if pk.get('user_id', '').strip().lower() == PASSBOLT_USER_ID.strip().lower():
                        ada_private_key_entry = pk
                        break
                if not ada_private_key_entry:
                    raise Exception("Could not find Ada's encrypted private key for shared key in metadata_private_keys.")
                encrypted_private_key = ada_private_key_entry.get('data')
                if not encrypted_private_key:
                    raise Exception("Ada's encrypted private key entry is missing 'data'.")
                shared_key_clear = gpg_decrypt_message(encrypted_private_key, ADA_PRIVATE_KEY_PASSPHRASE)
                shared_key_json = json.loads(shared_key_clear)
                armored_shared_private_key = shared_key_json["armored_key"].replace("\\n", "\n")
                with tempfile.NamedTemporaryFile("w", delete=False) as f:
                    shared_key_path = f.name
                    f.write(armored_shared_private_key)
                import_result = subprocess.run([
                    "gpg", "--batch", "--yes", "--import", shared_key_path
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if import_result.returncode != 0:
                    raise Exception(f"GPG import of shared key failed: {import_result.stderr}")
                os.unlink(shared_key_path)
                cleartext = gpg_decrypt_message(metadata, ADA_PRIVATE_KEY_PASSPHRASE)
                import re
                m = re.search(r'key ([A-F0-9]{40})', import_result.stderr)
                if m:
                    shared_fpr = m.group(1)
                    subprocess.run([
                        "gpg", "--batch", "--yes", "--delete-secret-keys", shared_fpr
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                secret_decrypt_passphrase = ADA_PRIVATE_KEY_PASSPHRASE
            else:
                raise Exception(f"Unknown metadata_key_type: {metadata_key_type}")

            # Fetch and decrypt the secret (password)
            secret_response = api_get(f"/secrets/resource/{resource_id}.json", jwt_token=jwt_token)
            secret_data = secret_response.get('body', secret_response)
            encrypted_secret = secret_data.get('data')
            decrypted_secret_raw = gpg_decrypt_message(encrypted_secret, secret_decrypt_passphrase).strip()
            # Extract password, totp, custom fields if present
            try:
                secret_obj = json.loads(decrypted_secret_raw)
                password = secret_obj.get('password', decrypted_secret_raw)
                totp = json.dumps(secret_obj.get('totp', '')) if 'totp' in secret_obj else ''
                if 'custom_fields' in secret_obj:
                    custom_fields = ", ".join(
                        f"{f.get('type','')}: {f.get('secret_value','')}" for f in secret_obj['custom_fields']
                    )
            except Exception:
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
            except Exception:
                pass

        except Exception as e:
            continue  # Skip resource on error

        table.append([
            meta_name,
            resource_id[:8],
            password,
            totp,
            custom_fields,
            username,
            url,
            description,
            icon
        ])

    # Print the results as a table
    print(tabulate(table, headers=headers, tablefmt='grid'))

if __name__ == "__main__":
    main() 