#!/usr/bin/env python3
"""
Decrypt Passbolt v5 resource metadata using Ada's private key and the Passbolt API.
Handles both private (user_key) and shared (shared_key) resource metadata.
"""
import requests
import json
import warnings
import subprocess
import os
import tempfile

PASSBOLT_URL = "https://passbolt.local"
RESOURCE_ID = "5c90c883-e967-4c64-afdb-4198cb14e1a0"
ADA_PRIVATE_KEY_PATH = "ada_private.key"
ADA_PRIVATE_KEY_PASSPHRASE = "ada@passbolt.com"
PASSBOLT_USER_ID = "0460d687-f393-490a-b710-79f333aae3b1"
PASSBOLT_USER_FPR = "03F60E958F4CB29723ACDF761353B5B15D9B054F"

# Ignore SSL warnings for self-signed certs
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def get_jwt_token():
    """Authenticate with Passbolt and return a JWT access token."""
    import tempfile, os, uuid, time
    session = requests.Session()
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
    """Import a private key into the GPG keyring."""
    result = subprocess.run([
        "gpg", "--batch", "--yes", "--import", path
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        exit(1)

def gpg_decrypt_message(encrypted_message, passphrase):
    """Decrypt a PGP message using GPG and the given passphrase."""
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
    """GET request to Passbolt API with optional JWT auth."""
    url = f"{PASSBOLT_URL}{path}"
    headers = {"Authorization": f"Bearer {jwt_token}"} if jwt_token else {}
    resp = requests.get(url, headers=headers, verify=False)
    resp.raise_for_status()
    return resp.json()

def main():
    jwt_token = get_jwt_token()
    resource = api_get(f"/resources/{RESOURCE_ID}.json", jwt_token=jwt_token)
    if 'body' in resource:
        resource = resource['body']
    elif 'data' in resource:
        resource = resource['data']

    metadata = resource.get('metadata')
    metadata_key_id = resource.get('metadata_key_id')
    metadata_key_type = resource.get('metadata_key_type')

    import_private_key(ADA_PRIVATE_KEY_PATH)

    if metadata_key_type == "user_key":
        cleartext = gpg_decrypt_message(metadata, ADA_PRIVATE_KEY_PASSPHRASE)
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
    else:
        raise Exception(f"Unknown metadata_key_type: {metadata_key_type}")

    print("\n--- Decrypted Metadata ---")
    try:
        print(json.dumps(json.loads(cleartext), indent=2))
    except Exception:
        print(cleartext)

if __name__ == "__main__":
    main() 