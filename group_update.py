#!/usr/bin/env python3
"""
Script to create a group and add a user to it in Passbolt.
Uses JWT authentication and handles existing groups.

Configuration:
- Set environment variables or modify the constants below
- PASSBOLT_URL: Your Passbolt instance URL
- USER_ID: Your Passbolt user ID
- USER_EMAIL: Email of the user to add to the group
- GROUP_NAME: Name of the group to create/use
- PRIVATE_KEY_PATH: Path to your GPG private key file
- KEY_PASSPHRASE: Your GPG key passphrase
- USER_FPR: Your GPG key fingerprint

Usage Examples:
    # Using environment variables
    export PASSBOLT_URL="https://passbolt.local"
    export USER_ID="your-user-id"
    export USER_EMAIL="user@example.com"
    export GROUP_NAME="My Group"
    python3 group_update.py

    # Using command line arguments
    python3 group_update.py --user-email "user@example.com" --group-name "My Group"

    # Using both (command line overrides environment)
    export USER_EMAIL="default@example.com"
    python3 group_update.py --user-email "override@example.com"
"""

import os
import json
import time
import uuid
import tempfile
import subprocess
import requests
import urllib3
import argparse

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Create a Passbolt group and add a user to it")
    parser.add_argument("--user-email", help="Email of the user to add to the group")
    parser.add_argument("--group-name", help="Name of the group to create/use")
    parser.add_argument("--passbolt-url", help="Passbolt instance URL")
    parser.add_argument("--user-id", help="Your Passbolt user ID")
    parser.add_argument("--private-key", help="Path to your GPG private key file")
    parser.add_argument("--passphrase", help="Your GPG key passphrase")
    parser.add_argument("--fingerprint", help="Your GPG key fingerprint")
    return parser.parse_args()

# Configuration - Set these or use environment variables
PASSBOLT_URL = os.getenv("PASSBOLT_URL", "https://passbolt.local")
USER_ID = os.getenv("USER_ID", "d2385e03-490c-4318-9bc0-d7c309657b30")  # Your user ID
USER_EMAIL = os.getenv("USER_EMAIL", "betty@passbolt.com")  # User to add to group
GROUP_NAME = os.getenv("GROUP_NAME", "Test Group")  # Group name
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "ada_private.key")  # Your private key
KEY_PASSPHRASE = os.getenv("KEY_PASSPHRASE", "ada@passbolt.com")  # Your passphrase
USER_FPR = os.getenv("USER_FPR", "03F60E958F4CB29723ACDF761353B5B15D9B054F")  # Your fingerprint

def import_private_key(key_path):
    """Import private key into GPG."""
    subprocess.run(["gpg", "--batch", "--yes", "--import", key_path],
                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def get_jwt_token():
    """Get JWT token using GPG authentication."""
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

    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        f.write(server_key_data)
        server_key_path = f.name

    subprocess.run(["gpg", "--batch", "--yes", "--import", server_key_path],
                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.unlink(server_key_path)

    import_private_key(PRIVATE_KEY_PATH)

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
        "gpg", "--batch", "--yes", "--trust-model", "always", "--pinentry-mode", "loopback",
        "--passphrase", KEY_PASSPHRASE, "--sign", "--encrypt", "--armor",
        "--recipient", server_key_fpr, "--local-user", USER_FPR, "--output", encrypted_path, challenge_path
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

    login_body = {"user_id": USER_ID, "challenge": encrypted_challenge}
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf_token
    }

    resp = session.post(f"{PASSBOLT_URL}/auth/jwt/login.json", headers=headers, json=login_body, verify=False)
    resp.raise_for_status()
    data = resp.json()

    encrypted_response = data["body"]["challenge"]
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        f.write(encrypted_response)
        enc_resp_path = f.name

    dec_resp_path = enc_resp_path + ".json"
    gpg_dec_cmd = [
        "gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", KEY_PASSPHRASE,
        "--decrypt", "--output", dec_resp_path, enc_resp_path
    ]

    subprocess.run(gpg_dec_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    with open(dec_resp_path, "r") as f:
        decrypted = json.load(f)

    os.unlink(enc_resp_path)
    os.unlink(dec_resp_path)

    return decrypted["access_token"]

def api_get(path, jwt_token):
    """Helper function for GET requests."""
    url = f"{PASSBOLT_URL}{path}"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json"
    }
    resp = requests.get(url, headers=headers, verify=False)
    if resp.status_code != 200:
        print(f"[!] API Error: {resp.status_code}")
        print(f"[!] Response: {resp.text}")
        resp.raise_for_status()
    return resp.json()

def api_post(path, data, jwt_token):
    """Helper function for POST requests."""
    url = f"{PASSBOLT_URL}{path}"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    resp = requests.post(url, headers=headers, json=data, verify=False)
    if resp.status_code != 200:
        print(f"[!] API Error: {resp.status_code}")
        print(f"[!] Response: {resp.text}")
        resp.raise_for_status()
    return resp.json()

def api_put(path, data, jwt_token):
    """Helper function for PUT requests."""
    url = f"{PASSBOLT_URL}{path}"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    resp = requests.put(url, headers=headers, json=data, verify=False)
    if resp.status_code != 200:
        print(f"[!] API Error: {resp.status_code}")
        print(f"[!] Response: {resp.text}")
        resp.raise_for_status()
    return resp.json()

def main():
    # Parse command line arguments
    args = parse_arguments()

    # Override configuration with command line arguments
    global PASSBOLT_URL, USER_ID, USER_EMAIL, GROUP_NAME, PRIVATE_KEY_PATH, KEY_PASSPHRASE, USER_FPR

    if args.passbolt_url:
        PASSBOLT_URL = args.passbolt_url
    if args.user_id:
        USER_ID = args.user_id
    if args.user_email:
        USER_EMAIL = args.user_email
    if args.group_name:
        GROUP_NAME = args.group_name
    if args.private_key:
        PRIVATE_KEY_PATH = args.private_key
    if args.passphrase:
        KEY_PASSPHRASE = args.passphrase
    if args.fingerprint:
        USER_FPR = args.fingerprint

    print("=== Passbolt Group User Test ===")
    print(f"Target User: {USER_EMAIL}")
    print(f"Group Name: {GROUP_NAME}")
    print()

    # Validate configuration
    if not all([PASSBOLT_URL, USER_ID, USER_EMAIL, GROUP_NAME, PRIVATE_KEY_PATH, KEY_PASSPHRASE, USER_FPR]):
        print("[!] Error: Missing required configuration. Please set all environment variables or update the constants.")
        return

    if not os.path.exists(PRIVATE_KEY_PATH):
        print(f"[!] Error: Private key file not found: {PRIVATE_KEY_PATH}")
        return

    print(f"[+] User fingerprint: {USER_FPR}")

    # Get JWT token
    print("[*] Getting JWT token...")
    try:
        jwt_token = get_jwt_token()
        print("[+] JWT token obtained successfully")
    except Exception as e:
        print(f"[!] Failed to get JWT token: {e}")
        return

    # ============================================================================
    # Step 1: Find Target User
    # ============================================================================
    print(f"[*] Looking up user: {USER_EMAIL}")

    users_response = api_get("/users.json", jwt_token=jwt_token)
    target_user = None

    for user in users_response.get("body", []):
        if user.get("username") == USER_EMAIL:
            target_user = user
            break

    if not target_user:
        print(f"[!] User {USER_EMAIL} not found")
        return

    target_user_id = target_user["id"]
    print(f"[+] Found user: {target_user_id}")

    # ============================================================================
    # Step 2: Check/Create Group
    # ============================================================================
    print(f"[*] Checking for existing group: {GROUP_NAME}")

    # Get all groups to check if our group already exists
    groups_response = api_get("/groups.json?contain[users]=1", jwt_token=jwt_token)
    existing_group = None

    for group in groups_response.get("body", []):
        if group.get("name") == GROUP_NAME:
            existing_group = group
            break

    if existing_group:
        print(f"[+] Found existing group: {existing_group['id']}")
        group_id = existing_group["id"]

        # Check if the target user is already in the group
        users_in_group = existing_group.get("users", [])
        user_already_in_group = any(user.get("username") == USER_EMAIL for user in users_in_group)

        if user_already_in_group:
            print(f"[+] User {USER_EMAIL} is already in the group")
        else:
            print(f"[*] User {USER_EMAIL} is not in the group, will add them")
    else:
        print(f"[*] Group '{GROUP_NAME}' does not exist, creating new group...")

        # Create group with only the current user initially
        group_data = {
            "name": GROUP_NAME,
            "groups_users": [
                {
                    "user_id": USER_ID,  # Current user as group manager
                    "is_admin": True
                }
            ]
        }

        group_response = api_post("/groups.json", group_data, jwt_token)
        group_id = group_response["body"]["id"]
        print(f"[+] Group created successfully: {group_id}")
        user_already_in_group = False

    # ============================================================================
    # Step 3: Add User to Group (if not already in group)
    # ============================================================================
    if not user_already_in_group:
        print(f"[*] Adding user {USER_EMAIL} to group...")

        # For adding a new user to an existing group, we only need to specify the new user
        # The API will handle the existing users automatically
        update_group_data = {
            "groups_users": [
                {
                    "user_id": target_user_id,
                    "is_admin": False
                }
            ],
            "secrets": []
        }

        print(f"[*] Sending update payload: {json.dumps(update_group_data, indent=2)}")

        try:
            api_put(f"/groups/{group_id}.json", update_group_data, jwt_token)
            print(f"[+] User {USER_EMAIL} successfully added to group {GROUP_NAME}")
        except Exception as e:
            print(f"[!] Failed to add user to existing group: {e}")
            return
    else:
        print(f"[+] User {USER_EMAIL} is already in the group, no action needed")

    # ============================================================================
    # Step 4: Verify Group Membership
    # ============================================================================
    print("[*] Verifying group membership...")

    group_details = api_get(f"/groups/{group_id}.json?contain[users]=1", jwt_token=jwt_token)

    if "body" in group_details and "users" in group_details["body"]:
        users_in_group = group_details["body"]["users"]
        print(f"[+] Group {GROUP_NAME} now contains {len(users_in_group)} users:")
        for user in users_in_group:
            username = user["username"]
            is_admin = user["_joinData"]["is_admin"]
            print(f"    - {username} ({'Admin' if is_admin else 'Member'})")
    else:
        print("[!] Could not verify group membership - unexpected response structure")
        print(f"Response: {json.dumps(group_details, indent=2)}")

    print("\n=== Operation Completed Successfully ===")
    print(f"Group '{GROUP_NAME}' created with ID: {group_id}")
    print(f"User '{USER_EMAIL}' added to the group")

if __name__ == "__main__":
    main()
