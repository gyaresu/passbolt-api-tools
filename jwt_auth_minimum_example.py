#!/usr/bin/env python3
"""
Minimal Passbolt JWT Authentication Example with hardcoded values

This script demonstrates the complete JWT authentication flow with Passbolt:
1. GPG Key Setup: Import and verify your private key
2. Server Key Exchange: Get and trust the server's public key
3. Challenge Creation: Create and encrypt an authentication challenge
4. JWT Authentication: Exchange the challenge for JWT tokens
5. Response Decryption: Decrypt and verify the server's response

The authentication process uses GPG encryption to ensure secure communication
between the client and Passbolt server. This is a requirement for all Passbolt
API interactions.
"""

import os
import json
import uuid
import time
import subprocess
import requests
import tempfile
import shutil

# ============================================================================
# Configuration
# ============================================================================
# These values would typically come from environment variables or a config file
# in a production environment. They are hardcoded here for demonstration.
API_URL = "https://passbolt.local"  # Your Passbolt instance URL
USER_ID = "0460d687-f393-490a-b710-79f333aae3b1"
PRIVATE_KEY_PATH = "ada_private.key"  # Path to Ada's GPG private key
KEY_PASSPHRASE = "ada@passbolt.com"  # Ada's GPG key passphrase

# ============================================================================
# How to get the User ID:
# 1. Log into Passbolt web interface
# 2. Go to "Users & Groups"
# 3. Click on "Ada Lovelace"
# 4. The user ID is in the URL path: /app/users/view/{user_id}
# 5. Example: https://passbolt.local/app/users/view/8599f576-9775-4ebc-a7cb-d102de1d46dd
# ============================================================================

def main():
    # ============================================================================
    # Step 1: GPG Key Setup
    # ============================================================================
    # Create an isolated GPG environment to prevent interference with system keys
    temp_gpg_home = tempfile.mkdtemp(prefix="tmp_gpg_home_")
    gpg_env = os.environ.copy()
    gpg_env["GNUPGHOME"] = temp_gpg_home

    try:
        print("[*] Setting up GPG...")
        # Import your private key into the temporary GPG environment
        subprocess.run(
            ["gpg", "--batch", "--yes", "--import", PRIVATE_KEY_PATH],
            env=gpg_env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Get your key's fingerprint - this is required for signing messages
        list_result = subprocess.run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            env=gpg_env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Extract fingerprint from GPG output
        fingerprint = None
        for line in list_result.stdout.splitlines():
            if line.startswith("fpr:"):
                fingerprint = line.split(":")[9]
                break

        if not fingerprint:
            raise Exception("Failed to extract fingerprint")

        print(f"[+] Using key: {fingerprint}")

        # ============================================================================
        # Step 2: Server Key Exchange
        # ============================================================================
        # Get the server's public key and CSRF token
        print("[*] Getting server key...")
        session = requests.Session()
        response = session.get(f"{API_URL}/auth/verify.json", verify=False)
        data = response.json()

        # CSRF token is required for all POST requests to prevent cross-site request forgery
        csrf_token = None
        for cookie in session.cookies:
            if cookie.name == "csrfToken":
                csrf_token = cookie.value
                break

        if not csrf_token:
            raise Exception("Failed to get CSRF token")

        # Get and import the server's public key
        server_key_data = data["body"]["keydata"]
        server_key_fpr = data["body"]["fingerprint"]

        # Save and import server key
        server_key_path = os.path.join(temp_gpg_home, "server_key.asc")
        with open(server_key_path, "w") as f:
            f.write(server_key_data)

        subprocess.run(
            ["gpg", "--batch", "--yes", "--import", server_key_path],
            env=gpg_env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Trust the server key (level 6 = ultimate trust)
        trust_input = f"{server_key_fpr}:6:\n"
        subprocess.run(
            ["gpg", "--import-ownertrust"],
            input=trust_input,
            env=gpg_env,
            text=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # ============================================================================
        # Step 3: Challenge Creation
        # ============================================================================
        # Create a challenge that will be encrypted and sent to the server
        # The challenge is a JSON payload that must be signed and encrypted using GPG.
        # This is a security measure to ensure the request comes from a legitimate user
        # with access to the private key.
        #
        # Challenge Payload Structure:
        # - version: Protocol version (1.0.0)
        # - domain: The Passbolt instance URL (must match the server's domain)
        # - verify_token: A unique UUID to prevent replay attacks
        # - verify_token_expiry: Unix timestamp for when the challenge expires (5 minutes)
        #
        # Documentation:
        # - JWT Authentication: https://www.passbolt.com/docs/development/authentication/#jwt-authentication
        # - API Reference: https://www.passbolt.com/docs/api/#tag/Authentication-(JWT)
        print("[*] Creating and encrypting challenge...")
        challenge_token = str(uuid.uuid4()).lower()
        challenge_payload = {
            "version": "1.0.0",  # Protocol version
            "domain": API_URL,   # Must match the server's domain
            "verify_token": challenge_token,  # Unique token to prevent replay attacks
            "verify_token_expiry": int(time.time()) + 300  # 5 minutes expiry
        }

        # Write challenge to a temporary file
        # The challenge must be in a file for GPG to sign and encrypt it
        challenge_path = os.path.join(temp_gpg_home, "challenge.json")
        with open(challenge_path, "w") as f:
            json.dump(challenge_payload, f, separators=(',', ':'))

        # Sign the challenge with your private key and encrypt it with the server's public key
        # This ensures:
        # 1. Only the server can read the challenge (encryption with server's public key)
        # 2. The challenge came from the user (signature with user's private key)
        # 3. The challenge hasn't been tampered with (signature)
        encrypted_path = os.path.join(temp_gpg_home, "challenge.enc")
        subprocess.run([
            "gpg", "--batch", "--yes",
            "--pinentry-mode", "loopback",
            "--passphrase", KEY_PASSPHRASE,
            "--trust-model", "always",
            "--sign", "--encrypt", "--armor",
            "--recipient", server_key_fpr,
            "--local-user", fingerprint,
            "--output", encrypted_path, challenge_path
        ], env=gpg_env, check=True)

        # Read the encrypted challenge
        # The encrypted challenge will be sent to the server in the next step
        with open(encrypted_path, "r") as f:
            encrypted_challenge = f.read()

        # ============================================================================
        # Step 4: JWT Authentication
        # ============================================================================
        # Send the encrypted challenge to get JWT tokens
        print("[*] Sending authentication request...")
        request_body = {
            "user_id": USER_ID,
            "challenge": encrypted_challenge
        }

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

        jwt_data = jwt_response.json()

        # Verify the authentication was successful
        if jwt_data.get("header", {}).get("status") != "success":
            raise Exception(f"Authentication failed: {jwt_data['header'].get('message')}")

        # ============================================================================
        # Step 5: Response Decryption
        # ============================================================================
        # Decrypt the server's response which contains the JWT tokens
        print("[*] Decrypting server response...")
        encrypted_response = jwt_data["body"]["challenge"]

        response_path = os.path.join(temp_gpg_home, "response.asc")
        decrypted_path = os.path.join(temp_gpg_home, "response.json")

        with open(response_path, "w") as f:
            f.write(encrypted_response)

        subprocess.run([
            "gpg", "--batch", "--yes",
            "--pinentry-mode", "loopback",
            "--passphrase", KEY_PASSPHRASE,
            "--decrypt", "--output", decrypted_path, response_path
        ], env=gpg_env, check=True)

        # Read and parse the JWT tokens
        with open(decrypted_path, "r") as f:
            token_data = json.load(f)

        # Display the tokens and authorization header
        print("\n=== JWT Authentication Successful ===")
        print(f"Access Token: {token_data['access_token'][:50]}...")
        print(f"Refresh Token: {token_data['refresh_token']}")
        print("\n=== API Authorization Header ===")
        print(f"Authorization: Bearer {token_data['access_token']}")

    finally:
        # Clean up temporary files and GPG environment
        print("\n[*] Cleaning up...")
        if os.path.exists(temp_gpg_home):
            shutil.rmtree(temp_gpg_home)

if __name__ == "__main__":
    main()
