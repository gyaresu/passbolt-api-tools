#!/usr/bin/env python3
"""
Encrypt Secrets for Bruno

This script encrypts a secret string using GPG and injects it into a Bruno .bru file.
It's designed to work with Passbolt's API and Bruno's request format.

Features:
- GPG encryption of secrets using a specified recipient's public key
- Injection of encrypted secrets into Bruno request files
- Support for updating metadata fields (name, username, URI, description)
- Preserves Bruno's double-brace file structure (outer for config, inner for JSON)
- Updates only the first secret in the secrets array
- Maintains Bruno's file formatting and indentation

Usage:
    python3 encrypt_secrets_for_bruno.py \
        --secret "my-secret" \
        --fingerprint "GPG_FINGERPRINT" \
        --bruno-file "path/to/request.bru" \
        [--name "Secret Name"] \
        [--username "username"] \
        [--uri "https://example.com"] \
        [--description "Secret description"]

Example:
    # Basic secret encryption and injection
    python3 encrypt_secrets_for_bruno.py \
        --secret "test3" \
        --fingerprint 03F60E958F4CB29723ACDF761353B5B15D9B054F \
        --bruno-file ".bruno_env/docker/requests/Create Super Secret.bru"

    # Full metadata update
    python3 encrypt_secrets_for_bruno.py \
        --secret "test3" \
        --fingerprint 03F60E958F4CB29723ACDF761353B5B15D9B054F \
        --bruno-file ".bruno_env/docker/requests/Create Super Secret.bru"
        --name "test3" \
        --username "test3" \
        --uri "https://test3" \
        --description "test3"

Security Notes:
- The secret is encrypted using the recipient's public key
- The encrypted secret is stored in the Bruno request file
- The original secret is never stored on disk
- GPG encryption uses the recipient's public key for secure transmission
"""

import argparse
import subprocess
import json
import os
import sys

def encrypt_secret(plaintext: str, recipient_fpr: str) -> str:
    """
    Encrypt the plaintext using the provided GPG fingerprint.
    
    Args:
        plaintext (str): The secret text to encrypt
        recipient_fpr (str): GPG fingerprint of the recipient's public key
        
    Returns:
        str: The encrypted and armored OpenPGP message
        
    Raises:
        SystemExit: If GPG encryption fails
    """
    print(f"[*] Encrypting with GPG recipient: {recipient_fpr}")
    try:
        result = subprocess.run(
            [
                "gpg", "--armor", "--batch", "--yes",
                "--trust-model", "always",
                "--encrypt", "--recipient", recipient_fpr
            ],
            input=plaintext,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        print("[*] Encryption completed.")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print("[!] GPG encryption failed:")
        print(e.stderr)
        sys.exit(1)

def inject_secret_fields(bruno_file_path: str, encrypted_data: str, 
                        name: str = None, username: str = None, 
                        uri: str = None, description: str = None) -> None:
    """
    Inject encrypted data and metadata into a Bruno request file.
    
    This function:
    1. Locates the body:json block in the Bruno request file
    2. Finds the inner JSON object (between the double braces)
    3. Updates the specified metadata fields
    4. Replaces the secret data in the first secret entry
    5. Preserves Bruno's file structure and formatting
    
    Bruno File Structure:
    body:json {
      {  # Outer brace for Bruno config
        "name": "Secret Name",  # Inner brace for JSON payload
        "secrets": [
          {
            "data": "...",
            "user_id": "{{user_id}}"
          }
        ]
      }
    }
    
    Args:
        bruno_file_path (str): Path to the Bruno .bru file
        encrypted_data (str): The encrypted secret to inject
        name (str, optional): New name for the secret
        username (str, optional): New username for the secret
        uri (str, optional): New URI for the secret
        description (str, optional): New description for the secret
        
    Raises:
        SystemExit: If file operations or JSON parsing fails
    """
    print(f"[*] Updating Bruno request: {bruno_file_path}")
    if not os.path.exists(bruno_file_path):
        print(f"[!] Bruno request file not found: {bruno_file_path}")
        sys.exit(1)

    with open(bruno_file_path, "r") as f:
        lines = f.readlines()

    # Locate 'body:json' and start of JSON
    body_start_idx = next((i for i, line in enumerate(lines) if "body:json" in line), -1)
    if body_start_idx == -1:
        print("[!] Could not find 'body:json' block.")
        sys.exit(1)

    json_open_idx = next((i for i in range(body_start_idx + 1, len(lines)) if "{" in lines[i]), -1)
    if json_open_idx == -1:
        print("[!] Could not find opening brace for JSON.")
        sys.exit(1)

    # Extract block with balanced braces
    brace_count = 0
    json_lines = []
    start_idx = json_open_idx
    end_idx = -1

    for i in range(start_idx, len(lines)):
        brace_count += lines[i].count("{")
        brace_count -= lines[i].count("}")
        json_lines.append(lines[i])
        if brace_count == 0:
            end_idx = i
            break

    if end_idx == -1:
        print("[!] Could not find the matching closing brace for JSON body.")
        sys.exit(1)

    raw_json = "".join(json_lines)
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as e:
        print(f"[!] JSON decode error: {e}")
        print("[*] Raw extracted JSON:")
        print(raw_json)
        sys.exit(1)

    # Update fields
    if name: payload["name"] = name
    if username: payload["username"] = username
    if uri: payload["uri"] = uri
    if description: payload["description"] = description

    if "secrets" in payload and isinstance(payload["secrets"], list):
        payload["secrets"][0]["data"] = encrypted_data
    else:
        print("[!] No 'secrets' array found in body JSON.")
        sys.exit(1)

    new_json = json.dumps(payload, indent=2)
    new_block = [f"  {line}\n" for line in new_json.splitlines()]

    updated_lines = lines[:start_idx] + new_block + lines[end_idx + 1:]

    with open(bruno_file_path, "w") as f:
        f.writelines(updated_lines)

    print("[+] Secret and metadata injected successfully.")

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Encrypt a secret and inject it into a Bruno .bru request file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--secret", required=True, help="The plaintext secret to encrypt")
    parser.add_argument("--fingerprint", required=True, help="GPG fingerprint to encrypt the secret to")
    parser.add_argument("--bruno-file", required=True, help="Path to the Bruno .bru file to inject into")
    parser.add_argument("--name", help="Secret name to update in the .bru file")
    parser.add_argument("--username", help="Username to update in the .bru file")
    parser.add_argument("--uri", help="URI to update in the .bru file")
    parser.add_argument("--description", help="Description to update in the .bru file")
    args = parser.parse_args()

    print("[*] Starting secret encryption + Bruno injection...")
    encrypted = encrypt_secret(args.secret, args.fingerprint)

    print("\n=== Encrypted OpenPGP Secret ===")
    print(encrypted[:300] + ("..." if len(encrypted) > 300 else ""))
    print()

    inject_secret_fields(
        args.bruno_file,
        encrypted,
        name=args.name,
        username=args.username,
        uri=args.uri,
        description=args.description
    )

if __name__ == "__main__":
    main()
