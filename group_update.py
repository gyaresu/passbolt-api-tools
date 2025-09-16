#!/usr/bin/env python3
"""
Script to create a group and manage user permissions in Passbolt.
Uses JWT authentication and handles existing groups and admin status changes.

Configuration is loaded from .env file with the following variables:
- USER_ID: Your Passbolt user ID (required)
- URL: Passbolt server URL (default: https://passbolt.local)
- KEY_FILE: Path to GPG private key file (default: ada_private.key)
- PASSPHRASE: GPG key passphrase (default: ada@passbolt.com)
- USER_EMAIL: Email of the user to add to the group (default: betty@passbolt.com)
- GROUP_NAME: Name of the group to create/use (default: Test Group)
- USER_FPR: Your GPG key fingerprint (default: 03F60E958F4CB29723ACDF761353B5B15D9B054F)

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
    
    # Toggle admin status for existing user
    python3 group_update.py --user-email "betty@passbolt.com" --group-name "Test Group" --toggle-admin
    
    # Set specific admin status
    python3 group_update.py --user-email "betty@passbolt.com" --group-name "Test Group" --set-admin true
    
    # Remove user from group
    python3 group_update.py --user-email "betty@passbolt.com" --group-name "Test Group" --remove-user
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
from dotenv import load_dotenv

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Create a Passbolt group and manage user permissions",
        epilog='''
Examples:
  # Add a user to a group
  %(prog)s --user-email "user@example.com" --group-name "My Group"
  
  # Toggle admin status for existing user
  %(prog)s --user-email "user@example.com" --group-name "My Group" --toggle-admin
  
  # Remove user from group
  %(prog)s --user-email "user@example.com" --group-name "My Group" --remove-user
  
  # Delete entire group
  %(prog)s --group-name "My Group" --delete-group
  
  # Set specific admin status
  %(prog)s --user-email "user@example.com" --group-name "My Group" --set-admin true

Configuration:
  Set up a .env file with:
  USER_ID=your-user-id-here
  URL=https://passbolt.local
  KEY_FILE=your_private.key
  PASSPHRASE=your-passphrase
  USER_EMAIL=default@example.com
  GROUP_NAME=Default Group
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--user-email", help="Email of the user to add to the group")
    parser.add_argument("--group-name", help="Name of the group to create/use")
    parser.add_argument("--passbolt-url", help="Passbolt instance URL")
    parser.add_argument("--user-id", help="Your Passbolt user ID")
    parser.add_argument("--private-key", help="Path to your GPG private key file")
    parser.add_argument("--passphrase", help="Your GPG key passphrase")
    parser.add_argument("--fingerprint", help="Your GPG key fingerprint")
    parser.add_argument("--toggle-admin", action="store_true", 
                       help="Toggle admin status for the specified user (if already in group)")
    parser.add_argument("--set-admin", choices=["true", "false"], 
                       help="Set admin status to true or false for the specified user")
    parser.add_argument("--delete-group", action="store_true",
                       help="Delete the specified group")
    parser.add_argument("--remove-user", action="store_true",
                       help="Remove the specified user from the group")
    return parser.parse_args()

# Load configuration from .env file
load_dotenv()

# Configuration - Set these or use environment variables
PASSBOLT_URL = os.getenv("URL", "https://passbolt.local")
USER_ID = os.getenv("USER_ID", "8baca8bd-3bde-4ab6-96d6-f65492ce2791")  # Ada's user ID
USER_EMAIL = os.getenv("USER_EMAIL", "betty@passbolt.com")  # User to add to group
GROUP_NAME = os.getenv("GROUP_NAME", "Test Group")  # Group name
PRIVATE_KEY_PATH = os.getenv("KEY_FILE", "ada_private.key")  # Your private key
KEY_PASSPHRASE = os.getenv("PASSPHRASE", "ada@passbolt.com")  # Your passphrase
USER_FPR = os.getenv("USER_FPR", "03F60E958F4CB29723ACDF761353B5B15D9B054F")  # Your fingerprint

def import_private_key(key_path):
    """Import private key into GPG."""
    subprocess.run(["gpg", "--batch", "--yes", "--import", key_path],
                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def get_jwt_token():
    """Get JWT token using GPG authentication."""
    session = requests.Session()
    resp = session.get(f"{PASSBOLT_URL}/auth/verify.json?api-version=v2", verify=False)
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

    resp = session.post(f"{PASSBOLT_URL}/auth/jwt/login.json?api-version=v2", headers=headers, json=login_body, verify=False)
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
    # Add API version if not already present
    separator = "&" if "?" in path else "?"
    url = f"{PASSBOLT_URL}{path}{separator}api-version=v2"
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
    # Add API version if not already present
    separator = "&" if "?" in path else "?"
    url = f"{PASSBOLT_URL}{path}{separator}api-version=v2"
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
    # Add API version if not already present
    separator = "&" if "?" in path else "?"
    url = f"{PASSBOLT_URL}{path}{separator}api-version=v2"
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

def api_delete(path, jwt_token):
    """Helper function for DELETE requests."""
    # Add API version if not already present
    separator = "&" if "?" in path else "?"
    url = f"{PASSBOLT_URL}{path}{separator}api-version=v2"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json"
    }
    resp = requests.delete(url, headers=headers, verify=False)
    if resp.status_code != 200:
        print(f"[!] API Error: {resp.status_code}")
        print(f"[!] Response: {resp.text}")
    resp.raise_for_status()
    return resp.json()

def main():
    # Parse command line arguments
    args = parse_arguments()
    
    # Check if any explicit action is provided
    has_explicit_action = any([
        args.user_email,
        args.group_name,
        args.toggle_admin,
        args.set_admin is not None,
        args.delete_group,
        args.remove_user
    ])
    
    # If no explicit action, show help and exit
    if not has_explicit_action:
        print("Error: No action specified. This script requires explicit parameters for safety.")
        print("\nUse --help to see available options and examples.")
        print("\nQuick examples:")
        print("  # Add a user to a group")
        print("  python group_update.py --user-email 'user@example.com' --group-name 'My Group'")
        print("  # List groups (requires explicit parameters)")
        print("  python group_update.py --group-name 'Test Group' --user-email 'betty@passbolt.com'")
        return 1
    
    # Configuration validation
    if not USER_ID:
        print("Error: USER_ID is required. Please set it in your .env file:")
        print("  USER_ID=your-user-id-here")
        return 1
    
    if not os.path.exists(PRIVATE_KEY_PATH):
        print(f"Error: GPG key file not found: {PRIVATE_KEY_PATH}")
        print(f"Please check that the file exists and the path is correct.")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Looking for key file: {os.path.abspath(PRIVATE_KEY_PATH)}")
        return 1

    # Override configuration with command line arguments
    passbolt_url = args.passbolt_url or PASSBOLT_URL
    user_id = args.user_id or USER_ID
    user_email = args.user_email or USER_EMAIL
    group_name = args.group_name or GROUP_NAME
    private_key_path = args.private_key or PRIVATE_KEY_PATH
    key_passphrase = args.passphrase or KEY_PASSPHRASE
    user_fpr = args.fingerprint or USER_FPR

    print("=== Passbolt Group User Test ===")
    print(f"Target User: {user_email}")
    print(f"Group Name: {group_name}")
    print()

    # Validate configuration
    if not all([passbolt_url, user_id, user_email, group_name, private_key_path, key_passphrase, user_fpr]):
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
        print("[+] JWT token obtained")
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

        # Handle group deletion if requested
        if args.delete_group:
            print(f"[*] Deleting group: {GROUP_NAME}")
            try:
                api_delete(f"/groups/{group_id}.json", jwt_token)
                print(f"[+] Group '{GROUP_NAME}' deleted")
                print(f"\n=== Operation Complete ===")
                print(f"Group '{GROUP_NAME}' was deleted")
                return
            except Exception as e:
                print(f"[!] Failed to delete group: {e}")
                return

        # Check if the target user is already in the group
        users_in_group = existing_group.get("users", [])
        user_already_in_group = any(user.get("username") == USER_EMAIL for user in users_in_group)

        if user_already_in_group:
            print(f"[+] User {USER_EMAIL} is already in the group")
            
            # Check if admin management is requested
            if args.toggle_admin or args.set_admin is not None:
                print(f"[*] Admin management requested for existing user")
                # We'll handle this in the admin management section
        else:
            print(f"[*] User {USER_EMAIL} is not in the group, will add them")
    else:
        print(f"[*] Group '{GROUP_NAME}' does not exist, creating new group...")

        # Create group with both current user and target user
        group_data = {
            "name": GROUP_NAME,
            "groups_users": [
                {
                    "user_id": USER_ID,  # Current user as group manager
                    "is_admin": True
                },
                {
                    "user_id": target_user_id,  # Target user
                    "is_admin": False
                }
            ]
        }

        group_response = api_post("/groups.json", group_data, jwt_token)
        group_id = group_response["body"]["id"]
        print(f"[+] Group created: {group_id}")
        user_already_in_group = True  # User is now in the group

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
            print(f"[+] User {USER_EMAIL} added to group {GROUP_NAME}")
        except Exception as e:
            print(f"[!] Failed to add user to existing group: {e}")
            return
    else:
        print(f"[+] User {USER_EMAIL} is already in the group")

    # ============================================================================
    # Step 3.5: Admin Management (if requested)
    # ============================================================================
    if user_already_in_group and (args.toggle_admin or args.set_admin is not None):
        print(f"[*] Managing admin status for user {USER_EMAIL}...")
        
        # Get detailed group information to find the user's group relationship ID
        group_details = api_get(f"/groups/{group_id}.json?contain[users]=1", jwt_token=jwt_token)
        
        if "body" not in group_details or "users" not in group_details["body"]:
            print("[!] Could not retrieve group details for admin management")
            return
            
        # Find the target user in the group and get their current admin status
        target_user_in_group = None
        for user in group_details["body"]["users"]:
            if user.get("username") == USER_EMAIL:
                target_user_in_group = user
                break
                
        if not target_user_in_group:
            print(f"[!] User {USER_EMAIL} not found in group details")
            return
            
        current_admin_status = target_user_in_group["_joinData"]["is_admin"]
        group_user_id = target_user_in_group["_joinData"]["id"]
        
        print(f"[*] Current admin status: {current_admin_status}")
        
        # Determine new admin status
        new_admin_status = current_admin_status
        if args.toggle_admin:
            new_admin_status = not current_admin_status
            print(f"[*] Toggling admin status from {current_admin_status} to {new_admin_status}")
        elif args.set_admin is not None:
            new_admin_status = args.set_admin.lower() == "true"
            print(f"[*] Setting admin status to {new_admin_status}")
            
        if new_admin_status == current_admin_status:
            print(f"[+] Admin status is already {new_admin_status}, no change needed")
        else:
            # Build the complete groups_users array with all existing users
            groups_users_update = []
            for user in group_details["body"]["users"]:
                user_group_data = {
                    "id": user["_joinData"]["id"],  # Use the group relationship ID
                    "is_admin": user["_joinData"]["is_admin"]
                }
                
                # Update the target user's admin status
                if user.get("username") == USER_EMAIL:
                    user_group_data["is_admin"] = new_admin_status
                    
                groups_users_update.append(user_group_data)
            
            update_group_data = {
                "groups_users": groups_users_update,
                "secrets": []
            }
            
            print(f"[*] Sending admin update payload: {json.dumps(update_group_data, indent=2)}")
            
            try:
                api_put(f"/groups/{group_id}.json", update_group_data, jwt_token)
                print(f"[+] Admin status updated for {USER_EMAIL} to {new_admin_status}")
            except Exception as e:
                print(f"[!] Failed to update admin status: {e}")
                return

    # ============================================================================
    # Step 3.6: Remove User from Group (if requested)
    # ============================================================================
    if args.remove_user and user_already_in_group:
        print(f"[*] Removing user {USER_EMAIL} from group...")
        
        # Get detailed group information
        group_details = api_get(f"/groups/{group_id}.json?contain[users]=1", jwt_token=jwt_token)
        
        if "body" not in group_details or "users" not in group_details["body"]:
            print("[!] Could not retrieve group details for user removal")
            return
            
        # Build the groups_users array - only include the user to be deleted
        groups_users_update = []
        for user in group_details["body"]["users"]:
            if user.get("username") == USER_EMAIL:
                user_group_data = {
                    "id": user["_joinData"]["id"],  # Use the group relationship ID
                    "delete": True
                }
                print(f"[*] Marking user {USER_EMAIL} for deletion")
                groups_users_update.append(user_group_data)
                break  # Only include the user to be deleted
        
        update_group_data = {
            "groups_users": groups_users_update,
            "secrets": []
        }
        
        print(f"[*] Sending user removal payload: {json.dumps(update_group_data, indent=2)}")
        
        try:
            api_put(f"/groups/{group_id}.json", update_group_data, jwt_token)
            print(f"[+] Removed {USER_EMAIL} from group {GROUP_NAME}")
            
            # Refresh the group check after removal
            print(f"[*] Refreshing group membership check...")
            refresh_group_response = api_get(f"/groups/{group_id}.json?contain[users]=1", jwt_token=jwt_token)
            if "body" in refresh_group_response and "users" in refresh_group_response["body"]:
                refresh_users_in_group = refresh_group_response["body"]["users"]
                user_still_in_group = any(user.get("username") == USER_EMAIL for user in refresh_users_in_group)
                if not user_still_in_group:
                    print(f"[+] Confirmed: {USER_EMAIL} has been removed from the group")
                else:
                    print(f"[!] Warning: {USER_EMAIL} is still showing in the group after removal")
        except Exception as e:
            print(f"[!] Failed to remove user from group: {e}")
            return
    elif args.remove_user and not user_already_in_group:
        print(f"[!] User {USER_EMAIL} is not in the group, cannot remove")

    # ============================================================================
    # Step 4: Verify Group Membership
    # ============================================================================
    print("[*] Verifying group membership...")

    # Always fetch fresh group details for verification
    verification_group_details = api_get(f"/groups/{group_id}.json?contain[users]=1", jwt_token=jwt_token)

    if "body" in verification_group_details and "users" in verification_group_details["body"]:
        users_in_group = verification_group_details["body"]["users"]
        print(f"[+] Group {GROUP_NAME} now contains {len(users_in_group)} users:")
        for user in users_in_group:
            username = user["username"]
            is_admin = user["_joinData"]["is_admin"]
            print(f"    - {username} ({'Admin' if is_admin else 'Member'})")
    else:
        print("[!] Could not verify group membership - unexpected response structure")
        print(f"Response: {json.dumps(verification_group_details, indent=2)}")

    print(f"\n=== Operation Complete ===")
    print(f"Group '{GROUP_NAME}' created with ID: {group_id}")
    
    # Determine what operation was performed based on arguments
    if args.remove_user:
        print(f"User '{USER_EMAIL}' was removed from the group")
    elif args.toggle_admin or args.set_admin is not None:
        print(f"Admin status for '{USER_EMAIL}' was managed")
    elif args.delete_group:
        print(f"Group '{GROUP_NAME}' was deleted")
    else:
        print(f"User '{USER_EMAIL}' added to the group")

if __name__ == "__main__":
    main()
