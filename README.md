# Passbolt API Examples

## Quick Reference

- **JWT authentication and API testing:**
  `python3 jwt_auth_with_api_test.py`
- **JWT authentication with Bruno support:**
  `python3 jwt_api_with_bruno_support.py`
- **JWT authentication (minimal example):**
  `python3 jwt_auth_minimum_example.py`
- **Automatic JWT token refresh:**
  `python3 loop_refresh_jwt_token.py`
- **Group management (create groups and add users):**
  `python3 group_update.py`
- **Legacy GPG authentication (shell):**
  `./passbolt-gpgauth-example.sh`
- **Decrypt and display all resource metadata/passwords (table):**
  `python3 passbolt_api_metadata_client.py`

## Prerequisites

- Python 3.6+
- GPG 2.1+
- Bruno API Client (for Bruno integration)
- Passbolt account with GPG key

## Setup

### GPG Key Setup
To use these scripts, you'll need your GPG private key from Passbolt:

1. Log into your Passbolt instance
2. Click on your avatar in the top right
3. Click "Key Inspector"
4. Click the "Private" button to export your private key
5. Save the key file (e.g., `ada_private.key`)
6. Note your key's fingerprint (shown in the Keys section)

The exported key file and fingerprint will be used in the examples below.

### Getting Your User ID and Fingerprint
For scripts that require your Passbolt user ID and GPG fingerprint:

**PASSBOLT_USER_ID**: Your unique user ID in Passbolt. Log in to your Passbolt web interface, go to **Users & Groups**, click on your user entry, and look at the URL in your browser. It will look like `https://your-passbolt-instance/app/users/view/8599f576-9775-4ebc-a7cb-d102de1d46dd` - the long string at the end is your user ID.

**GPG_FINGERPRINT**: Your GPG key fingerprint. Log into your Passbolt instance, click on your avatar in the top right, click "Key Inspector", and you'll see your fingerprint in the Keys section (e.g., `03F60E958F4CB29723ACDF761353B5B15D9B054F`).

**Note**: Some scripts (like `jwt_api_with_bruno_support.py` and `jwt_auth_with_api_test.py`) require the private key to be imported into your local GPG keyring for validation. Export your private key from Passbolt, import it with `gpg --import your_private_key.asc`, and the script will validate the fingerprint exists in your keyring before proceeding.

### Python Environment
```bash
# Create a new virtual environment
python3 -m venv venv

# Activate the virtual environment
# On Unix/macOS:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate

# Install required packages
pip3 install requests python-dotenv pyyaml
```

### Required Packages
The scripts require the following external packages:
```
requests>=2.32.3
python-dotenv>=1.0.0
pyyaml>=6.0.1
tabulate>=0.9.0
```

All other dependencies are part of Python's standard library.

## Examples

### 1. JWT Authentication with API Testing
Script (`jwt_auth_with_api_test.py`) showing:
- Complete JWT authentication flow
- API testing capabilities
- Error handling
- Token management
- No Bruno integration

```bash
# Using a key from GPG keyring
python3 jwt_auth_with_api_test.py \
    --url "https://passbolt.local" \
    --user-id "YOUR_ID" \
    --fingerprint "YOUR_KEY" \
    --passphrase "your-passphrase" \
    --insecure

# Using a local key file
python3 jwt_auth_with_api_test.py \
    --url "https://passbolt.local" \
    --user-id "YOUR_ID" \
    --key-file "./ada_private.key" \
    --passphrase "your-passphrase" \
    --insecure

# Test API access after authentication
python3 jwt_auth_with_api_test.py \
    --url "https://passbolt.local" \
    --user-id "YOUR_ID" \
    --fingerprint "YOUR_KEY" \
    --passphrase "your-passphrase" \
    --insecure \
    --test
```

### 2. JWT Authentication with Bruno Support
Script (`jwt_api_with_bruno_support.py`) for Bruno integration:
- JWT authentication with Passbolt API
- Bruno API client integration
- Environment variable management
- Secret encryption and injection
- Multiple output formats (Bruno, curl, JSON)

The script will automatically create and update your Bruno environment file (e.g., `.bruno_env/docker/environments/local.bru`) with:
```hcl
vars {
  host: https://passbolt.local
  jwt_token: <JWT token>
  user_id: 8599f576-9775-4ebc-a7cb-d102de1d46dd
}
```

These variables can then be used in your Bruno requests with `{{host}}`, `{{jwt_token}}`, and `{{user_id}}`.

Note: The script will automatically create the Bruno environment file and directory structure if they don't exist.

```bash
# Basic usage with GPG keyring (local instance)
python3 jwt_api_with_bruno_support.py \
    --url "https://passbolt.local" \
    --user-id "8599f576-9775-4ebc-a7cb-d102de1d46dd" \
    --fingerprint "03F60E958F4CB29723ACDF761353B5B15D9B054F" \
    --passphrase "ada@passbolt.com" \
    --insecure

# Basic usage with key file (local instance)
python3 jwt_api_with_bruno_support.py \
    --url "https://passbolt.local" \
    --user-id "8599f576-9775-4ebc-a7cb-d102de1d46dd" \
    --key-file "./ada_private.key" \
    --passphrase "ada@passbolt.com" \
    --insecure

# With Bruno environment configuration (local instance)
python3 jwt_api_with_bruno_support.py \
    --url "https://passbolt.local" \
    --user-id "8599f576-9775-4ebc-a7cb-d102de1d46dd" \
    --fingerprint "03F60E958F4CB29723ACDF761353B5B15D9B054F" \
    --passphrase "ada@passbolt.com" \
    --insecure \
    --bruno-format \
    --bruno-env-path ".bruno_env/docker/environments" \
    --bruno-env-name "local"

# Cloud instance
python3 jwt_api_with_bruno_support.py \
    --url "https://cloud.passbolt.com/userexample" \
    --user-id "YOUR_USER_ID" \
    --fingerprint "YOUR_GPG_FINGERPRINT" \
    --passphrase "YOUR_PASSPHRASE"
```

### 3. Automatic JWT Token Refresh
Script (`loop_refresh_jwt_token.py`) for automatic JWT token refresh:
- Runs the JWT authentication script at regular intervals
- Supports configuration via environment variables or YAML
- Handles errors and provides status updates
- Can be configured for different environments

```bash
# Using environment variables
python3 loop_refresh_jwt_token.py --env-file .env

# Using command line arguments
python3 loop_refresh_jwt_token.py \
    --url "https://passbolt.local" \
    --user-id "YOUR_ID" \
    --fingerprint "YOUR_KEY" \
    --passphrase "your-passphrase" \
    --insecure \
    --bruno-format \
    --bruno-env-path ".bruno_env/docker/environments" \
    --bruno-env-name "local" \
    --interval 300
```

Example `.env` file:
```env
URL=https://passbolt.local
USER_ID=8599f576-9775-4ebc-a7cb-d102de1d46dd
FINGERPRINT=03F60E958F4CB29723ACDF761353B5B15D9B054F
PASSPHRASE=ada@passbolt.com
INSECURE=true
BRUNO_FORMAT=true
BRUNO_ENV_PATH=.bruno_env/docker/environments
BRUNO_ENV_NAME=local
```

### 4. Group Management
Script (`group_update.py`) for creating groups and adding users. The script handles JWT authentication, group creation and management, user addition to existing groups, duplicate prevention, and supports both environment variables and command line arguments.

```bash
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

# Full configuration via command line
python3 group_update.py \
    --passbolt-url "https://passbolt.local" \
    --user-id "your-user-id" \
    --user-email "user@example.com" \
    --group-name "My Group" \
    --private-key "path/to/private.key" \
    --passphrase "your-passphrase" \
    --fingerprint "your-fingerprint"
```

### 5. Legacy GPG Authentication
Script (`passbolt-gpgauth-example.sh`) for legacy GPG authentication:
- Traditional GPG authentication
- Challenge/response flow
- Session management
- Basic API interaction

```bash
./passbolt-gpgauth-example.sh
```

### 6. Decrypt and Display All Resource Metadata (passbolt_api_metadata_client.py)

This script fetches all resources Ada can access from a Passbolt v5 instance, decrypts their metadata and passwords, and displays the results in a table. It is intended for educational/demo use with test data.

#### Setup
1. Export Ada's private key from Passbolt (see GPG Key Setup above).
2. Place the key file (e.g., `ada_private.key`) in the project directory.
3. Edit the script to set:
   - `PASSBOLT_URL` (default: `https://passbolt.local`)
   - `ADA_PRIVATE_KEY_PATH` (default: `ada_private.key`)
   - `ADA_PRIVATE_KEY_PASSPHRASE` (default: `ada@passbolt.com`)
   - `PASSBOLT_USER_ID` and `PASSBOLT_USER_FPR` (see Getting Your User ID and Fingerprint above)
4. Ensure GPG is installed and available in your PATH.

#### Usage
Run the script:
```bash
python3 passbolt_api_metadata_client.py
```

The script will:
- Authenticate to Passbolt using JWT and Ada's private key
- Fetch all resources Ada can access
- Decrypt each resource's metadata and password
- Display a table with columns:
  - Name, ID, Password, TOTP, Custom Fields, Username, URL, Description, Icon

**Sample Output (truncated for readability):**
```
+-----------------------+----------+--------------------+----------------+-------------------------------+
| Name                  | ID       | Password           | Username       | URL                           |
+=======================+==========+====================+================+===============================+
| e2ee test             | 5c90c883 | N$=hY=K6v@h,&f)iT9 | edith          | https://example.com, ...      |
+-----------------------+----------+--------------------+----------------+-------------------------------+
```
*Table truncated for readability. Actual output includes TOTP, Custom Fields, Description, Icon, etc.*

- If a resource cannot be decrypted, it will be skipped.
- The script is intended for local/test Passbolt instances and should not be used with real data.

## Supporting Tools

### Secret Encryption for Bruno
A utility script (`encrypt_secrets_for_bruno.py`) for encrypting Passbolt API payloads:
- **Purpose**: Passbolt requires all secret data in API requests to be encrypted with GPG
- **Functionality**:
  - Encrypts secret data using GPG for Passbolt API requests
  - Injects encrypted secrets into Bruno request files
  - Updates Bruno request metadata with encryption details
  - Handles both single secrets and complex JSON payloads

Note: The Bruno request file must already exist and contain a valid JSON body section. The script will not create new request files.

#### Bruno Request File Requirements
The Bruno request file must:
1. Exist before running the script
2. Contain a `body:json` section
3. Have a JSON body with a `secrets` array
4. Follow the Passbolt API payload format

Example Bruno request file structure:
```hcl
meta {
  name: Create Secret
  type: http
  seq: 1
}

post {
  url: {{host}}/resources.json
  body: json
  auth: inherit
}

headers {
  Authorization: Bearer {{jwt_token}}
  Content-Type: application/json
  Accept: application/json
}

body:json {
  {
    "name": "Secret Name",
    "username": "username",
    "uri": "https://example.com",
    "description": "Secret description",
    "secrets": [
      {
        "user_id": "{{user_id}}",
        "data": "-----BEGIN PGP MESSAGE-----\n...encrypted data...\n-----END PGP MESSAGE-----"
      }
    ]
  }
}
```

Note: The double braces in the `body:json` section are part of Bruno's configuration format and are required. The outer braces are for Bruno's configuration, while the inner braces contain the actual JSON payload.

#### Passbolt Payload Format
When sending encrypted data to Passbolt, the payload must follow this structure:

```json
{
  "name": "Secret Name",
  "username": "username",
  "uri": "https://example.com",
  "description": "Secret description",
  "secrets": [
    {
      "user_id": "recipient-user-id",
      "data": "-----BEGIN PGP MESSAGE-----\n...encrypted data...\n-----END PGP MESSAGE-----"
    }
  ]
}
```

The script handles this by:
1. Encrypting the secret value with GPG
2. Wrapping it in the required JSON structure
3. Injecting it into the Bruno request file

#### Use Cases
- Creating new secrets in Passbolt
- Updating existing secrets
- Sharing secrets with other users
- Any API request requiring encrypted payloads

```bash
# Basic password secret
python3 encrypt_secrets_for_bruno.py \
    --secret "my-secret" \
    --fingerprint "03F60E958F4CB29723ACDF761353B5B15D9B054F" \
    --bruno-file ".bruno_env/docker/requests/Create Secret.bru" \
    --name "Secret Name" \
    --username "username" \
    --uri "https://example.com" \
    --description "Secret description"
```

The script will update the Bruno request body to:
```json
{
  "name": "Secret Name",
  "username": "username",
  "uri": "https://example.com",
  "description": "Secret description",
  "secrets": [
    {
      "data": "-----BEGIN PGP MESSAGE-----\n...encrypted data...\n-----END PGP MESSAGE-----",
      "user_id": "{{user_id}}"
    }
  ]
}
```

```bash
# API key with service metadata
python3 encrypt_secrets_for_bruno.py \
    --secret "<STRIPE KEY>" \
    --fingerprint "03F60E958F4CB29723ACDF761353B5B15D9B054F" \
    --bruno-file ".bruno_env/docker/requests/Create Secret.bru" \
    --name "Stripe API Key" \
    --username "stripe-service" \
    --uri "https://api.stripe.com" \
    --description "Production Stripe API Key"
```

The script will update the Bruno request body to:
```json
{
  "name": "Stripe API Key",
  "username": "stripe-service",
  "uri": "https://api.stripe.com",
  "description": "Production Stripe API Key",
  "secrets": [
    {
      "data": "-----BEGIN PGP MESSAGE-----\n...encrypted data...\n-----END PGP MESSAGE-----",
      "user_id": "{{user_id}}"
    }
  ]
}
```

Note: The `--secret` parameter is the actual secret value (password, API key, etc.) that needs to be encrypted. The metadata (name, username, uri, description) are provided as separate parameters. The actual API endpoint is configured in the Bruno request file. The `{{user_id}}` placeholder will be replaced with the actual user ID when the request is made.

## Security Notes

- Always use HTTPS for Passbolt server URLs
- Keep GPG private keys secure
- Use strong passphrases
- Don't share tokens or passphrases
- Clean up temporary files after use
- Use `--insecure` flag only for local development with self-signed certificates
- Never use `--insecure` with production or cloud instances

## Documentation

### Script Documentation
Each script includes comprehensive help documentation that can be accessed using Python's built-in help system:

```bash
# View full script documentation
python3 -c "import jwt_auth_with_api_test; help(jwt_auth_with_api_test)"
python3 -c "import jwt_api_with_bruno_support; help(jwt_api_with_bruno_support)"
python3 -c "import jwt_auth_minimum_example; help(jwt_auth_minimum_example)"
python3 -c "import group_update; help(group_update)"
python3 -c "import encrypt_secrets_for_bruno; help(encrypt_secrets_for_bruno)"
python3 -c "import loop_refresh_jwt_token; help(loop_refresh_jwt_token)"
python3 -c "import passbolt-gpgauth-example; help(passbolt-gpgauth-example)"

# View specific function documentation
python3 -c "from jwt_auth_with_api_test import check_gpg_key_validity; help(check_gpg_key_validity)"
```

The help documentation includes:
- Detailed explanation of the authentication process
- Command-line options and usage examples
- Security notes and best practices
- Error handling and troubleshooting

#### Quick Reference
| Script | Purpose | Key Features |
|--------|---------|--------------|
| `jwt_auth_with_api_test.py` | Complete JWT auth | CLI args, error handling, API testing |
| `jwt_api_with_bruno_support.py` | Bruno integration | Environment vars, token injection |
| `jwt_auth_minimum_example.py` | Minimal JWT auth | Basic authentication flow |
| `group_update.py` | Group management | User addition, duplicate prevention, CLI args |
| `encrypt_secrets_for_bruno.py` | Secret encryption | GPG encryption, Bruno request handling |
| `loop_refresh_jwt_token.py` | Automatic JWT token refresh | Environment vars, YAML configuration |
| `passbolt-gpgauth-example.sh` | Legacy GPG auth | Traditional auth flow |

### External Documentation
- [Passbolt API Documentation](https://www.passbolt.com/docs/api/)
- [JWT Authentication Guide](https://www.passbolt.com/docs/development/authentication/#jwt-authentication)
- [GPG Authentication Guide](https://www.passbolt.com/docs/development/authentication/#gpgauth)
- [Bruno API Client](https://www.usebruno.com/)

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License (AGPL) as published by the Free Software Foundation version 3.

The name "Passbolt" is a registered trademark of Passbolt SA, and Passbolt SA hereby declines to grant a trademark license to "Passbolt" pursuant to the GNU Affero General Public License version 3 Section 7(e), without a separate agreement with Passbolt SA.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html).
