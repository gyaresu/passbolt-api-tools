# Passbolt API Tools

Tools for Passbolt resource management with encrypted metadata support.

## Quick Start

```bash
# Setup
cp env.example .env
# Edit .env with your Passbolt configuration

# List all resources
python3 passbolt.py list

# Decrypt and display resources
python3 passbolt.py decrypt

# Monitor password expiry
python3 passbolt.py monitor
```

## Scripts

### 1. passbolt.py - Main Resource Management

Main script for Passbolt resource management with encrypted metadata support.

#### Features

- **Resource Creation**: Create resources with encrypted metadata using shared metadata keys
- **Shared Folder Support**: Share resources with folder users using browser extension approach
- **Resource Management**: List, view, and manage existing resources
- **Decryption**: Decrypt resource metadata and secrets (both user_key and shared_key encryption)
- **Sharing**: Share resources with other users and groups
- **Monitoring**: Track password expiry dates with JSON export
- **Educational Mode**: Explanations of authentication and decryption processes

#### Usage

```bash
# List all accessible resources
python3 passbolt.py list

# Show detailed information about a specific resource
python3 passbolt.py show --resource-id RESOURCE_ID

# Create a new resource in a folder (shared with folder users)
python3 passbolt.py create \
    --folder-name "My Folder" \
    --resource-name "My Resource" \
    --username "user@example.com" \
    --password "secret123" \
    --uri "https://example.com" \
    --description "Resource description"

# Share a resource with another user
python3 passbolt.py share \
    --resource-id RESOURCE_ID \
    --share-with "user@example.com" \
    --permission-type 7

# Decrypt and display all resources
python3 passbolt.py decrypt

# Monitor password expiry (JSON output)
python3 passbolt.py monitor --json

# List all folders
python3 passbolt.py folders

# List all users
python3 passbolt.py users

# Delete a resource
python3 passbolt.py delete --resource-id RESOURCE_ID
```

#### Shared Folder Resource Creation

The script implements the same approach as the Passbolt browser extension for creating resources in shared folders:

1. **Create Resource**: Creates the resource with only the current user's permission initially
2. **Get Folder Permissions**: Retrieves all users who have access to the folder
3. **Decrypt Secret**: Decrypts the resource's secret using the user's private key
4. **Encrypt for Users**: Encrypts the secret for each user who needs access
5. **Share Resource**: Calls the share endpoint with both permissions and encrypted secrets

This ensures resources created in shared folders are visible to all intended users.

#### Available Actions

| Action | Description | Requirements |
|--------|-------------|--------------|
| `create` | Create a new resource with encrypted metadata | `--resource-name`, `--username`, `--password` |
| `list` | List all accessible resources | None |
| `show` | Show detailed information about a specific resource | `--resource-id` |
| `share` | Share a resource with another user | `--resource-id`, `--share-with` |
| `decrypt` | Decrypt and display all resources | None |
| `monitor` | Monitor password expiry dates | None |
| `folders` | List all folders | None |
| `users` | List all users | None |
| `delete` | Delete a resource | `--resource-id` |

#### Technical Actions

- **Authentication**: GPG challenge/response with JWT token generation
- **Metadata Encryption**: Uses shared metadata keys with user key signing
- **Secret Management**: Handles individual user secrets (JSON objects with password + description)
- **API Integration**: Passbolt API v2 compatibility
- **Error Handling**: Validation and error messages

#### Permission Types

- `1` - Read only
- `7` - Read + Update (default)
- `15` - Read + Update + Delete (Owner)

### 2. jwt_auth_minimum_example.py - JWT Authentication

Example of Passbolt JWT authentication using GPG challenge/response.

#### Features

- **GPG Authentication**: Challenge/response flow
- **JWT Token Generation**: Obtains access and refresh tokens
- **Environment Configuration**: Uses `.env` file for configuration
- **Error Handling**: Validation and error messages

#### Usage

```bash
# Authenticate and get JWT tokens
python3 jwt_auth_minimum_example.py
```

### 3. group_update.py - Group Management

Script for creating groups and managing user permissions in Passbolt.

#### Features

- **Group Creation**: Create new groups or use existing ones
- **User Management**: Add/remove users from groups
- **Admin Permissions**: Toggle admin status for group members
- **Group Deletion**: Remove groups entirely

#### Usage

```bash
# Create a group and add a user
python3 group_update.py --group-name "My Group" --user-email "user@example.com"

# Toggle admin status for a user
python3 group_update.py --group-name "My Group" --user-email "user@example.com" --toggle-admin

# Remove a user from a group
python3 group_update.py --group-name "My Group" --user-email "user@example.com" --remove-user

# Delete a group
python3 group_update.py --group-name "My Group" --delete-group
```

## Configuration

All scripts use a `.env` file for configuration. Copy `env.example` to `.env` and update with your values:

```bash
# Required: Passbolt user ID
USER_ID=your-user-id-here

# Optional: Passbolt server URL (default: https://passbolt.local)
URL=https://passbolt.local

# Optional: Path to GPG private key file (default: ada_private.key)
KEY_FILE=your_private.key

# Optional: GPG key passphrase (default: ada@passbolt.com)
PASSPHRASE=your-passphrase
```

## Prerequisites

- **Passbolt instance** with encrypted metadata support
- **Python 3.7+** with virtual environment
- **GPG** installed and configured
- **Valid Passbolt user account** with GPG key

## Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd passbolt-api-tools
   ```

2. **Create virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**:
   ```bash
   cp env.example .env
   # Edit .env with your Passbolt configuration
   ```

5. **Test authentication**:
   ```bash
   python3 jwt_auth_minimum_example.py
   ```

## Requirements

The project uses these Python packages:

- `requests` - HTTP client for API calls
- `python-dotenv` - Environment variable management
- `PyYAML` - YAML configuration support
- `tabulate` - Pretty table formatting

Install with:
```bash
pip install -r requirements.txt
```

## License

This project is licensed under the GNU Affero General Public License v3 - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test your changes
5. Submit a pull request

## Support

For issues and questions:
1. Check the script help: `python3 <script>.py --help`
2. Review the configuration in `.env`
3. Test with the JWT authentication script first
4. Check Passbolt server logs for API errors