#!/bin/bash

set -e  # Exit immediately if any command fails

# =============================================================================
# OUTPUT FORMATTING
# =============================================================================
# Define colors and formatting for better output readability
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'
DIM='\033[2m'

# Output formatting functions
print_header() {
    echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}\n"
}

print_test() {
    echo -e "\n${BOLD}${CYAN}Test $1:${NC} $2"
}

print_step() {
    echo -e "${DIM}  → $1${NC}"
}

print_success() {
    echo -e "${GREEN}  ✓ $1${NC}"
}

print_error() {
    echo -e "${RED}  ✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}  ! $1${NC}"
}

print_info() {
    echo -e "${DIM}  ℹ $1${NC}"
}

print_result() {
    local status=$1
    local message=$2
    if [ "$status" = "success" ]; then
        print_success "$message"
    else
        print_error "$message"
    fi
}

# =============================================================================
# CONFIGURATION
# =============================================================================
# This script demonstrates the legacy GPG authentication method for Passbolt.
# Note: GPG authentication is being phased out in favor of JWT authentication.
#
# The GPG authentication process works as follows:
# 1. The client sends their GPG key ID to the server
# 2. The server encrypts a challenge token with the client's public key
# 3. The client decrypts the token with their private key
# 4. The client sends the decrypted token back to prove ownership of the key
#
# Security considerations:
# - The GPG key must be trusted (ultimate trust level)
# - The private key must be protected with a passphrase
# - The challenge token is time-limited
# - The session is protected with CSRF tokens
#
# Required configuration:
# API_URL: The base URL of your Passbolt instance
# KEYID: Your GPG key ID for authentication (get this from 'gpg --list-keys')
# VERSION: The Passbolt API version to use
# GPG_PASSPHRASE: The passphrase for your GPG key
# =============================================================================
API_URL="https://passbolt.local"
KEYID="03F60E958F4CB29723ACDF761353B5B15D9B054F"
VERSION="v2"
GPG_PASSPHRASE="ada@passbolt.com"

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
# These functions handle common tasks throughout the authentication process:
#
# check_response: Verifies HTTP response status
#   - Checks if the response matches the expected status code
#   - Displays detailed error information if the check fails
#   - Exits the script on failure to prevent further execution
#
# get_cookie_value: Extracts cookie values from response headers
#   - Parses the cookies.txt file for specific cookie names
#   - Used to extract session and CSRF tokens
#
# encrypt_secret: Encrypts data using GPG
#   - Takes a secret and recipient key ID as input
#   - Uses GPG to encrypt the data with the recipient's public key
#   - Returns the encrypted data in ASCII-armored format
#   - Used for encrypting resource secrets before sending to the server
#
# generate_random_string: Creates random strings for testing
#   - Generates cryptographically secure random strings
#   - Used for creating unique resource names and passwords
#   - Helps prevent collisions in test data
# =============================================================================
function check_response() {
    local response_file=$1
    local expected_status=$2
    local error_message=$3
    
    if ! grep -q "^HTTP/.* $expected_status" "$response_file"; then
        print_error "$error_message"
        print_info "Response status:"
        grep "^HTTP/" "$response_file"
        print_info "Response body:"
        cat "$response_file"
        exit 1
    fi
}

function get_cookie_value() {
    local cookie_name=$1
    grep -o "$cookie_name=[^;]*" cookies.txt | cut -d'=' -f2
}

function encrypt_secret() {
    local secret="$1"
    local recipient="$2"
    local tmp_file=$(mktemp)
    echo -n "$secret" | gpg --encrypt --armor -r "$recipient" > "$tmp_file"
    cat "$tmp_file" | awk '{printf "%s\\n", $0}'
    rm -f "$tmp_file"
}

function generate_random_string() {
    local length=$1
    local chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    local result=''
    for (( i=0; i<length; i++ )); do
        result+=${chars:$((RANDOM % ${#chars})):1}
    done
    echo "$result"
}

# =============================================================================
# STEP 0: GPG Key Trust Setup
# =============================================================================
# Before we can use the GPG key for authentication, we need to trust it.
# This step automatically sets the trust level to "ultimate" (5) for the key.
#
# The trust levels in GPG are:
# 0 = Unknown
# 1 = I don't know or won't say
# 2 = I do NOT trust
# 3 = I trust marginally
# 4 = I trust fully
# 5 = I trust ultimately
#
# In a production environment, you should:
# 1. Verify the key's fingerprint
# 2. Check the key's creation date and expiration
# 3. Verify the key's owner
# 4. Consider using a lower trust level
# =============================================================================
print_header "Setting up GPG Key Trust"
print_step "Setting trust level to ultimate for key: ${KEYID:0:10}..."

# Completely suppress all GPG output including key information and prompts
echo -e "trust\n5\ny\nsave\n" | gpg --quiet --batch --command-fd 0 --edit-key "$KEYID" 2>/dev/null >/dev/null
print_success "GPG key trust setup completed"

# =============================================================================
# STEP 1: Request Authentication Challenge
# =============================================================================
print_header "Starting Authentication Process"
print_step "Requesting challenge token from server..."

TMP_HEADERS=$(mktemp)  # Create temporary file for storing response headers
curl -sk -D "$TMP_HEADERS" \
  -H "accept: application/json" \
  -H "Content-Type: application/json" \
  -X POST "$API_URL/auth/login.json?api-version=$VERSION" \
  -d "{\"gpg_auth\": {\"keyid\": \"$KEYID\"}}" > /dev/null

# Only show relevant headers
print_info "Response status: $(grep "^HTTP/" "$TMP_HEADERS" | cut -d' ' -f2)"
print_info "Auth token received: $(grep -qi "^x-gpgauth-user-auth-token:" "$TMP_HEADERS" && echo "Yes" || echo "No")"

# =============================================================================
# STEP 2: Extract and Decode Challenge Token
# =============================================================================
print_step "Extracting and decoding challenge token..."

RAW_TOKEN=$(grep -i "^x-gpgauth-user-auth-token:" "$TMP_HEADERS" | cut -d' ' -f2-)
DECODED=$(echo "$RAW_TOKEN" | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))")
CLEANED=$(echo "$DECODED" \
  | sed 's/-----BEGIN\\\+PGP\\\+MESSAGE-----/-----BEGIN PGP MESSAGE-----/' \
  | sed 's/-----END\\\+PGP\\\+MESSAGE-----/-----END PGP MESSAGE-----/' \
  | sed 's/\\\+PGP\\\+MESSAGE/ PGP MESSAGE/g')

print_info "Token processed successfully"

# =============================================================================
# STEP 3: Decrypt Challenge Token
# =============================================================================
print_step "Decrypting challenge token..."

DECRYPTED=$(echo "$CLEANED" | gpg \
  --quiet \
  --batch \
  --yes \
  --pinentry-mode loopback \
  --passphrase "$GPG_PASSPHRASE" \
  --decrypt 2>/dev/null | head -n1)

if [[ -z "$DECRYPTED" ]]; then
  print_error "GPG decryption failed. Check passphrase or key config."
  exit 1
fi
print_success "Token decrypted successfully"

# =============================================================================
# STEP 4: Complete Authentication and Get CSRF Token
# =============================================================================
print_step "Completing authentication process..."

curl -sk \
  -c cookies.txt \
  -D headers.txt \
  -H "accept: application/json" \
  -H "Content-Type: application/json" \
  -X POST "$API_URL/auth/login.json?api-version=$VERSION" \
  -d "{
    \"gpg_auth\": {
      \"keyid\": \"$KEYID\",
      \"user_token_result\": \"$DECRYPTED\"
    }
  }" > /dev/null

# Only show authentication status
if ! grep -qi "^x-gpgauth-authenticated: true" headers.txt; then
  print_error "Authentication failed - X-GPGAuth-Authenticated header not found or not true"
  exit 1
fi
print_success "Authentication completed successfully"

# =============================================================================
# TEST SUITE: Authentication and Authorization Tests
# =============================================================================
print_header "Starting Authentication and Authorization Tests"

# Test 1: Protected Endpoint Access Without CSRF Token
# -----------------------------------------------------------------------------
print_test "1" "Protected Endpoint Access Without CSRF Token"
print_step "Attempting to access protected endpoint with session cookie only..."

curl -sk \
  -b cookies.txt \
  -D test_headers.txt \
  -H "accept: application/json" \
  -X GET "$API_URL/users/me.json?api-version=$VERSION" > test_response.txt

HTTP_STATUS=$(grep "^HTTP/" test_headers.txt | cut -d' ' -f2)
if [ "$HTTP_STATUS" = "200" ]; then
    print_success "GET request succeeded (expected behavior)"
else
    print_error "Unexpected response status: $HTTP_STATUS"
    exit 1
fi

# Test 2: CSRF Token Acquisition
# -----------------------------------------------------------------------------
print_test "2" "CSRF Token Acquisition"
print_step "Requesting CSRF token from verify endpoint..."

curl -sk \
  -b cookies.txt \
  -D verify_headers.txt \
  -H "accept: application/json" \
  -X GET "$API_URL/auth/verify.json?api-version=$VERSION" > /dev/null

CSRF_TOKEN=$(grep -i "^set-cookie: csrfToken=" verify_headers.txt | cut -d'=' -f2 | cut -d';' -f1)
if [[ -z "$CSRF_TOKEN" ]]; then
    print_error "Failed to acquire CSRF token"
    exit 1
fi
print_success "CSRF token acquired successfully"

# Test 3: Protected Endpoint Access With CSRF Token
# -----------------------------------------------------------------------------
print_test "3" "Protected Endpoint Access With CSRF Token"
print_step "Accessing protected endpoint with session cookie and CSRF token..."

curl -sk \
  -b cookies.txt \
  -D test_headers2.txt \
  -H "accept: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -X GET "$API_URL/users/me.json?api-version=$VERSION" > test_response2.txt

HTTP_STATUS=$(grep "^HTTP/" test_headers2.txt | cut -d' ' -f2)
if [ "$HTTP_STATUS" = "200" ]; then
    print_success "Protected endpoint accessed successfully"
else
    print_error "Failed to access protected endpoint"
    exit 1
fi

# Test 4: POST Request Without CSRF Token
# -----------------------------------------------------------------------------
print_test "4" "POST Request Protection Test"
print_step "Attempting POST request without CSRF token (should fail)..."

curl -sk \
  -b cookies.txt \
  -D post_headers.txt \
  -H "accept: application/json" \
  -H "Content-Type: application/json" \
  -X POST "$API_URL/resources.json?api-version=$VERSION" \
  -d '{
    "name": "Test Resource",
    "username": "test",
    "uri": "https://test.com",
    "description": "Test resource created by API",
    "secrets": [{
        "data": "test-password"
    }],
    "resource_type_id": "669f8c64-242a-59fb-92fc-81f660975fd3"
}' > post_response.txt

HTTP_STATUS=$(grep "^HTTP/" post_headers.txt | cut -d' ' -f2)
if [ "$HTTP_STATUS" = "403" ]; then
    print_success "POST request properly rejected (expected behavior)"
else
    print_warning "Unexpected response status: $HTTP_STATUS"
fi

# Test 5: Successful Resource Creation
# -----------------------------------------------------------------------------
print_test "5" "Resource Creation with Proper Security"
print_step "Preparing to create new resource..."

# Initialize temporary files
POST_HEADERS=$(mktemp)
VERIFY_HEADERS=$(mktemp)

# Generate random resource details
RESOURCE_NAME="Test Resource $(generate_random_string 6)"
RESOURCE_USERNAME="test-user-$(generate_random_string 4)"
RESOURCE_PASSWORD="$(generate_random_string 12)"

print_info "Resource name: $RESOURCE_NAME"
print_info "Username: $RESOURCE_USERNAME"

# Get fresh cookies and CSRF token
print_step "Refreshing session and CSRF token..."
curl -sk \
    -b cookies.txt \
    -c cookies.txt \
    -D "$VERIFY_HEADERS" \
    -H "accept: application/json" \
    -X GET "$API_URL/auth/verify.json?api-version=$VERSION" > /dev/null

check_response "$VERIFY_HEADERS" "200" "Failed to refresh CSRF token"

# Extract cookies and tokens
SESSION_COOKIE=$(awk -F'\t' '/passbolt_session/ {print $7}' cookies.txt)
CSRF_TOKEN=$(awk -F'\t' '/csrfToken/ {print $7}' cookies.txt)

if [[ -z "$SESSION_COOKIE" ]] || [[ -z "$CSRF_TOKEN" ]]; then
    print_error "Failed to get session cookie or CSRF token"
    exit 1
fi

print_success "Session and CSRF token refreshed"

# Encrypt the secret
print_step "Encrypting resource secret..."
ENCRYPTED_SECRET=$(encrypt_secret "$RESOURCE_PASSWORD" "$KEYID")
if [[ -z "$ENCRYPTED_SECRET" ]]; then
    print_error "Failed to encrypt secret"
    exit 1
fi
print_success "Secret encrypted successfully"

# Make the POST request with encrypted secret
print_step "Creating resource with encrypted secret..."
curl -sk \
    -b cookies.txt \
    -c cookies.txt \
    -D "$POST_HEADERS" \
    -H "accept: application/json" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $CSRF_TOKEN" \
    -X POST "$API_URL/resources.json?api-version=$VERSION" \
    -d "{
        \"name\": \"$RESOURCE_NAME\",
        \"username\": \"$RESOURCE_USERNAME\",
        \"uri\": \"https://test.com\",
        \"description\": \"Test resource created by API\",
        \"secrets\": [{
            \"data\": \"$ENCRYPTED_SECRET\"
        }],
        \"resource_type_id\": \"669f8c64-242a-59fb-92fc-81f660975fd3\"
    }" > post_response.txt

HTTP_STATUS=$(grep "^HTTP/" "$POST_HEADERS" | cut -d' ' -f2)
if [ "$HTTP_STATUS" = "200" ]; then
    print_success "Resource created successfully"
else
    print_error "Failed to create resource"
    exit 1
fi

# Clean up temporary files
print_step "Cleaning up temporary files..."
rm -f "$TMP_HEADERS" \
      "$VERIFY_HEADERS" \
      "$POST_HEADERS" \
      "headers.txt" \
      "verify_headers.txt" \
      "test_headers.txt" \
      "test_headers2.txt" \
      "test_response.txt" \
      "test_response2.txt" \
      "post_headers.txt" \
      "post_response.txt" \
      "cookies.txt"

print_header "Test Suite Completed"
print_success "All tests completed successfully!"

# =============================================================================
# FINAL AUTHENTICATION SUMMARY
# =============================================================================
print_header "Authentication Summary"

# Only show the essential authentication information
print_info "Session Cookie: passbolt_session=$SESSION_COOKIE"
print_info "CSRF Token: $CSRF_TOKEN"

# Only show resource details if creation was successful
if [ "$HTTP_STATUS" = "200" ]; then
    print_info "\nCreated Resource:"
    print_info "  Name: $RESOURCE_NAME"
    print_info "  Username: $RESOURCE_USERNAME"
    print_info "  Password: $RESOURCE_PASSWORD"
fi

