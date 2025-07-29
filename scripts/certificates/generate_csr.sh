#!/bin/bash

# Generate Certificate Signing Request for Apple Developer Certificate
# This script creates a private key and CSR for requesting a developer certificate

set -e

# Configuration
KEY_SIZE=2048
COUNTRY="US"
STATE="Your State"
CITY="Your City"
ORG="HawksNest Software"  # Your organization name
ORG_UNIT="Development"
EMAIL="your-email@example.com"  # Replace with your actual email
COMMON_NAME="HawksNest Software Developer"  # Replace with your name/org

# Output files
PRIVATE_KEY="hawksnest_developer.key"
CSR_FILE="hawksnest_developer.csr"
CONFIG_FILE="csr_config.conf"

echo "Generating Apple Developer Certificate Signing Request"
echo "===================================================="
echo ""

# Create OpenSSL config file for CSR
cat > "$CONFIG_FILE" << EOF
[req]
default_bits = $KEY_SIZE
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORG
OU = $ORG_UNIT
CN = $COMMON_NAME
emailAddress = $EMAIL

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
email.1 = $EMAIL
EOF

echo "1. Generating private key..."
openssl genrsa -out "$PRIVATE_KEY" $KEY_SIZE

echo "2. Setting secure permissions on private key..."
chmod 600 "$PRIVATE_KEY"

echo "3. Generating Certificate Signing Request..."
openssl req -new -key "$PRIVATE_KEY" -out "$CSR_FILE" -config "$CONFIG_FILE"

echo "4. Verifying CSR..."
openssl req -text -noout -verify -in "$CSR_FILE"

echo ""
echo "Certificate Signing Request generated successfully!"
echo "=================================================="
echo ""
echo "Files created:"
echo "  Private Key: $PRIVATE_KEY (keep this secure!)"
echo "  CSR File:    $CSR_FILE (upload this to Apple)"
echo "  Config File: $CONFIG_FILE (can be deleted)"
echo ""
echo "Next steps:"
echo "1. Keep '$PRIVATE_KEY' secure - you'll need it later"
echo "2. Upload '$CSR_FILE' to Apple Developer Portal"
echo "3. Download the certificate from Apple"
echo "4. Convert to DER format for use with the obfuscation system"
echo ""
echo "Security reminder: Never share your private key!"

# Clean up config file
rm -f "$CONFIG_FILE"
