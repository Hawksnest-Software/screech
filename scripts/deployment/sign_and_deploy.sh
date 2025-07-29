#!/bin/bash

# Screech macOS Code Signing and Deployment Script
# Signs the binary with proper entitlements and deploys to macOS target

MAC_IP="192.168.1.36"
MAC_USER="arm"
BINARY_NAME="screech"
ENTITLEMENTS="screech_network_extension/MainApp/ScreechMainApp.entitlements"
REMOTE_PATH="/tmp/screech_macos_signed"

echo "=== Screech macOS Code Signing & Deployment ==="
echo "Target: ${MAC_USER}@${MAC_IP}"
echo "Binary: ${BINARY_NAME}"
echo "Entitlements: ${ENTITLEMENTS}"
echo

# Check if binary exists
if [ ! -f "builddir-macos-debug/${BINARY_NAME}" ]; then
    echo "ERROR: Binary not found at builddir-macos-debug/${BINARY_NAME}"
    echo "Please run: meson compile -C builddir-macos-debug ${BINARY_NAME}"
    exit 1
fi

# Check if entitlements exist
if [ ! -f "${ENTITLEMENTS}" ]; then
    echo "ERROR: Entitlements file not found: ${ENTITLEMENTS}"
    exit 1
fi

echo "✓ Binary found: builddir-macos-debug/${BINARY_NAME}"
echo "✓ Entitlements found: ${ENTITLEMENTS}"

# Copy files to macOS target for signing (since we need to sign on macOS)
echo
echo "Copying files to macOS target for signing..."

# Copy binary
scp "builddir-macos-debug/${BINARY_NAME}" "${MAC_USER}@${MAC_IP}:/tmp/${BINARY_NAME}_unsigned"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to copy binary to target"
    exit 1
fi

# Create remote directory structure and copy entitlements
ssh "${MAC_USER}@${MAC_IP}" "mkdir -p /tmp/screech_network_extension/MainApp"
scp "${ENTITLEMENTS}" "${MAC_USER}@${MAC_IP}:/tmp/${ENTITLEMENTS}"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to copy entitlements to target"
    exit 1
fi

echo "✓ Files copied to target"

# Create signing script for remote execution
cat > /tmp/remote_sign.sh << 'EOF'
#!/bin/bash

UNSIGNED_BINARY="/tmp/screech_unsigned"
ENTITLEMENTS="/tmp/screech_network_extension/MainApp/ScreechMainApp.entitlements"
SIGNED_BINARY="/tmp/screech_macos_signed"

echo "=== Remote Code Signing ==="
echo "Unsigned binary: ${UNSIGNED_BINARY}"
echo "Entitlements: ${ENTITLEMENTS}"
echo "Signed binary: ${SIGNED_BINARY}"
echo

# Check if we have a signing identity
echo "Available signing identities:"
security find-identity -v -p codesigning
echo

# Try to find a Developer ID or ad-hoc sign
SIGNING_IDENTITY=$(security find-identity -v -p codesigning | grep "Developer ID" | head -1 | sed -n 's/.*"\(.*\)".*/\1/p')

if [ -z "$SIGNING_IDENTITY" ]; then
    echo "No Developer ID found, using ad-hoc signing..."
    SIGNING_IDENTITY="-"
else
    echo "Using signing identity: $SIGNING_IDENTITY"
fi

# Sign the binary
echo "Signing binary with entitlements..."
codesign --force --options runtime --entitlements "${ENTITLEMENTS}" --sign "${SIGNING_IDENTITY}" "${UNSIGNED_BINARY}"

if [ $? -eq 0 ]; then
    echo "✓ Code signing successful"
    cp "${UNSIGNED_BINARY}" "${SIGNED_BINARY}"
    chmod +x "${SIGNED_BINARY}"
    
    # Verify the signature
    echo "Verifying signature..."
    codesign --verify --verbose "${SIGNED_BINARY}"
    
    echo "Checking entitlements..."
    codesign --display --entitlements - "${SIGNED_BINARY}"
    
    echo "✓ Binary signed and ready: ${SIGNED_BINARY}"
else
    echo "ERROR: Code signing failed"
    exit 1
fi
EOF

# Copy and execute the signing script on macOS
scp /tmp/remote_sign.sh "${MAC_USER}@${MAC_IP}:/tmp/remote_sign.sh"
ssh "${MAC_USER}@${MAC_IP}" "chmod +x /tmp/remote_sign.sh && /tmp/remote_sign.sh"

if [ $? -ne 0 ]; then
    echo "ERROR: Remote signing failed"
    exit 1
fi

echo
echo "=== Code Signing Complete ==="
echo

# Check if binary was signed successfully
ssh "${MAC_USER}@${MAC_IP}" "ls -la ${REMOTE_PATH}"
if [ $? -ne 0 ]; then
    echo "ERROR: Signed binary not found at ${REMOTE_PATH}"
    exit 1
fi

echo "✓ Signed binary available at: ${REMOTE_PATH}"

# Clean up temporary files
ssh "${MAC_USER}@${MAC_IP}" "rm -rf /tmp/screech_unsigned /tmp/screech_network_extension /tmp/remote_sign.sh"

echo
echo "=== Deployment Complete ==="
echo
echo "To run the signed Screech binary:"
echo "  ssh ${MAC_USER}@${MAC_IP}"
echo "  sudo ${REMOTE_PATH}"
echo
echo "Or run directly:"
echo "  ssh -t ${MAC_USER}@${MAC_IP} 'sudo ${REMOTE_PATH}'"
echo

# Offer to run immediately
read -p "Run signed Screech now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Running signed Screech on target..."
    echo "Press Ctrl+C to stop monitoring"
    echo
    ssh -t "${MAC_USER}@${MAC_IP}" "sudo ${REMOTE_PATH}"
fi

echo "Code signing and deployment completed."
