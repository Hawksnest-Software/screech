#!/bin/bash

# Screech macOS Deployment Script
# Deploy and run Screech on macOS target

MAC_IP="192.168.1.36"
MAC_USER="arm"
BINARY_NAME="screech_macos"
REMOTE_PATH="/tmp/screech_macos"

echo "=== Screech macOS Deployment ==="
echo "Target: ${MAC_USER}@${MAC_IP}"
echo "Binary: ${BINARY_NAME}"
echo

# Check if binary exists
if [ ! -f "build-macos-obfuscated/${BINARY_NAME}" ]; then
    echo "ERROR: Binary not found at build-macos-obfuscated/${BINARY_NAME}"
    echo "Please run: meson compile -C build-macos-obfuscated ${BINARY_NAME}"
    exit 1
fi

echo "✓ Binary found: build-macos-obfuscated/${BINARY_NAME}"

# Check binary architecture
echo "Binary info:"
file "build-macos-obfuscated/${BINARY_NAME}"
echo

# Copy binary to macOS target
echo "Deploying binary to ${MAC_USER}@${MAC_IP}:${REMOTE_PATH}..."
scp "build-macos-obfuscated/${BINARY_NAME}" "${MAC_USER}@${MAC_IP}:${REMOTE_PATH}"

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to copy binary to target"
    exit 1
fi

echo "✓ Binary deployed successfully"

# Make binary executable
echo "Setting executable permissions..."
ssh "${MAC_USER}@${MAC_IP}" "chmod +x ${REMOTE_PATH}"

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to set executable permissions"
    exit 1
fi

echo "✓ Permissions set"

# Check if target needs to run as root
echo "Checking if target can run as root..."
ssh "${MAC_USER}@${MAC_IP}" "sudo -n true" 2>/dev/null

if [ $? -ne 0 ]; then
    echo "WARNING: Target may need sudo privileges"
    echo "You may be prompted for password when running the binary"
fi

echo
echo "=== Deployment Complete ==="
echo
echo "To run Screech on the target machine:"
echo "  ssh ${MAC_USER}@${MAC_IP}"
echo "  sudo ${REMOTE_PATH}"
echo
echo "Or run directly:"
echo "  ssh -t ${MAC_USER}@${MAC_IP} 'sudo ${REMOTE_PATH}'"
echo

# Offer to run immediately
read -p "Run Screech now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Running Screech on target..."
    echo "Press Ctrl+C to stop monitoring"
    echo
    ssh -t "${MAC_USER}@${MAC_IP}" "sudo ${REMOTE_PATH}"
fi

echo "Deployment script completed."
