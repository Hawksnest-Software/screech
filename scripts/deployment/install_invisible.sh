#!/bin/bash

# Screech Invisible Migration Installation Script
# This script sets up the kernel-level monitoring version

set -e  # Exit on any error

echo "🔍 Screech Invisible Migration Installer"
echo "========================================"
echo

# Detect platform
PLATFORM=$(uname -s)
echo "Detected platform: $PLATFORM"

# Check if we're on macOS
if [[ "$PLATFORM" != "Darwin" ]]; then
    echo "❌ This installation script is designed for macOS"
    echo "   For Linux, use the original PcapPlusPlus version"
    exit 1
fi

# Check macOS version
MACOS_VERSION=$(sw_vers -productVersion)
echo "macOS version: $MACOS_VERSION"

# Function to compare version numbers
version_compare() {
    if [[ $1 == $2 ]]; then
        return 0
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    # fill empty fields in ver1 with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            # fill empty fields in ver2 with zeros
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            return 2
        fi
    done
    return 0
}

# Determine installation method
ENDPOINT_SECURITY_AVAILABLE=false
if version_compare "$MACOS_VERSION" "10.15.0"; then
    if [[ $? -eq 1 ]] || [[ $? -eq 0 ]]; then
        ENDPOINT_SECURITY_AVAILABLE=true
        echo "✅ Endpoint Security Framework available"
    fi
fi

if [[ "$ENDPOINT_SECURITY_AVAILABLE" == "false" ]]; then
    echo "⚠️  Endpoint Security not available, will use DTrace fallback"
fi

echo

# Check prerequisites
echo "Checking prerequisites..."

# Check for Xcode command line tools (if building)
if ! command -v clang &> /dev/null; then
    echo "❌ Xcode command line tools not found"
    echo "   Install with: xcode-select --install"
    exit 1
fi
echo "✅ Xcode command line tools found"

# Check for meson (if available)
if command -v meson &> /dev/null; then
    echo "✅ Meson build system found"
    BUILD_WITH_MESON=true
else
    echo "⚠️  Meson not found, will compile manually"
    BUILD_WITH_MESON=false
fi

# Check for DTrace
if command -v dtrace &> /dev/null; then
    echo "✅ DTrace found"
    DTRACE_AVAILABLE=true
else
    echo "❌ DTrace not found (unusual for macOS)"
    DTRACE_AVAILABLE=false
fi

echo

# Build the appropriate version
if [[ "$ENDPOINT_SECURITY_AVAILABLE" == "true" ]]; then
    echo "🔨 Building Endpoint Security version..."
    
    if [[ "$BUILD_WITH_MESON" == "true" ]]; then
        # Use meson build
        cp meson_macos.build meson.build
        if [[ ! -d "build_macos" ]]; then
            meson setup build_macos
        fi
        meson compile -C build_macos
        
        # Sign the binary
        echo "🔐 Signing binary..."
        codesign --force --sign - --entitlements screech.entitlements build_macos/screech_macos
        
        BINARY_PATH="build_macos/screech_macos"
    else
        # Manual compilation
        echo "📦 Compiling manually..."
        clang++ -std=c++17 -O2 \
            -framework EndpointSecurity \
            -framework Network \
            -framework Foundation \
            screech_macos_kernel.cpp \
            -o screech_macos
        
        # Sign the binary
        echo "🔐 Signing binary..."
        codesign --force --sign - --entitlements screech.entitlements screech_macos
        
        BINARY_PATH="screech_macos"
    fi
    
    echo "✅ Endpoint Security version built: $BINARY_PATH"
    
    # Verify code signing
    if codesign -v "$BINARY_PATH" 2>/dev/null; then
        echo "✅ Code signing verified"
    else
        echo "⚠️  Code signing verification failed (may still work)"
    fi
    
    MAIN_BINARY="$BINARY_PATH"
fi

# Setup DTrace version
if [[ "$DTRACE_AVAILABLE" == "true" ]]; then
    echo "🔧 Setting up DTrace version..."
    chmod +x screech_dtrace.d
    echo "✅ DTrace version ready: ./screech_dtrace.d"
    
    if [[ -z "$MAIN_BINARY" ]]; then
        MAIN_BINARY="screech_dtrace.d"
    fi
fi

echo

# Installation complete
echo "🎉 Installation Complete!"
echo "========================"
echo

if [[ "$ENDPOINT_SECURITY_AVAILABLE" == "true" ]]; then
    echo "📋 Endpoint Security Version Setup:"
    echo "   1. Grant Full Disk Access in System Preferences → Security & Privacy"
    echo "   2. Run with: sudo ./$MAIN_BINARY"
    echo "   3. First run may require additional security permissions"
    echo
fi

if [[ "$DTRACE_AVAILABLE" == "true" ]]; then
    echo "📋 DTrace Version Usage:"
    echo "   • Simple alternative: sudo ./screech_dtrace.d"
    echo "   • Works on all macOS versions"
    echo "   • No special entitlements required"
    echo
fi

echo "📚 Documentation:"
echo "   • See README_EBPF_MIGRATION.md for detailed information"
echo "   • Both versions maintain same output format"
echo "   • Logs saved to screech_<process_name>.log files"
echo

# Test run option
echo "🧪 Would you like to test the installation? [y/N]"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    echo
    echo "Testing DTrace version (requires sudo)..."
    echo "Press Ctrl+C after a few seconds to stop"
    echo
    sudo ./screech_dtrace.d &
    DTRACE_PID=$!
    sleep 5
    kill $DTRACE_PID 2>/dev/null || true
    echo
    echo "✅ Test completed successfully!"
fi

echo
echo "🔍 Screech is now ready for invisible network monitoring!"
echo "   Your original version has been backed up automatically."
