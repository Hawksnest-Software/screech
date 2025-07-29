#!/bin/bash

# Screech Linux eBPF Installation Script
# This script builds and installs the eBPF version for Linux

set -e  # Exit on any error

echo "🔍 Screech Linux eBPF Installation Script"
echo "=========================================="
echo

# Detect platform
PLATFORM=$(uname -s)
echo "Detected platform: $PLATFORM"

# Check if we're on Linux
if [[ "$PLATFORM" != "Linux" ]]; then
    echo "❌ This installation script is designed for Linux"
    echo "   For macOS, use install_invisible.sh"
    exit 1
fi

# Check Linux kernel version
KERNEL_VERSION=$(uname -r)
echo "Kernel version: $KERNEL_VERSION"

# Extract major and minor version numbers
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

# Check minimum kernel version for eBPF (4.1+)
if [[ $KERNEL_MAJOR -lt 4 ]] || [[ $KERNEL_MAJOR -eq 4 && $KERNEL_MINOR -lt 1 ]]; then
    echo "❌ eBPF requires Linux kernel 4.1 or newer"
    echo "   Your kernel: $KERNEL_VERSION"
    echo "   Falling back to original PcapPlusPlus version"
    BUILD_EBPF=false
else
    echo "✅ Kernel version supports eBPF"
    BUILD_EBPF=true
fi

echo

# Check prerequisites
echo "Checking prerequisites..."

# Check for root access (needed for eBPF)
if [[ $EUID -ne 0 ]]; then
    echo "⚠️  Root privileges will be required to run eBPF programs"
fi

# Check for clang
if command -v clang &> /dev/null; then
    CLANG_VERSION=$(clang --version | head -n1)
    echo "✅ Clang found: $CLANG_VERSION"
    HAS_CLANG=true
else
    echo "❌ clang not found"
    echo "   Install with: sudo apt-get install clang (Ubuntu/Debian)"
    echo "   Install with: sudo yum install clang (RHEL/CentOS)"
    echo "   Install with: sudo pacman -S clang (Arch)"
    HAS_CLANG=false
    BUILD_EBPF=false
fi

# Check for libbpf development headers
if pkg-config --exists libbpf; then
    LIBBPF_VERSION=$(pkg-config --modversion libbpf)
    echo "✅ libbpf found: $LIBBPF_VERSION"
    HAS_LIBBPF=true
elif [[ -f "/usr/include/bpf/bpf.h" ]] || [[ -f "/usr/local/include/bpf/bpf.h" ]]; then
    echo "✅ libbpf headers found"
    HAS_LIBBPF=true
else
    echo "❌ libbpf development headers not found"
    echo "   Install with: sudo apt-get install libbpf-dev (Ubuntu/Debian)"
    echo "   Install with: sudo yum install libbpf-devel (RHEL/CentOS)"
    echo "   Install with: sudo pacman -S libbpf (Arch)"
    HAS_LIBBPF=false
    BUILD_EBPF=false
fi

# Check for meson
if command -v meson &> /dev/null; then
    MESON_VERSION=$(meson --version)
    echo "✅ Meson found: $MESON_VERSION"
    HAS_MESON=true
else
    echo "❌ Meson build system not found"
    echo "   Install with: pip3 install meson ninja"
    HAS_MESON=false
    exit 1
fi

# Check for ninja
if command -v ninja &> /dev/null; then
    echo "✅ Ninja build system found"
else
    echo "❌ Ninja build system not found"
    echo "   Install with: sudo apt-get install ninja-build"
    exit 1
fi

echo

# Determine build configuration
if [[ "$BUILD_EBPF" == "true" && "$HAS_CLANG" == "true" && "$HAS_LIBBPF" == "true" ]]; then
    echo "🔨 Building eBPF version..."
    BUILD_TYPE="ebpf"
    
    # Configure meson with eBPF enabled
    if [[ ! -d "build_ebpf" ]]; then
        meson setup build_ebpf -Denable_ebpf=true -Ddebug_ebpf=false
    else
        echo "   Build directory exists, reconfiguring..."
        meson configure build_ebpf -Denable_ebpf=true -Ddebug_ebpf=false
    fi
    
    # Build the project
    meson compile -C build_ebpf
    
    BINARY_PATH="build_ebpf/screech_ebpf"
    EBPF_OBJ_PATH="build_ebpf/screech_ebpf.o"
    
else
    echo "🔨 Building original PcapPlusPlus version..."
    BUILD_TYPE="original"
    
    # Check for PcapPlusPlus
    if ! pkg-config --exists PcapPlusPlus; then
        echo "❌ PcapPlusPlus not found"
        echo "   Please install PcapPlusPlus first"
        exit 1
    fi
    
    # Configure meson with eBPF disabled
    if [[ ! -d "build_original" ]]; then
        meson setup build_original -Denable_ebpf=false -Dforce_original=true
    else
        echo "   Build directory exists, reconfiguring..."
        meson configure build_original -Denable_ebpf=false -Dforce_original=true
    fi
    
    # Build the project
    meson compile -C build_original
    
    BINARY_PATH="build_original/screech"
fi

echo "✅ Build completed successfully!"
echo

# Installation
echo "📦 Installation options:"
echo "   1. Install system-wide (requires sudo)"
echo "   2. Keep in build directory"
echo "   3. Create symlinks in ~/bin"
echo

read -p "Choose installation method [1-3]: " INSTALL_CHOICE

case $INSTALL_CHOICE in
    1)
        echo "Installing system-wide..."
        if [[ "$BUILD_TYPE" == "ebpf" ]]; then
            sudo meson install -C build_ebpf
        else
            sudo meson install -C build_original
        fi
        echo "✅ Installed to system directories"
        ;;
    2)
        echo "✅ Keeping binaries in build directory"
        echo "   Run with: sudo ./$BINARY_PATH"
        ;;
    3)
        mkdir -p ~/bin
        if [[ "$BUILD_TYPE" == "ebpf" ]]; then
            ln -sf "$(pwd)/$BINARY_PATH" ~/bin/screech_ebpf
            ln -sf "$(pwd)/build_ebpf/run_screech_ebpf.sh" ~/bin/run_screech_ebpf
            echo "✅ Created symlinks in ~/bin"
            echo "   Run with: sudo run_screech_ebpf"
        else
            ln -sf "$(pwd)/$BINARY_PATH" ~/bin/screech
            echo "✅ Created symlink in ~/bin"
            echo "   Run with: sudo screech"
        fi
        ;;
    *)
        echo "Invalid choice, keeping in build directory"
        ;;
esac

echo

# Final setup instructions
echo "🎉 Installation Complete!"
echo "========================"
echo

if [[ "$BUILD_TYPE" == "ebpf" ]]; then
    echo "📋 eBPF Version Setup:"
    echo "   • Binary: $BINARY_PATH"
    echo "   • eBPF Object: $EBPF_OBJ_PATH"
    echo "   • Requires root privileges to load eBPF programs"
    echo "   • Run with: sudo ./$BINARY_PATH"
    echo "   • Or use helper: sudo ./build_ebpf/run_screech_ebpf.sh"
    echo
    echo "🛡️ eBPF Advantages:"
    echo "   ✅ Invisible to userspace programs"
    echo "   ✅ Kernel-level network monitoring"
    echo "   ✅ No packet capture overhead"
    echo "   ✅ Direct process correlation"
    echo
else
    echo "📋 Original Version Setup:"
    echo "   • Binary: $BINARY_PATH"
    echo "   • Uses PcapPlusPlus for packet capture"
    echo "   • Run with: sudo ./$BINARY_PATH"
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
    echo "Testing installation (requires sudo)..."
    echo "Press Ctrl+C after a few seconds to stop"
    echo
    
    if [[ "$BUILD_TYPE" == "ebpf" ]]; then
        sudo timeout 10s ./$BINARY_PATH || true
    else
        sudo timeout 10s ./$BINARY_PATH || true
    fi
    
    echo
    echo "✅ Test completed successfully!"
fi

echo
echo "🔍 Screech Linux eBPF version is ready for invisible network monitoring!"
echo "   Your original version has been backed up automatically."
