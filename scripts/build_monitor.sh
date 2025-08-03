#!/bin/bash
#
# build_monitor.sh - Build the monitor application with remote logging support
#

set -e

echo "=== Building Monitor Application ==="

# Create build directory
BUILD_DIR="build"
mkdir -p "$BUILD_DIR"

# Compile the remote logging library
echo "Compiling remote logging library..."
g++ -c -fPIC \
    -I libs/remote_logging \
    libs/remote_logging/RemoteLogger.cpp \
    -o "$BUILD_DIR/RemoteLogger.o"

# Compile the event logger library
echo "Compiling event logger library..."
g++ -c -fPIC \
    -I libs/event_logger \
    -I libs/remote_logging \
    libs/event_logger/EventLogger.cpp \
    -o "$BUILD_DIR/EventLogger.o"

# Compile the main application
echo "Compiling main application..."
g++ -std=c++17 \
    -I libs/event_logger \
    -I libs/remote_logging \
    -I include/core \
    src/core/screech_main.cpp \
    "$BUILD_DIR/RemoteLogger.o" \
    "$BUILD_DIR/EventLogger.o" \
    -o "$BUILD_DIR/monitor" \
    -pthread

echo "✓ Build complete!"
echo "Executable: $BUILD_DIR/monitor"
echo

# Test the build
echo "Testing build..."
if "$BUILD_DIR/monitor" --help >/dev/null 2>&1; then
    echo "✓ Build test successful"
else
    echo "✗ Build test failed"
    exit 1
fi

echo
echo "Usage examples:"
echo "  $BUILD_DIR/monitor --help"
echo "  $BUILD_DIR/monitor --remote-log-server 192.168.1.28"
echo "  $BUILD_DIR/monitor --remote-log-server 192.168.1.28 --verbose"
