#!/bin/bash

# Test script to systematically determine which obfuscation features cause crashes
set -e

TARGET_HOST="arm@192.168.1.36"
BINARY_PATH="/tmp/screech_macos_signed"
TEST_DURATION=10  # seconds to run each test
SUDO_PASSWORD=""  # Will be populated interactively

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_failure() {
    echo -e "${RED}[FAILURE]${NC} $1"
}

# Deploy binary to target
deploy_binary() {
    echo "Deploying binary to target..."
    ./scripts/deployment/sign_and_deploy.sh <<< "n" > /dev/null 2>&1
}

# Test a specific configuration
test_config() {
    local config_name="$1"
    local config_args="$2"
    
    log_test "Testing configuration: $config_name"
    echo "Arguments: $config_args"
    
    # Run the binary with timeout and capture output
    local output_file=$(mktemp)
    local success=false
    
    # Create the test command that passes sudo password via stdin
    local test_cmd=""
    
    # Check if gtimeout exists (from coreutils), otherwise use a different approach
    if ssh -o ConnectTimeout=5 $TARGET_HOST "command -v gtimeout" > /dev/null 2>&1; then
        test_cmd="echo '$SUDO_PASSWORD' | gtimeout ${TEST_DURATION} sudo -S $BINARY_PATH $config_args"
    else
        # Use a background process with kill after timeout
        test_cmd="(echo '$SUDO_PASSWORD' | sudo -S $BINARY_PATH $config_args &); pid=\$!; sleep ${TEST_DURATION}; kill \$pid 2>/dev/null; wait \$pid 2>/dev/null"
    fi
    
    # Run the test via SSH
    if ssh -o ConnectTimeout=10 $TARGET_HOST "$test_cmd" > "$output_file" 2>&1; then
        success=true
    else
        # Check if it was killed (that's success for our test)
        local exit_code=$?
        if [ $exit_code -eq 124 ] || [ $exit_code -eq 143 ] || [ $exit_code -eq 137 ]; then
            success=true
        fi
    fi
    
    # Check if the monitoring actually started
    if grep -q "Unified monitoring is now active" "$output_file"; then
        if $success; then
            log_success "$config_name - Program started and ran successfully"
            return 0
        else
            log_failure "$config_name - Program started but crashed during execution"
            echo "Last few lines of output:"
            tail -5 "$output_file"
            return 1
        fi
    else
        log_failure "$config_name - Program failed to start properly"
        echo "Output:"
        cat "$output_file"
        return 1
    fi
    
    rm -f "$output_file"
}

# Get sudo password interactively
get_sudo_password() {
    echo "This script will test various obfuscation configurations."
    echo "Please enter the sudo password for $TARGET_HOST:"
    read -s SUDO_PASSWORD
    echo "Testing sudo access..."
    
    # Test sudo access
    if ssh -o ConnectTimeout=10 $TARGET_HOST "echo '$SUDO_PASSWORD' | sudo -S echo 'Sudo test successful'" > /dev/null 2>&1; then
        echo "✓ Sudo access confirmed"
    else
        echo "✗ Sudo access failed. Please check your password."
        exit 1
    fi
    echo
}

# Main testing sequence
main() {
    echo "=== Systematic Obfuscation Testing ==="
    echo "Testing each configuration for $TEST_DURATION seconds..."
    echo
    
    # Get sudo password
    get_sudo_password
    
    # First, ensure we have a deployed binary
    deploy_binary
    
    # Test results tracking
    local passed_tests=()
    local failed_tests=()
    
    # Test 1: Minimal (baseline - should work)
    if test_config "Minimal Configuration" "--obfuscation=minimal"; then
        passed_tests+=("minimal")
    else
        failed_tests+=("minimal")
    fi
    echo
    
    # Test 2: Moderate 
    if test_config "Moderate Configuration" "--obfuscation=moderate"; then
        passed_tests+=("moderate")
    else
        failed_tests+=("moderate")
    fi
    echo
    
    # Test 3: Full
    if test_config "Full Configuration" "--obfuscation=full"; then
        passed_tests+=("full")
    else
        failed_tests+=("full")
    fi
    echo
    
    # If moderate or full failed, test individual features starting from minimal
    if [[ " ${failed_tests[@]} " =~ " moderate " ]] || [[ " ${failed_tests[@]} " =~ " full " ]]; then
        echo "=== Testing Individual Features (starting from minimal) ==="
        
        # Test enabling each feature individually on top of minimal
        local individual_tests=(
            "function-pointers:--obfuscation=minimal --enable-function-pointers"
            "anti-disassembly:--obfuscation=minimal --enable-anti-disassembly" 
            "syscall-randomization:--obfuscation=minimal --enable-syscall-randomization"
            "debugger-detection:--obfuscation=minimal --enable-debugger-detection"
            "vm-detection:--obfuscation=minimal --enable-vm-detection"
            "env-checks:--obfuscation=minimal --enable-env-checks"
            "integrity-monitoring:--obfuscation=minimal --enable-integrity-monitoring"
            "variant-generation:--obfuscation=minimal --enable-variant-generation"
            "timing-obfuscation:--obfuscation=minimal --enable-timing-obfuscation"
        )
        
        for test_case in "${individual_tests[@]}"; do
            IFS=':' read -r feature_name args <<< "$test_case"
            if test_config "Minimal + $feature_name" "$args"; then
                passed_tests+=("minimal+$feature_name")
            else
                failed_tests+=("minimal+$feature_name")
            fi
            echo
        done
        
        # Test the most aggressive features separately
        echo "=== Testing Aggressive Features ==="
        
        local aggressive_tests=(
            "direct-syscalls:--obfuscation=minimal --enable-direct-syscalls"
            "ptrace-protection:--obfuscation=minimal --enable-ptrace-protection"
            "anti-debug-ptrace:--obfuscation=minimal --enable-anti-debug-ptrace"
        )
        
        for test_case in "${aggressive_tests[@]}"; do
            IFS=':' read -r feature_name args <<< "$test_case"
            if test_config "Minimal + $feature_name" "$args"; then
                passed_tests+=("minimal+$feature_name")
            else
                failed_tests+=("minimal+$feature_name")
            fi
            echo
        done
    fi
    
    # Summary
    echo "=== TEST SUMMARY ==="
    echo
    if [ ${#passed_tests[@]} -gt 0 ]; then
        log_success "Passed tests:"
        for test in "${passed_tests[@]}"; do
            echo "  ✓ $test"
        done
        echo
    fi
    
    if [ ${#failed_tests[@]} -gt 0 ]; then
        log_failure "Failed tests:"
        for test in "${failed_tests[@]}"; do
            echo "  ✗ $test"
        done
        echo
        echo "CONCLUSION: The failed features are likely incompatible with endpoint security."
    else
        log_success "All tests passed!"
    fi
}

# Check if we can reach the target
if ! ssh -o ConnectTimeout=5 $TARGET_HOST "echo 'Connection test'" > /dev/null 2>&1; then
    echo "Error: Cannot connect to target host $TARGET_HOST"
    exit 1
fi

# Run main test sequence
main
