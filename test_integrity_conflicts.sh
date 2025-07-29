#!/bin/bash

# Script to find exact functionality conflicting with integrity monitoring
set -e

TARGET_HOST="arm@192.168.1.36"
BINARY_PATH="/tmp/screech_macos_signed"
TEST_DURATION=8  # seconds to run each test

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_failure() {
    echo -e "${RED}[✗]${NC} $1"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Test a specific configuration
test_config() {
    local config_name="$1"
    local config_args="$2"
    
    log_test "Testing: $config_name"
    echo "Args: $config_args"
    
    # Run the test with timeout using a background process approach
    local output_file=$(mktemp)
    local success=false
    
    # Create test command 
    local test_cmd="(echo '$SUDO_PASSWORD' | sudo -S $BINARY_PATH $config_args &); pid=\$!; sleep ${TEST_DURATION}; kill \$pid 2>/dev/null; wait \$pid 2>/dev/null"
    
    # Run the test via SSH
    if ssh -o ConnectTimeout=10 $TARGET_HOST "$test_cmd" > "$output_file" 2>&1; then
        success=true
    else
        local exit_code=$?
        # If killed by timeout or signal, that's actually success
        if [ $exit_code -eq 143 ] || [ $exit_code -eq 137 ] || [ $exit_code -eq 124 ]; then
            success=true
        fi
    fi
    
    # Check if the monitoring actually started
    if grep -q "Unified monitoring is now active" "$output_file"; then
        if $success; then
            log_success "$config_name - WORKS"
            rm -f "$output_file"
            return 0
        else
            log_failure "$config_name - Started but crashed during execution"
            echo "Last few lines:"
            tail -3 "$output_file"
            rm -f "$output_file"
            return 1
        fi
    else
        log_failure "$config_name - CRASHES (failed to start)"
        echo "Output:"
        head -10 "$output_file"
        rm -f "$output_file"
        return 1
    fi
}

# Get sudo password
echo "Please enter sudo password for $TARGET_HOST:"
read -s SUDO_PASSWORD
echo

# Deploy the binary first
echo "Deploying binary..."
./scripts/deployment/sign_and_deploy.sh <<< "n" > /dev/null 2>&1
echo

log_info "=== INTEGRITY MONITORING CONFLICT ANALYSIS ==="
echo

# First, confirm our baseline
log_info "Step 1: Confirm baseline behaviors"
test_config "Minimal (should work)" "--obfuscation=minimal"
test_config "Minimal + Integrity (should work)" "--obfuscation=minimal --enable-integrity-monitoring"
test_config "Full (should crash)" "--obfuscation=full"
test_config "Full - Integrity (should work)" "--obfuscation=full --disable-integrity"
echo

# Now test integrity monitoring with individual features from moderate/full
log_info "Step 2: Test integrity + individual moderate features"

moderate_features=(
    "function-pointers:--enable-function-pointers"
    "anti-disassembly:--enable-anti-disassembly"
    "syscall-randomization:--enable-syscall-randomization"
    "debugger-detection:--enable-debugger-detection"
    "vm-detection:--enable-vm-detection"
    "env-checks:--enable-env-checks"
    "variant-generation:--enable-variant-generation"
    "timing-obfuscation:--enable-timing-obfuscation"
)

working_features=()
failing_features=()

for feature_test in "${moderate_features[@]}"; do
    IFS=':' read -r feature_name args <<< "$feature_test"
    if test_config "Integrity + $feature_name" "--obfuscation=minimal --enable-integrity-monitoring $args"; then
        working_features+=("$args")
    else
        failing_features+=("$args")
        log_failure "CONFLICT FOUND: Integrity monitoring conflicts with $feature_name"
    fi
    echo
done

# Test integrity monitoring with aggressive features
log_info "Step 3: Test integrity + aggressive features"

aggressive_features=(
    "direct-syscalls:--enable-direct-syscalls"
    "ptrace-protection:--enable-ptrace-protection" 
    "anti-debug-ptrace:--enable-anti-debug-ptrace"
)

for feature_test in "${aggressive_features[@]}"; do
    IFS=':' read -r feature_name args <<< "$feature_test"
    if test_config "Integrity + $feature_name" "--obfuscation=minimal --enable-integrity-monitoring $args"; then
        working_features+=("$args")
    else
        failing_features+=("$args")
        log_failure "CONFLICT FOUND: Integrity monitoring conflicts with $feature_name"
    fi
    echo
done

# If we found failing features, test combinations
if [ ${#failing_features[@]} -gt 0 ]; then
    log_info "Step 4: Test combinations of conflicting features"
    
    # Test if it's just one specific feature or combinations
    if [ ${#failing_features[@]} -eq 1 ]; then
        log_info "Only one conflicting feature found: ${failing_features[0]}"
    else
        log_info "Multiple conflicting features found. Testing combinations..."
        
        # Test pairs of conflicting features
        for ((i=0; i<${#failing_features[@]}; i++)); do
            for ((j=i+1; j<${#failing_features[@]}; j++)); do
                combo_args="${failing_features[i]} ${failing_features[j]}"
                test_config "Combo test" "--obfuscation=minimal --enable-integrity-monitoring $combo_args"
                echo
            done
        done
    fi
else
    log_info "Step 4: No individual conflicts found. Testing feature combinations..."
    
    # Test progressively larger combinations of working features
    log_info "Testing combinations of working features with integrity monitoring..."
    
    # Test all working features together
    all_working_args=$(IFS=' '; echo "${working_features[*]}")
    test_config "All working features + Integrity" "--obfuscation=minimal --enable-integrity-monitoring $all_working_args"
    echo
    
    # If that works, the issue might be more subtle - test with moderate preset
    test_config "Moderate preset + Integrity" "--obfuscation=moderate --enable-integrity-monitoring"
fi

echo
log_info "=== SUMMARY ==="
echo

if [ ${#failing_features[@]} -gt 0 ]; then
    log_failure "CONFLICTING FEATURES IDENTIFIED:"
    for feature in "${failing_features[@]}"; do
        echo "  ✗ $feature"
    done
else
    log_info "No individual feature conflicts found. Issue may be:"
    echo "  • Combination of multiple features"
    echo "  • Race condition or timing issue"  
    echo "  • Resource exhaustion with all features enabled"
    echo "  • Order of initialization problem"
fi

echo
if [ ${#working_features[@]} -gt 0 ]; then
    log_success "SAFE TO USE WITH INTEGRITY MONITORING:"
    for feature in "${working_features[@]}"; do
        echo "  ✓ $feature"
    done
fi

log_info "Next steps: Focus investigation on the conflicting features identified above."
