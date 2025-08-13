#!/bin/bash
# Kernel BPF Feature Profiler
# Usage: ./profile_kernel.sh [user@host] [output_file]
# If no host specified, profiles local kernel

set -e

REMOTE_HOST="$1"
OUTPUT_FILE="${2:-kernel_profile.json}"
# Get the project root directory (parent of scripts directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$PROJECT_DIR/config"

# Create config directory if it doesn't exist
mkdir -p "$CONFIG_DIR"

# Function to run all commands in a single SSH session
run_remote_profiling() {
    if [ -n "$REMOTE_HOST" ]; then
        # Create a single SSH session with all commands
        ssh "$REMOTE_HOST" 'bash -s' << 'EOF'
# Kernel information
echo "KERNEL_VERSION=$(uname -r)"
echo "ARCHITECTURE=$(uname -m)"

# Check BPF-related features
echo "BTF_VMLINUX=$(test -e /sys/kernel/btf/vmlinux && echo 'true' || echo 'false')"
echo "BPF_SYSCALL=$(grep -q CONFIG_BPF_SYSCALL=y /boot/config-* 2>/dev/null && echo 'true' || echo 'unknown')"
echo "BPF_JIT=$(grep -q CONFIG_BPF_JIT=y /boot/config-* 2>/dev/null && echo 'true' || echo 'unknown')"
echo "KPROBES=$(test -e /sys/kernel/debug/tracing/kprobe_events && echo 'true' || echo 'false')"
echo "TRACEPOINTS=$(test -e /sys/kernel/debug/tracing/events && echo 'true' || echo 'false')"
echo "BPF_FS=$(test -e /sys/fs/bpf && echo 'true' || echo 'false')"

# Check for ring buffer support
RINGBUF_SUPPORT="false"
if test -e /sys/kernel/btf/vmlinux; then
    if grep -q BPF_MAP_TYPE_RINGBUF /proc/kallsyms 2>/dev/null; then
        RINGBUF_SUPPORT="true"
    fi
fi
echo "RINGBUF_SUPPORT=$RINGBUF_SUPPORT"

# Check libbpf tools availability
echo "BPFTOOL=$(command -v bpftool >/dev/null && echo 'true' || echo 'false')"

# Check CO-RE support indicators
CORE_SUPPORT="false"
if test -e /sys/kernel/btf/vmlinux; then
    if command -v bpftool >/dev/null && bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep -q "struct sock"; then
        CORE_SUPPORT="true"
    fi
fi
echo "CORE_SUPPORT=$CORE_SUPPORT"

# Check available kprobe points
KPROBE_POINTS="0"
if test -e /sys/kernel/debug/tracing/kprobe_events; then
    KPROBE_POINTS=$(grep -E '(tcp_v4_connect|udp_sendmsg|__sys_socket)' /proc/kallsyms 2>/dev/null | wc -l)
fi
echo "KPROBE_POINTS=$KPROBE_POINTS"

# Check security restrictions
echo "UNPRIVILEGED_BPF=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo 'unknown')"
echo "BPF_JIT_HARDEN=$(sysctl -n net.core.bpf_jit_harden 2>/dev/null || echo 'unknown')"
EOF
    else
        # Local execution
        echo "KERNEL_VERSION=$(uname -r)"
        echo "ARCHITECTURE=$(uname -m)"
        echo "BTF_VMLINUX=$(test -e /sys/kernel/btf/vmlinux && echo 'true' || echo 'false')"
        echo "BPF_SYSCALL=$(grep -q CONFIG_BPF_SYSCALL=y /boot/config-* 2>/dev/null && echo 'true' || echo 'unknown')"
        echo "BPF_JIT=$(grep -q CONFIG_BPF_JIT=y /boot/config-* 2>/dev/null && echo 'true' || echo 'unknown')"
        echo "KPROBES=$(test -e /sys/kernel/debug/tracing/kprobe_events && echo 'true' || echo 'false')"
        echo "TRACEPOINTS=$(test -e /sys/kernel/debug/tracing/events && echo 'true' || echo 'false')"
        echo "BPF_FS=$(test -e /sys/fs/bpf && echo 'true' || echo 'false')"
        
        RINGBUF_SUPPORT="false"
        if test -e /sys/kernel/btf/vmlinux; then
            if grep -q BPF_MAP_TYPE_RINGBUF /proc/kallsyms 2>/dev/null; then
                RINGBUF_SUPPORT="true"
            fi
        fi
        echo "RINGBUF_SUPPORT=$RINGBUF_SUPPORT"
        
        echo "BPFTOOL=$(command -v bpftool >/dev/null && echo 'true' || echo 'false')"
        
        CORE_SUPPORT="false"
        if test -e /sys/kernel/btf/vmlinux; then
            if command -v bpftool >/dev/null && bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep -q "struct sock"; then
                CORE_SUPPORT="true"
            fi
        fi
        echo "CORE_SUPPORT=$CORE_SUPPORT"
        
        KPROBE_POINTS="0"
        if test -e /sys/kernel/debug/tracing/kprobe_events; then
            KPROBE_POINTS=$(grep -E '(tcp_v4_connect|udp_sendmsg|__sys_socket)' /proc/kallsyms 2>/dev/null | wc -l)
        fi
        echo "KPROBE_POINTS=$KPROBE_POINTS"
        
        echo "UNPRIVILEGED_BPF=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo 'unknown')"
        echo "BPF_JIT_HARDEN=$(sysctl -n net.core.bpf_jit_harden 2>/dev/null || echo 'unknown')"
    fi
}

echo "Profiling kernel on ${REMOTE_HOST:-localhost}..."

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Run all profiling commands in a single session
PROFILE_OUTPUT=$(run_remote_profiling)

# Parse the output
eval "$PROFILE_OUTPUT"

echo "Kernel: $KERNEL_VERSION ($ARCHITECTURE)"

# Generate JSON profile
cat > "$CONFIG_DIR/$OUTPUT_FILE" << EOF
{
  "profile_info": {
    "timestamp": "$TIMESTAMP",
    "profiled_host": "${REMOTE_HOST:-localhost}",
    "generated_by": "$(whoami)@$(hostname)"
  },
  "kernel": {
    "version": "$KERNEL_VERSION",
    "architecture": "$ARCHITECTURE"
  },
  "bpf_features": {
    "btf_vmlinux": $BTF_VMLINUX,
    "bpf_syscall": "$BPF_SYSCALL",
    "bpf_jit": "$BPF_JIT",
    "bpf_fs": $BPF_FS,
    "ringbuf_support": $RINGBUF_SUPPORT,
    "core_support": $CORE_SUPPORT,
    "unprivileged_bpf_disabled": "$UNPRIVILEGED_BPF",
    "bpf_jit_harden": "$BPF_JIT_HARDEN"
  },
  "tracing": {
    "kprobes": $KPROBES,
    "tracepoints": $TRACEPOINTS,
    "available_kprobe_points": $KPROBE_POINTS
  },
  "tools": {
    "bpftool": $BPFTOOL
  },
  "recommendations": {
    "use_btf": $BTF_VMLINUX,
    "use_core": $CORE_SUPPORT,
    "use_ringbuf": $RINGBUF_SUPPORT,
    "use_kprobes": $KPROBES
  }
}
EOF

echo "Kernel profile saved to: $CONFIG_DIR/$OUTPUT_FILE"
echo ""
echo "Summary:"
echo "  BTF Support: $BTF_VMLINUX"
echo "  CO-RE Support: $CORE_SUPPORT"  
echo "  Ring Buffer: $RINGBUF_SUPPORT"
echo "  Kprobes: $KPROBES"
echo "  Available kprobe points: $KPROBE_POINTS"
echo ""

if [ "$BTF_VMLINUX" = "false" ]; then
    echo "⚠️  BTF not available - will use legacy BPF features"
fi

if [ "$CORE_SUPPORT" = "false" ]; then
    echo "⚠️  CO-RE not available - will use direct memory access"
fi

if [ "$RINGBUF_SUPPORT" = "false" ]; then
    echo "⚠️  Ring buffer not available - will use perf buffer"
fi

echo ""
echo "Use this profile with: meson configure builddir -Dkernel_profile=$OUTPUT_FILE"
