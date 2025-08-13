#!/bin/bash

# Network Tap Configuration Script
# Configures Raspberry Pi as a network tap for monitoring target device traffic
# Supports both IPv4 and IPv6

set -euo pipefail

# Default configuration
# Get the project root directory (parent of scripts directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="${PROJECT_ROOT}/config"
TEMPLATE_FILE="${CONFIG_DIR}/network_tap.nft.template"
OUTPUT_FILE="/tmp/network_tap.nft"
SYSCTL_BACKUP="/tmp/sysctl.conf.backup"

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Configure Raspberry Pi as a network tap for monitoring device traffic.

OPTIONS:
    -t, --target-ip IP          Target device IPv4 address
    -m, --target-mac MAC        Target device MAC address  
    -p, --primary-iface IFACE   Primary network interface (default: eth0)
    -s, --secondary-iface IFACE Secondary network interface (default: wlan0)
    -a, --auto-discover         Auto-discover target device from ARP table
    -r, --remove               Remove network tap configuration
    -h, --help                 Display this help message

EXAMPLES:
    $0 --target-ip 192.168.1.34 --target-mac fa:b4:d9:42:2c:e9
    $0 --auto-discover
    $0 --remove

EOF
}

# Function to auto-discover target device
auto_discover() {
    echo "Auto-discovering devices on network..."
    echo "Available devices:"
    ip neigh show | grep -E "REACHABLE|STALE" | while read line; do
        ip=$(echo "$line" | awk '{print $1}')
        mac=$(echo "$line" | awk '{print $5}')
        iface=$(echo "$line" | awk '{print $7}')
        echo "  IP: $ip, MAC: $mac, Interface: $iface"
    done
    echo
    echo "Please run the script again with specific --target-ip and --target-mac values"
    exit 1
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "Error: Invalid IP address format: $ip"
        exit 1
    fi
}

# Function to validate MAC address
validate_mac() {
    local mac=$1
    if [[ ! $mac =~ ^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$ ]]; then
        echo "Error: Invalid MAC address format: $mac"
        exit 1
    fi
}

# Function to enable IP forwarding
enable_forwarding() {
    echo "Enabling IP forwarding..."
    
    # Backup current sysctl.conf
    if [[ -f /etc/sysctl.conf ]]; then
        cp /etc/sysctl.conf "$SYSCTL_BACKUP"
    fi
    
    # Enable forwarding
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1
    
    # Make persistent
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    fi
}

# Function to generate nftables configuration
generate_config() {
    local target_ip=$1
    local target_mac=$2
    local primary_iface=$3
    local secondary_iface=$4
    
    echo "Generating nftables configuration..."
    
    if [[ ! -f "$TEMPLATE_FILE" ]]; then
        echo "Error: Template file not found: $TEMPLATE_FILE"
        exit 1
    fi
    
    # Create temporary file with proper permissions
    OUTPUT_FILE=$(mktemp /tmp/network_tap_XXXXXX.nft)
    
    # Substitute variables in template
    sed -e "s/{{TARGET_IPV4}}/$target_ip/g" \
        -e "s/{{TARGET_MAC}}/$target_mac/g" \
        -e "s/{{PRIMARY_INTERFACE}}/$primary_iface/g" \
        -e "s/{{SECONDARY_INTERFACE}}/$secondary_iface/g" \
        "$TEMPLATE_FILE" > "$OUTPUT_FILE"
    
    chmod +x "$OUTPUT_FILE"
    echo "Configuration generated: $OUTPUT_FILE"
}

# Function to apply nftables configuration
apply_config() {
    echo "Applying nftables configuration..."
    nft -f "$OUTPUT_FILE"
    echo "nftables rules applied successfully"
    
    echo "Current ruleset:"
    nft list tables
}

# Function to remove network tap configuration
remove_config() {
    echo "Removing network tap configuration..."
    
    # Flush nftables rules
    nft flush ruleset 2>/dev/null || true
    
    # Clean up temporary configuration files
    rm -f /tmp/network_tap_*.nft
    
    # Restore sysctl.conf if backup exists
    if [[ -f "$SYSCTL_BACKUP" ]]; then
        cp "$SYSCTL_BACKUP" /etc/sysctl.conf
        rm -f "$SYSCTL_BACKUP"
    fi
    
    # Disable forwarding
    sysctl -w net.ipv4.ip_forward=0 2>/dev/null || true
    sysctl -w net.ipv6.conf.all.forwarding=0 2>/dev/null || true
    
    echo "Network tap configuration removed"
}

# Function to show current status
show_status() {
    echo "=== Network Tap Status ==="
    echo "IP Forwarding (IPv4): $(sysctl -n net.ipv4.ip_forward)"
    echo "IP Forwarding (IPv6): $(sysctl -n net.ipv6.conf.all.forwarding)"
    echo
    echo "Current nftables tables:"
    nft list tables 2>/dev/null || echo "No nftables rules configured"
    echo
}

# Main function
main() {
    local target_ip=""
    local target_mac=""
    local primary_iface="eth0"
    local secondary_iface="wlan0"
    local auto_discover=false
    local remove=false
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target-ip)
                target_ip="$2"
                shift 2
                ;;
            -m|--target-mac)
                target_mac="$2"
                shift 2
                ;;
            -p|--primary-iface)
                primary_iface="$2"
                shift 2
                ;;
            -s|--secondary-iface)
                secondary_iface="$2"
                shift 2
                ;;
            -a|--auto-discover)
                auto_discover=true
                shift
                ;;
            -r|--remove)
                remove=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Handle remove operation
    if [[ "$remove" == true ]]; then
        remove_config
        exit 0
    fi
    
    # Handle auto-discover
    if [[ "$auto_discover" == true ]]; then
        auto_discover
        exit 0
    fi
    
    # Validate required parameters
    if [[ -z "$target_ip" || -z "$target_mac" ]]; then
        echo "Error: Target IP and MAC address are required"
        usage
        exit 1
    fi
    
    # Validate input
    validate_ip "$target_ip"
    validate_mac "$target_mac"
    
    # Show current status
    show_status
    
    # Configure network tap
    enable_forwarding
    generate_config "$target_ip" "$target_mac" "$primary_iface" "$secondary_iface"
    apply_config
    
    echo
    echo "=== Network Tap Configuration Complete ==="
    echo "Target Device: $target_ip ($target_mac)"
    echo "Primary Interface: $primary_iface"
    echo "Secondary Interface: $secondary_iface"
    echo
    echo "To monitor traffic, check system logs:"
    echo "  sudo journalctl -k -f | grep TAP"
    echo "  sudo tcpdump -i any host $target_ip"
    echo
    echo "To remove configuration:"
    echo "  $0 --remove"
}

# Run main function
main "$@"
