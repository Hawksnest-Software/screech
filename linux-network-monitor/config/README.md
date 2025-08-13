# Network Tap Configuration

This directory contains configuration files and scripts for setting up a Raspberry Pi as a network tap to monitor target device traffic.

## Files

- `network_tap.nft.template` - nftables configuration template with variable placeholders
- `setup_network_tap.sh` - Script to configure and manage the network tap

## Features

- **Dual Stack Support**: Monitors both IPv4 and IPv6 traffic
- **Dynamic Configuration**: Uses templates with variable substitution to avoid hardcoding sensitive information
- **Logging**: Logs all traffic to/from the target device with prefixed messages
- **Traffic Counters**: Maintains packet and byte counters for monitored traffic  
- **Masquerading**: Handles NAT for both IPv4 and IPv6 to maintain connectivity
- **Auto-discovery**: Can automatically discover devices on the network

## Usage

### Basic Setup

```bash
# Auto-discover devices on the network
sudo ./scripts/setup_network_tap.sh --auto-discover

# Configure tap for specific device
sudo ./scripts/setup_network_tap.sh \
    --target-ip 192.168.1.34 \
    --target-mac fa:b4:d9:42:2c:e9

# Configure with custom interfaces
sudo ./scripts/setup_network_tap.sh \
    --target-ip 192.168.1.34 \
    --target-mac fa:b4:d9:42:2c:e9 \
    --primary-iface eth0 \
    --secondary-iface wlan0
```

### Monitoring Traffic

```bash
# View logged traffic in real-time
sudo journalctl -k -f | grep TAP

# Capture packets with tcpdump
sudo tcpdump -i any host 192.168.1.34

# View nftables counters
sudo nft list ruleset
```

### Cleanup

```bash
# Remove network tap configuration
sudo ./scripts/setup_network_tap.sh --remove
```

## Network Architecture

```
[Internet] <-> [Gateway] <-> [Raspberry Pi Tap] <-> [Target Device]
                                     |
                                 [Monitor/Log]
```

The Raspberry Pi acts as a transparent proxy, forwarding all traffic while logging and monitoring packets to/from the target device.

## Requirements

- Raspberry Pi with Debian 12+ (Bookworm)
- nftables support (kernel 3.13+)
- Root privileges for network configuration
- Network interfaces: typically eth0 and wlan0

## Security Considerations

- Template files use variable placeholders to avoid storing sensitive information in version control
- Generated configuration files are stored in `/tmp` and not persisted in the repository
- All network changes require root privileges
- Logs may contain sensitive network information - handle appropriately

## Troubleshooting

### Check IP Forwarding
```bash
sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.forwarding
```

### Verify nftables Rules
```bash
sudo nft list tables
sudo nft list table inet tap_monitor
```

### Check Network Interfaces
```bash
ip addr show
ip route show
```

### Monitor System Logs
```bash
sudo journalctl -k -f | grep -E "(TAP|nft)"
```
