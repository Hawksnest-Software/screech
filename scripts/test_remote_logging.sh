#!/bin/bash
#
# test_remote_logging.sh - Test remote logging setup
# Tests connectivity between client and Raspberry Pi syslog server
#

set -e

PI_IP="${1:-192.168.1.28}"
ARM_MAC_IP="${2:-192.168.1.36}"
SYSLOG_PORT=514

echo "=== Remote Logging Test Script ==="
echo "Testing remote syslog connectivity"
echo "Raspberry Pi IP: $PI_IP"
echo "ARM Mac IP: $ARM_MAC_IP"
echo

# Function to test network connectivity
test_connectivity() {
    local host=$1
    local port=$2
    local description=$3
    
    echo "Testing connectivity to $description ($host:$port)..."
    
    if command -v nc >/dev/null 2>&1; then
        if timeout 5 nc -zu "$host" "$port" 2>/dev/null; then
            echo "✓ Port $port is open on $host"
            return 0
        else
            echo "✗ Port $port is not accessible on $host"
            return 1
        fi
    else
        echo "⚠ netcat (nc) not available, skipping port test"
        return 0
    fi
}

# Function to send test syslog message
send_test_message() {
    local host=$1
    local message=$2
    
    echo "Sending test message to $host: '$message'"
    
    if command -v logger >/dev/null 2>&1; then
        logger -n "$host" -P $SYSLOG_PORT -t monitor "$message"
        echo "✓ Test message sent"
    else
        echo "⚠ logger command not available"
    fi
}

# Function to test with python if available
send_python_test() {
    local host=$1
    local message=$2
    
    echo "Sending test message via Python socket to $host..."
    
    python3 - <<EOF
import socket
import time
import sys

host = "$host"
port = $SYSLOG_PORT
message = "<134>$(date '+%b %d %H:%M:%S') $(hostname) monitor[$$]: $message"

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(message.encode('utf-8'), (host, port))
    sock.close()
    print("✓ Python socket test message sent successfully")
except Exception as e:
    print(f"✗ Python socket test failed: {e}")
    sys.exit(1)
EOF
}

echo "=== Network Connectivity Tests ==="

# Test connectivity to Raspberry Pi
if test_connectivity "$PI_IP" "$SYSLOG_PORT" "Raspberry Pi"; then
    PI_REACHABLE=true
else
    PI_REACHABLE=false
fi

echo

# Test basic syslog functionality
echo "=== Syslog Test Messages ==="

if [ "$PI_REACHABLE" = true ]; then
    echo "Testing syslog messages to Raspberry Pi..."
    send_test_message "$PI_IP" "Test message from $(hostname) - Remote logging test"
    
    # Try Python method as backup
    if command -v python3 >/dev/null 2>&1; then
        send_python_test "$PI_IP" "Python socket test from $(hostname)"
    fi
    
    echo "Test messages sent to Raspberry Pi. Check logs with:"
    echo "  ssh pi@$PI_IP 'sudo monitor-logs $(hostname)'"
    echo "  ssh pi@$PI_IP 'sudo monitor-log-viewer'"
else
    echo "⚠ Skipping syslog tests - Raspberry Pi not reachable"
fi

echo

# Test current system's hostname resolution
echo "=== System Information ==="
echo "Current hostname: $(hostname)"
echo "Current IP addresses:"
ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print "  " $2}' || ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print "  " $2}'

echo

# Check if we're running on the ARM Mac
CURRENT_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[^ ]+' || echo "unknown")
if [[ "$CURRENT_IP" == "$ARM_MAC_IP" ]] || [[ "$(hostname)" == *"arm"* ]] || [[ "$(uname -m)" == "arm64" ]]; then
    echo "=== ARM Mac Detected ==="
    echo "This appears to be the ARM Mac at $ARM_MAC_IP"
    echo "Testing remote logging from ARM Mac to Raspberry Pi..."
    
    if [ "$PI_REACHABLE" = true ]; then
        send_test_message "$PI_IP" "ARM Mac test message - $(date)"
    fi
fi

echo

echo "=== Manual Testing Commands ==="
echo "To manually test remote logging:"
echo
echo "1. Send test message from current system:"
echo "   logger -n $PI_IP -P $SYSLOG_PORT -t monitor 'Manual test message'"
echo
echo "2. Check logs on Raspberry Pi:"
echo "   ssh pi@$PI_IP 'sudo monitor-logs $(hostname)'"
echo "   ssh pi@$PI_IP 'sudo monitor-logs list'"
echo
echo "3. Monitor live logs on Raspberry Pi:"
echo "   ssh pi@$PI_IP 'sudo monitor-log-viewer'"
echo
echo "4. Test the actual monitor application:"
echo "   ./monitor --remote-log-server $PI_IP --verbose"
echo

echo "=== Setup Verification ==="
echo "If tests are failing, verify:"
echo "1. Raspberry Pi syslog server is running:"
echo "   ssh pi@$PI_IP 'sudo systemctl status rsyslog'"
echo
echo "2. Firewall allows UDP port 514:"
echo "   ssh pi@$PI_IP 'sudo ufw status | grep 514'"
echo
echo "3. Syslog is listening on port 514:"
echo "   ssh pi@$PI_IP 'sudo netstat -ulnp | grep :514'"
echo
echo "4. Check for any syslog errors:"
echo "   ssh pi@$PI_IP 'sudo journalctl -u rsyslog -f'"

echo
echo "=== Test Complete ==="
