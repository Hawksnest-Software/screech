#!/bin/bash
#
# setup_raspberry_pi_systemd.sh - Configure Raspberry Pi systemd for remote logging
# Uses systemd-journald and journal-remote for log collection
#

set -e

LOG_DIR="/var/log/remote_monitor"
JOURNAL_REMOTE_CONF="/etc/systemd/journal-remote.conf"
JOURNAL_UPLOAD_CONF="/etc/systemd/journal-upload.conf"
SYSTEMD_CONF="/etc/systemd/journald.conf"

echo "=== Remote Monitor systemd Logging Server Setup ==="
echo "Setting up Raspberry Pi to receive remote logs using systemd"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Install systemd-journal-remote if not present
echo "Installing systemd-journal-remote..."
apt-get update
apt-get install -y systemd-journal-remote netcat-openbsd

# Create log directory structure
echo "Creating log directory structure..."
mkdir -p $LOG_DIR/hosts
mkdir -p /var/log/journal-remote
chmod 755 $LOG_DIR
chmod 755 $LOG_DIR/hosts
chmod 755 /var/log/journal-remote

# Configure systemd-journald to accept remote logs
echo "Configuring systemd-journald..."
cp $SYSTEMD_CONF $SYSTEMD_CONF.backup 2>/dev/null || true

cat > $SYSTEMD_CONF << 'EOF'
[Journal]
Storage=persistent
Compress=yes
SplitMode=host
SealInterval=1h
MaxRetentionSec=1month
MaxFileSec=1week
ForwardToSyslog=no
ForwardToKMsg=no
ForwardToConsole=no
EOF

# Create a simple syslog-style receiver using systemd
echo "Setting up syslog UDP receiver service..."

# Create a simple UDP syslog receiver script
cat > /usr/local/bin/syslog-receiver << 'EOF'
#!/bin/bash
#
# syslog-receiver - Simple UDP syslog receiver for systemd
#

LOG_DIR="/var/log/remote_monitor"

# Function to parse syslog message and extract hostname
parse_syslog() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Extract hostname from syslog message format
    # Format: <priority>timestamp hostname program: message
    if [[ $message =~ ^\<[0-9]+\>.*\ ([^\ ]+)\ ([^:\ \[]+)(\[[0-9]+\])?:\ (.*)$ ]]; then
        local hostname="${BASH_REMATCH[1]}"
        local program="${BASH_REMATCH[2]}"
        local message_content="${BASH_REMATCH[4]}"
        
        # Create host directory if it doesn't exist
        mkdir -p "$LOG_DIR/hosts/$hostname"
        
        # Write to host-specific log file
        echo "[$timestamp] $hostname $program: $message_content" >> "$LOG_DIR/hosts/$hostname/$program.log"
        
        # Also log to systemd journal
        echo "$hostname $program: $message_content" | systemd-cat -t "remote-$program" -p info
    else
        # Fallback - log to general remote log
        echo "[$timestamp] $message" >> "$LOG_DIR/remote.log"
        echo "$message" | systemd-cat -t "remote-unknown" -p info
    fi
}

# Listen on UDP port 514
echo "Starting syslog UDP receiver on port 514..."
while true; do
    nc -lukp 514 | while read line; do
        parse_syslog "$line"
    done
done
EOF

chmod +x /usr/local/bin/syslog-receiver

# Create systemd service for syslog receiver
cat > /etc/systemd/system/syslog-receiver.service << 'EOF'
[Unit]
Description=Remote Syslog UDP Receiver
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/syslog-receiver
Restart=always
RestartSec=3
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Configure firewall to allow syslog traffic
echo "Configuring firewall..."
if command -v ufw >/dev/null 2>&1; then
    ufw allow 514/udp comment "Syslog remote logging"
elif command -v iptables >/dev/null 2>&1; then
    iptables -A INPUT -p udp --dport 514 -j ACCEPT
    # Try to save iptables rules if iptables-persistent is available
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
    fi
fi

# Create log rotation configuration
echo "Setting up log rotation..."
cat > /etc/logrotate.d/remote-monitor << 'EOF'
/var/log/remote_monitor/hosts/*/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    copytruncate
    create 644 root root
}

/var/log/remote_monitor/remote.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    copytruncate
    create 644 root root
}
EOF

# Create monitoring and viewing scripts
echo "Creating log monitoring script..."
cat > /usr/local/bin/monitor-log-viewer << 'EOF'
#!/bin/bash
#
# monitor-log-viewer - Monitor incoming monitor logs
#

LOG_DIR="/var/log/remote_monitor"

clear
echo "=== Remote Monitor Log Viewer ==="
echo "Monitoring logs in $LOG_DIR"
echo "Press Ctrl+C to exit"
echo

show_stats() {
    echo "=== Log Statistics ($(date)) ==="
    echo "Active hosts:"
    ls -1 $LOG_DIR/hosts/ 2>/dev/null | wc -l
    echo "Total log files:"
    find $LOG_DIR -name "*.log" -type f 2>/dev/null | wc -l
    echo "Recent systemd remote logs:"
    journalctl -t remote-monitor --since "5 minutes ago" --no-pager -q | wc -l
    echo "Disk usage:"
    du -sh $LOG_DIR 2>/dev/null || echo "0B"
    echo
}

show_activity() {
    echo "=== Recent Activity ==="
    echo "File-based logs:"
    find $LOG_DIR -name "*.log" -type f -mmin -5 -exec echo "Recent activity in: {}" \; -exec tail -3 {} \; -exec echo \; 2>/dev/null | head -20
    
    echo "Systemd journal logs (last 5 minutes):"
    journalctl -t remote-monitor --since "5 minutes ago" --no-pager -q | tail -10
    echo
}

# Initial display
show_stats

# Monitor loop
while true; do
    show_activity
    echo "--- Waiting 30 seconds for next update ($(date)) ---"
    sleep 30
    clear
    show_stats
done
EOF

chmod +x /usr/local/bin/monitor-log-viewer

# Create log viewer script
echo "Creating log viewer script..."
cat > /usr/local/bin/monitor-logs << 'EOF'
#!/bin/bash
#
# monitor-logs - View monitor logs by hostname
#

LOG_DIR="/var/log/remote_monitor"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <hostname> [lines]"
    echo "       $0 list         - show available hosts"
    echo "       $0 all          - show all recent logs"
    echo "       $0 journal      - show systemd journal remote logs"
    echo
    echo "Available hosts:"
    ls -1 $LOG_DIR/hosts/ 2>/dev/null
    exit 1
fi

case "$1" in
    "list")
        echo "Available hosts:"
        ls -1 $LOG_DIR/hosts/ 2>/dev/null
        echo
        echo "Systemd journal remote logs available:"
        journalctl --list-boots --no-pager -q | head -5
        ;;
    "all")
        echo "Recent logs from all hosts:"
        find $LOG_DIR/hosts -name "*.log" -type f -exec echo "=== {} ===" \; -exec tail -10 {} \; 2>/dev/null
        ;;
    "journal")
        LINES="${2:-50}"
        echo "Recent systemd journal remote logs:"
        journalctl -t remote-monitor --no-pager -n $LINES
        ;;
    *)
        HOSTNAME="$1"
        LINES="${2:-50}"
        
        if [ -d "$LOG_DIR/hosts/$HOSTNAME" ]; then
            echo "Recent logs from $HOSTNAME:"
            find "$LOG_DIR/hosts/$HOSTNAME" -name "*.log" -type f -exec echo "=== {} ===" \; -exec tail -$LINES {} \; 2>/dev/null
        else
            echo "No logs found for hostname: $HOSTNAME"
            echo "Available hosts:"
            ls -1 $LOG_DIR/hosts/ 2>/dev/null
            echo
            echo "Try: $0 journal    # for systemd journal logs"
        fi
        ;;
esac
EOF

chmod +x /usr/local/bin/monitor-logs

# Restart systemd-journald and enable our service
echo "Restarting systemd services..."
systemctl daemon-reload
systemctl restart systemd-journald
systemctl enable syslog-receiver.service
systemctl start syslog-receiver.service

# Show service status
echo "Checking service status..."
systemctl status syslog-receiver.service --no-pager -l

# Show listening ports
echo "Verifying syslog receiver is listening on UDP port 514..."
sleep 2
netstat -ulnp 2>/dev/null | grep :514 || ss -ulnp 2>/dev/null | grep :514 || echo "Warning: Port 514 not found (service may still be starting)"

echo
echo "=== Setup Complete ==="
echo "Raspberry Pi is now configured as a remote logging server using systemd"
echo "Log files will be organized in: $LOG_DIR/hosts/<hostname>/"
echo "Systemd journal logs are also available via journalctl"
echo
echo "Useful commands:"
echo "  monitor-log-viewer        - Monitor live log activity"
echo "  monitor-logs <host>       - View logs from specific host"
echo "  monitor-logs list         - List available hosts"
echo "  monitor-logs all          - View recent logs from all hosts"
echo "  monitor-logs journal      - View systemd journal remote logs"
echo "  journalctl -t remote-monitor -f  - Follow systemd journal logs"
echo
echo "Test the setup from a client with:"
echo "  logger -n <pi-ip> -P 514 -t monitor 'Test message from client'"
echo
echo "Service management:"
echo "  systemctl status syslog-receiver   - Check service status"
echo "  systemctl restart syslog-receiver  - Restart service"
echo "  journalctl -u syslog-receiver -f   - Follow service logs"
