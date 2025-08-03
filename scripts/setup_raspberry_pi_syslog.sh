#!/bin/bash
#
# setup_raspberry_pi_syslog.sh - Configure Raspberry Pi as remote syslog server
# Organizes logs by hostname/IP address for easy management
#

set -e

SYSLOG_DIR="/var/log/remote_monitor"
SYSLOG_CONF="/etc/rsyslog.d/10-remote-monitor.conf"
LOGROTATE_CONF="/etc/logrotate.d/remote-monitor"

echo "=== Remote Monitor Syslog Server Setup ==="
echo "Setting up Raspberry Pi to receive remote logs from monitor clients"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Create log directory structure
echo "Creating log directory structure..."
mkdir -p $SYSLOG_DIR/hosts
chown syslog:adm $SYSLOG_DIR
chown syslog:adm $SYSLOG_DIR/hosts
chmod 755 $SYSLOG_DIR
chmod 755 $SYSLOG_DIR/hosts

# Configure rsyslog to accept remote connections
echo "Configuring rsyslog for remote logging..."

cat > $SYSLOG_CONF << 'EOF'
# Remote Monitor Logging Configuration
# Enable UDP syslog reception
module(load="imudp")
input(type="imudp" port="514")

# Create log directories by hostname
$CreateDirs on

# Template for hostname-based logging
$template RemoteMonitorFormat,"/var/log/remote_monitor/hosts/%HOSTNAME%/%PROGRAMNAME%.log"
$template RemoteLogFormat,"%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n"

# Route monitor logs by hostname
if $programname == 'monitor' then {
    ?RemoteMonitorFormat;RemoteLogFormat
    stop
}

# Route other remote logs to a general remote log
if $fromhost-ip != '127.0.0.1' then {
    /var/log/remote_monitor/remote.log;RemoteLogFormat
    stop
}
EOF

# Configure firewall to allow syslog traffic
echo "Configuring firewall..."
if command -v ufw >/dev/null 2>&1; then
    ufw allow 514/udp comment "Syslog remote logging"
elif command -v iptables >/dev/null 2>&1; then
    iptables -A INPUT -p udp --dport 514 -j ACCEPT
    # Save iptables rules (Debian/Ubuntu)
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
fi

# Configure log rotation
echo "Setting up log rotation..."
cat > $LOGROTATE_CONF << 'EOF'
/var/log/remote_monitor/hosts/*/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    copytruncate
    create 640 syslog adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}

/var/log/remote_monitor/remote.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    copytruncate
    create 640 syslog adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

# Create a simple log monitoring script
echo "Creating log monitoring script..."
cat > /usr/local/bin/monitor-log-viewer << 'EOF'
#!/bin/bash
#
# monitor-log-viewer - Monitor incoming monitor logs
#

SYSLOG_DIR="/var/log/remote_monitor"

echo "=== Remote Monitor Log Viewer ==="
echo "Monitoring logs in $SYSLOG_DIR"
echo "Press Ctrl+C to exit"
echo

# Function to show current log activity
show_activity() {
    echo "=== Recent Log Activity ==="
    find $SYSLOG_DIR -name "*.log" -type f -mmin -5 -exec echo "Recent activity in: {}" \; -exec tail -3 {} \; -exec echo \;
}

# Function to show log statistics
show_stats() {
    echo "=== Log Statistics ==="
    echo "Active hosts:"
    ls -1 $SYSLOG_DIR/hosts/ 2>/dev/null | wc -l
    echo "Total log files:"
    find $SYSLOG_DIR -name "*.log" -type f | wc -l
    echo "Disk usage:"
    du -sh $SYSLOG_DIR
    echo
}

# Show initial stats
show_stats

# Monitor loop
while true; do
    show_activity
    echo "--- Waiting 30 seconds for next update ---"
    sleep 30
    clear
    show_stats
done
EOF

chmod +x /usr/local/bin/monitor-log-viewer

# Create a log viewer script
echo "Creating log viewer script..."
cat > /usr/local/bin/monitor-logs << 'EOF'
#!/bin/bash
#
# monitor-logs - View monitor logs by hostname
#

SYSLOG_DIR="/var/log/remote_monitor"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <hostname> [lines]"
    echo "       $0 list    - show available hosts"
    echo "       $0 all     - show all recent logs"
    echo
    echo "Available hosts:"
    ls -1 $SYSLOG_DIR/hosts/ 2>/dev/null
    exit 1
fi

case "$1" in
    "list")
        echo "Available hosts:"
        ls -1 $SYSLOG_DIR/hosts/ 2>/dev/null
        ;;
    "all")
        echo "Recent logs from all hosts:"
        find $SYSLOG_DIR/hosts -name "*.log" -type f -exec tail -10 {} \; -exec echo "---" \;
        ;;
    *)
        HOSTNAME="$1"
        LINES="${2:-50}"
        
        if [ -d "$SYSLOG_DIR/hosts/$HOSTNAME" ]; then
            echo "Recent logs from $HOSTNAME:"
            find "$SYSLOG_DIR/hosts/$HOSTNAME" -name "*.log" -type f -exec tail -$LINES {} \;
        else
            echo "No logs found for hostname: $HOSTNAME"
            echo "Available hosts:"
            ls -1 $SYSLOG_DIR/hosts/ 2>/dev/null
        fi
        ;;
esac
EOF

chmod +x /usr/local/bin/monitor-logs

# Restart and enable rsyslog
echo "Restarting rsyslog service..."
systemctl restart rsyslog
systemctl enable rsyslog

# Show service status
echo "Checking rsyslog status..."
systemctl status rsyslog --no-pager -l

# Show listening ports
echo "Verifying syslog is listening on UDP port 514..."
netstat -ulnp | grep :514 || echo "Warning: Port 514 not found in netstat output"

echo
echo "=== Setup Complete ==="
echo "Raspberry Pi is now configured as a remote syslog server"
echo "Log files will be organized in: $SYSLOG_DIR/hosts/<hostname>/"
echo
echo "Useful commands:"
echo "  monitor-log-viewer     - Monitor live log activity"
echo "  monitor-logs <host>    - View logs from specific host"
echo "  monitor-logs list      - List available hosts"
echo "  monitor-logs all       - View recent logs from all hosts"
echo
echo "Test the setup from a client with:"
echo "  logger -n <pi-ip> -P 514 -t monitor 'Test message from client'"
echo
