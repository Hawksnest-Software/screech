#!/bin/bash
#
# setup_endpoint_security_rsyslog.sh - Configure rsyslog for endpoint security monitor logs
# Receives logs from macOS endpoint security monitor at 192.168.1.25 over UDP
#

set -e

SYSLOG_DIR="/var/log/endpoint_security"
SYSLOG_CONF="/etc/rsyslog.d/20-endpoint-security-monitor.conf"
LOGROTATE_CONF="/etc/logrotate.d/endpoint-security-monitor"
MONITOR_HOST="192.168.1.25"

echo "=== Endpoint Security Monitor Rsyslog Setup ==="
echo "Setting up rsyslog to receive endpoint security logs from $MONITOR_HOST"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Create log directory structure
echo "Creating log directory structure..."
mkdir -p $SYSLOG_DIR/processes
mkdir -p $SYSLOG_DIR/files
mkdir -p $SYSLOG_DIR/system
chown syslog:adm $SYSLOG_DIR
chown syslog:adm $SYSLOG_DIR/processes
chown syslog:adm $SYSLOG_DIR/files
chown syslog:adm $SYSLOG_DIR/system
chmod 755 $SYSLOG_DIR
chmod 755 $SYSLOG_DIR/processes
chmod 755 $SYSLOG_DIR/files
chmod 755 $SYSLOG_DIR/system

# Configure rsyslog for endpoint security monitor
echo "Configuring rsyslog for endpoint security monitor..."

cat > $SYSLOG_CONF << 'EOF'
# Endpoint Security Monitor Logging Configuration
# Receives logs from macOS endpoint security monitor over UDP

# Enable UDP syslog reception if not already enabled
module(load="imudp")
input(type="imudp" port="514")

# Create log directories automatically
$CreateDirs on

# Templates for different log types
$template EndpointSecurityProcessLog,"/var/log/endpoint_security/processes/%HOSTNAME%_processes.log"
$template EndpointSecurityFileLog,"/var/log/endpoint_security/files/%HOSTNAME%_files.log"
$template EndpointSecuritySystemLog,"/var/log/endpoint_security/system/%HOSTNAME%_system.log"
$template EndpointSecurityMainLog,"/var/log/endpoint_security/%HOSTNAME%_all.log"
$template EndpointSecurityLogFormat,"%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n"

# Filter logs from endpoint security monitor (IP: 192.168.1.25)
# Process-related events (EXEC, FORK, EXIT)
if ($fromhost-ip == "192.168.1.25" and ($msg contains "PROCESS_EXEC" or $msg contains "PROCESS_FORK" or $msg contains "PROCESS_EXIT")) then {
    ?EndpointSecurityProcessLog;EndpointSecurityLogFormat
    ?EndpointSecurityMainLog;EndpointSecurityLogFormat
    stop
}

# File-related events (OPEN, WRITE, CLOSE, UNLINK, RENAME, CREATE)
if ($fromhost-ip == "192.168.1.25" and ($msg contains "FILE_OPEN" or $msg contains "FILE_WRITE" or $msg contains "FILE_CLOSE" or $msg contains "FILE_UNLINK" or $msg contains "FILE_RENAME" or $msg contains "FILE_CREATE")) then {
    ?EndpointSecurityFileLog;EndpointSecurityLogFormat
    ?EndpointSecurityMainLog;EndpointSecurityLogFormat
    stop
}

# System-related events (SIGNAL, MMAP, etc.)
if ($fromhost-ip == "192.168.1.25" and $programname == "monitor") then {
    ?EndpointSecuritySystemLog;EndpointSecurityLogFormat
    ?EndpointSecurityMainLog;EndpointSecurityLogFormat
    stop
}

# Catch-all for any other logs from the endpoint security monitor host
if $fromhost-ip == "192.168.1.25" then {
    ?EndpointSecurityMainLog;EndpointSecurityLogFormat
    stop
}
EOF

# Configure firewall to allow syslog traffic
echo "Configuring firewall..."
if command -v ufw > /dev/null 2>&1; then
    ufw allow from $MONITOR_HOST to any port 514 comment "Endpoint Security Monitor logs"
    ufw allow 514/udp comment "Syslog remote logging"
elif command -v iptables > /dev/null 2>&1; then
    iptables -A INPUT -p udp -s $MONITOR_HOST --dport 514 -j ACCEPT
    iptables -A INPUT -p udp --dport 514 -j ACCEPT
    # Save iptables rules (Debian/Ubuntu)
    if command -v iptables-save > /dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
fi

# Configure log rotation
echo "Setting up log rotation..."
cat > $LOGROTATE_CONF << 'EOF'
/var/log/endpoint_security/*/*.log {
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

/var/log/endpoint_security/*.log {
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

# Create endpoint security log monitoring script
echo "Creating endpoint security log monitoring script..."
cat > /usr/local/bin/endpoint-security-logs << 'EOF'
#!/bin/bash
#
# endpoint-security-logs - Monitor endpoint security logs from remote host
#

SYSLOG_DIR="/var/log/endpoint_security"
MONITOR_HOST="192.168.1.25"

case "$1" in
    "processes")
        echo "Process Events from $MONITOR_HOST:"
        echo "=================================="
        find $SYSLOG_DIR/processes -name "*_processes.log" -exec echo "--- {} ---" \; -exec tail -20 {} \; 2>/dev/null
        ;;
    "files")
        echo "File Events from $MONITOR_HOST:"
        echo "=============================="
        find $SYSLOG_DIR/files -name "*_files.log" -exec echo "--- {} ---" \; -exec tail -20 {} \; 2>/dev/null
        ;;
    "system")
        echo "System Events from $MONITOR_HOST:"
        echo "================================"
        find $SYSLOG_DIR/system -name "*_system.log" -exec echo "--- {} ---" \; -exec tail -20 {} \; 2>/dev/null
        ;;
    "all")
        echo "All Events from $MONITOR_HOST:"
        echo "============================="
        find $SYSLOG_DIR -name "*_all.log" -exec echo "--- {} ---" \; -exec tail -20 {} \; 2>/dev/null
        ;;
    "watch")
        TYPE="${2:-all}"
        case "$TYPE" in
            "processes")
                echo "Watching process events from $MONITOR_HOST (Press Ctrl+C to stop)..."
                find $SYSLOG_DIR/processes -name "*_processes.log" -exec tail -f {} + 2>/dev/null
                ;;
            "files")
                echo "Watching file events from $MONITOR_HOST (Press Ctrl+C to stop)..."
                find $SYSLOG_DIR/files -name "*_files.log" -exec tail -f {} + 2>/dev/null
                ;;
            "system")
                echo "Watching system events from $MONITOR_HOST (Press Ctrl+C to stop)..."
                find $SYSLOG_DIR/system -name "*_system.log" -exec tail -f {} + 2>/dev/null
                ;;
            *)
                echo "Watching all events from $MONITOR_HOST (Press Ctrl+C to stop)..."
                find $SYSLOG_DIR -name "*_all.log" -exec tail -f {} + 2>/dev/null
                ;;
        esac
        ;;
    "stats")
        echo "Endpoint Security Monitor Log Statistics:"
        echo "========================================"
        echo "Monitor Host: $MONITOR_HOST"
        echo
        echo "Process events:"
        find $SYSLOG_DIR/processes -name "*_processes.log" -exec wc -l {} \; 2>/dev/null | awk '{sum+=$1} END {print "  Total:", sum ? sum : 0, "events"}'
        echo "File events:"
        find $SYSLOG_DIR/files -name "*_files.log" -exec wc -l {} \; 2>/dev/null | awk '{sum+=$1} END {print "  Total:", sum ? sum : 0, "events"}'
        echo "System events:"
        find $SYSLOG_DIR/system -name "*_system.log" -exec wc -l {} \; 2>/dev/null | awk '{sum+=$1} END {print "  Total:", sum ? sum : 0, "events"}'
        echo
        echo "Disk usage:"
        du -sh $SYSLOG_DIR 2>/dev/null || echo "  No logs yet"
        echo
        echo "Recent activity (last 5 minutes):"
        find $SYSLOG_DIR -name "*.log" -type f -mmin -5 2>/dev/null | wc -l | awk '{print "  Files updated:", $1}'
        ;;
    "test")
        echo "Testing endpoint security monitor connection..."
        echo "Sending test message to verify rsyslog configuration..."
        logger -n localhost -P 514 -t monitor --id=$$ "TEST: Endpoint security monitor test message from $(hostname)"
        echo "Test message sent. Check logs with: endpoint-security-logs all"
        ;;
    *)
        echo "Endpoint Security Monitor Log Viewer"
        echo "Usage: $0 {processes|files|system|all|watch|stats|test} [type]"
        echo
        echo "Commands:"
        echo "  processes    - Show recent process events (EXEC, FORK, EXIT)"
        echo "  files        - Show recent file events (OPEN, WRITE, etc.)"
        echo "  system       - Show recent system events"
        echo "  all          - Show all recent events"
        echo "  watch [type] - Watch live events (processes, files, system, all)"
        echo "  stats        - Show log statistics and disk usage"
        echo "  test         - Send test message to verify configuration"
        echo
        echo "Examples:"
        echo "  $0 processes"
        echo "  $0 watch files"
        echo "  $0 stats"
        echo
        echo "Log files are organized by event type:"
        echo "  Processes: $SYSLOG_DIR/processes/"
        echo "  Files:     $SYSLOG_DIR/files/"
        echo "  System:    $SYSLOG_DIR/system/"
        echo "  All:       $SYSLOG_DIR/"
        ;;
esac
EOF

chmod +x /usr/local/bin/endpoint-security-logs

# Create a simple real-time monitor script
echo "Creating real-time monitor script..."
cat > /usr/local/bin/endpoint-security-monitor << 'EOF'
#!/bin/bash
#
# endpoint-security-monitor - Real-time endpoint security event monitor
#

SYSLOG_DIR="/var/log/endpoint_security"
MONITOR_HOST="192.168.1.25"

echo "=== Real-time Endpoint Security Monitor ==="
echo "Monitoring events from: $MONITOR_HOST"
echo "Press Ctrl+C to stop"
echo

# Function to show recent activity
show_activity() {
    echo "=== Recent Activity (last 1 minute) ==="
    echo "Time: $(date)"
    
    # Process events
    PROC_COUNT=$(find $SYSLOG_DIR/processes -name "*.log" -newermt "1 minute ago" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo "0")
    echo "Process events: $PROC_COUNT"
    
    # File events
    FILE_COUNT=$(find $SYSLOG_DIR/files -name "*.log" -newermt "1 minute ago" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo "0")
    echo "File events: $FILE_COUNT"
    
    # System events
    SYS_COUNT=$(find $SYSLOG_DIR/system -name "*.log" -newermt "1 minute ago" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo "0")
    echo "System events: $SYS_COUNT"
    
    echo
    echo "=== Latest Events ==="
    find $SYSLOG_DIR -name "*.log" -type f -exec tail -3 {} + 2>/dev/null | head -20
    echo "=========================================="
}

# Monitor loop
while true; do
    clear
    show_activity
    echo
    echo "Next update in 30 seconds..."
    sleep 30
done
EOF

chmod +x /usr/local/bin/endpoint-security-monitor

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
echo "Rsyslog is now configured to receive endpoint security monitor logs from $MONITOR_HOST"
echo "Log files will be organized in: $SYSLOG_DIR/"
echo
echo "Directory structure:"
echo "  Main logs:    $SYSLOG_DIR/[hostname]_all.log"
echo "  Process logs: $SYSLOG_DIR/processes/[hostname]_processes.log"
echo "  File logs:    $SYSLOG_DIR/files/[hostname]_files.log"
echo "  System logs:  $SYSLOG_DIR/system/[hostname]_system.log"
echo
echo "Useful commands:"
echo "  endpoint-security-logs processes  - View process events"
echo "  endpoint-security-logs files      - View file events"
echo "  endpoint-security-logs watch all  - Watch live events"
echo "  endpoint-security-logs stats      - View statistics"
echo "  endpoint-security-monitor         - Real-time monitoring dashboard"
echo
echo "Test from the macOS endpoint security monitor with:"
echo "  ./macos-endpoint-security-monitor --remote-log-server $(hostname -I | awk '{print $1}') --verbose"
echo
echo "Or test locally with:"
echo "  endpoint-security-logs test"
