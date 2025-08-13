#!/bin/bash

# create_log_dirs.sh - Set up rsyslog configuration for individual process logging

echo "Setting up rsyslog configuration for Linux eBPF Network Monitor"
echo "Creating individual log files per process (similar to macOS endpoint security monitor)"

# Create rsyslog configuration for network monitor
RSYSLOG_CONFIG="/etc/rsyslog.d/50-screech-monitor.conf"

if [ ! -f "$RSYSLOG_CONFIG" ]; then
    echo "Creating rsyslog configuration..."
    cat > "$RSYSLOG_CONFIG" << 'EOF'
# Configuration for Linux eBPF Network Monitor
# Individual log files per process (like macOS endpoint security monitor)

# Create individual log files based on program name
# Each process gets its own log file in /var/log/network-monitor/processes/

# Template for dynamic file names based on program name
$template ProcessLogFile,"/var/log/network-monitor/processes/%programname%.log"

# Template for structured logging format
$template ProcessLogFormat,"%timegenerated:::date-rfc3339% %hostname% %programname%[%procid%]: %msg%\n"

# Route screech process logs to individual files
:programname, startswith, "screech-" ?ProcessLogFile;ProcessLogFormat
& stop

# Main monitor application logs
:programname, isequal, "screech-main" /var/log/network-monitor/main.log;ProcessLogFormat
& stop

# Fallback for any other screech logs
:programname, contains, "screech" /var/log/network-monitor/unknown.log;ProcessLogFormat
& stop

# Stop processing these messages (don't send to other log files)
:programname, startswith, "screech" ~
EOF

    echo "Created $RSYSLOG_CONFIG"
else
    echo "Rsyslog configuration already exists at $RSYSLOG_CONFIG"
fi

# Create log directory structure
LOG_BASE_DIR="/var/log/network-monitor"
PROCESSES_DIR="$LOG_BASE_DIR/processes"

echo "Creating log directory structure..."
mkdir -p "$LOG_BASE_DIR"
mkdir -p "$PROCESSES_DIR"

# Set proper permissions
chmod 755 "$LOG_BASE_DIR"
chmod 755 "$PROCESSES_DIR"

# Create initial log files
touch "$LOG_BASE_DIR/main.log"
touch "$LOG_BASE_DIR/unknown.log"
chmod 644 "$LOG_BASE_DIR"/*.log

# Set up log rotation for individual process files
LOGROTATE_CONFIG="/etc/logrotate.d/screech-monitor"
if [ ! -f "$LOGROTATE_CONFIG" ]; then
    echo "Creating log rotation configuration..."
    cat > "$LOGROTATE_CONFIG" << 'EOF'
/var/log/network-monitor/*.log
/var/log/network-monitor/processes/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        /bin/systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF
    echo "Created $LOGROTATE_CONFIG"
fi

# Create a helper script to monitor individual process logs
MONITOR_SCRIPT="/usr/local/bin/screech-logs"
cat > "$MONITOR_SCRIPT" << 'EOF'
#!/bin/bash

# screech-logs - Helper script to monitor individual process network logs

PROCESSES_DIR="/var/log/network-monitor/processes"
MAIN_LOG="/var/log/network-monitor/main.log"

case "$1" in
    list)
        echo "Available process logs:"
        ls -la "$PROCESSES_DIR"/ 2>/dev/null | grep "\.log$" | awk '{print $9}' | sed 's/screech-/  /' | sed 's/\.log//'
        ;;
    watch)
        if [ -z "$2" ]; then
            echo "Usage: screech-logs watch <process-name>"
            echo "Example: screech-logs watch firefox"
            exit 1
        fi
        LOG_FILE="$PROCESSES_DIR/screech-$2.log"
        if [ -f "$LOG_FILE" ]; then
            echo "Monitoring network activity for process: $2"
            echo "Log file: $LOG_FILE"
            echo "Press Ctrl+C to stop"
            echo "----------------------------------------"
            tail -f "$LOG_FILE"
        else
            echo "No log file found for process: $2"
            echo "Available processes:"
            "$0" list
        fi
        ;;
    main)
        echo "Monitoring main application logs..."
        tail -f "$MAIN_LOG"
        ;;
    summary)
        echo "Network Activity Summary:"
        echo "========================"
        echo "Main application events:"
        [ -f "$MAIN_LOG" ] && wc -l "$MAIN_LOG" || echo "  0 main.log"
        echo ""
        echo "Process-specific events:"
        for log in "$PROCESSES_DIR"/screech-*.log; do
            if [ -f "$log" ]; then
                process=$(basename "$log" | sed 's/screech-//' | sed 's/\.log//')
                count=$(wc -l < "$log")
                printf "  %-20s: %d events\n" "$process" "$count"
            fi
        done
        ;;
    *)
        echo "Linux eBPF Network Monitor - Log Viewer"
        echo "Usage: $0 {list|watch|main|summary} [process-name]"
        echo ""
        echo "Commands:"
        echo "  list              - List all monitored processes"
        echo "  watch <process>   - Watch network activity for specific process"
        echo "  main              - Watch main application logs"
        echo "  summary           - Show activity summary"
        echo ""
        echo "Examples:"
        echo "  $0 list"
        echo "  $0 watch firefox"
        echo "  $0 watch chrome"
        echo "  $0 summary"
        ;;
esac
EOF

chmod +x "$MONITOR_SCRIPT"
echo "Created monitoring script at $MONITOR_SCRIPT"

# Restart rsyslog to load new configuration
echo "Reloading rsyslog configuration..."
if systemctl is-active --quiet rsyslog; then
    systemctl reload rsyslog
    echo "Rsyslog configuration reloaded"
else
    echo "Warning: rsyslog service is not running"
    echo "Start rsyslog with: sudo systemctl start rsyslog"
fi

echo ""
echo "Setup complete!"
echo "=================="
echo ""
echo "Log structure:"
echo "  Main logs:    $LOG_BASE_DIR/main.log"
echo "  Process logs: $PROCESSES_DIR/screech-<process>.log"
echo ""
echo "Each monitored process will get its own individual log file:"
echo "  Firefox:      $PROCESSES_DIR/screech-firefox.log"
echo "  Chrome:       $PROCESSES_DIR/screech-chrome.log"
echo "  SSH:          $PROCESSES_DIR/screech-ssh.log"
echo "  curl:         $PROCESSES_DIR/screech-curl.log"
echo "  etc..."
echo ""
echo "Usage examples:"
echo "  screech-logs list                    # List all monitored processes"
echo "  screech-logs watch firefox          # Monitor Firefox network activity"
echo "  screech-logs summary                # Show activity summary"
echo "  tail -f $PROCESSES_DIR/screech-firefox.log  # Direct file monitoring"
echo ""
echo "Start the network monitor with: sudo linux-network-monitor"
