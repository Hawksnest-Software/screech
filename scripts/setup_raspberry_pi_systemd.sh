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
apt-get install -y systemd-journal-remote netcat-openbsd socat

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

# Create a session-based UDP syslog receiver script
cat > /usr/local/bin/syslog-receiver << 'EOF'
#!/bin/bash
#
# syslog-receiver - Session-based UDP syslog receiver for systemd
# Creates separate directories for each remote logging session
#

LOG_DIR="/var/log/remote_monitor"
SESSION_TRACKING_DIR="$LOG_DIR/.sessions"

# Ensure session tracking directory exists
mkdir -p "$SESSION_TRACKING_DIR"

# Function to get or create session directory for a hostname and session ID
get_session_dir() {
    local hostname="$1"
    local session_id="$2"
    
    # Use session ID from remote host if provided, otherwise fall back to timestamp
    local session_name
    if [[ -n "$session_id" && "$session_id" != "unknown" ]]; then
        session_name="$session_id"
    else
        # Fallback to timestamp-based session for backward compatibility
        local session_file="$SESSION_TRACKING_DIR/${hostname}_current_session"
        local session_start_file="$SESSION_TRACKING_DIR/${hostname}_session_start"
        
        # Check if we have an active timestamp-based session
        if [[ -f "$session_file" ]]; then
            local current_session=$(cat "$session_file")
            local session_dir="$LOG_DIR/hosts/$hostname/$current_session"
            
            # Check if session directory still exists and was recently active
            if [[ -d "$session_dir" ]]; then
                local last_activity=$(find "$session_dir" -name "*.log" -mmin -10 2>/dev/null | wc -l)
                if [[ $last_activity -gt 0 ]]; then
                    echo "$session_dir"
                    return 0
                fi
            fi
        fi
        
        # Create new timestamp-based session
        local session_timestamp=$(date '+%Y%m%d_%H%M%S')
        session_name="session_$session_timestamp"
        
        # Update session tracking for timestamp-based sessions
        echo "$session_name" > "$session_file"
        touch "$session_start_file"
    fi
    
    # Create session directory
    local session_dir="$LOG_DIR/hosts/$hostname/$session_name"
    mkdir -p "$session_dir"
    
    echo "$session_dir"
}

# Function to cleanup old sessions (keep last 10 sessions per hostname)
cleanup_old_sessions() {
    find "$LOG_DIR/hosts" -maxdepth 2 -type d -name "session_*" | while read session_dir; do
        local hostname=$(basename $(dirname "$session_dir"))
        
        # Keep only the 10 most recent sessions for each hostname
        ls -1t "$(dirname "$session_dir")" | grep "^session_" | tail -n +11 | while read old_session; do
            echo "Cleaning up old session: $(dirname "$session_dir")/$old_session"
            rm -rf "$(dirname "$session_dir")/$old_session"
        done
    done
}

# Function to parse syslog message and extract hostname
parse_syslog() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Skip empty or malformed messages
    if [[ -z "$message" || ${#message} -lt 10 ]]; then
        return
    fi
    
    # Extract hostname and session ID from syslog message format
    # Format: <priority> hostname program[session_id][tag]: message
    # Example: <134> arms-Mac-mini.local monitor[pid12345_1723740123][EVENT]: EVENT=[FILESYSTEM] ...
    # Fallback: <134> arms-Mac-mini.local monitor[EVENT]: EVENT=[FILESYSTEM] ... (no session ID)
    if [[ $message =~ ^\<[0-9]+\>\ +([a-zA-Z0-9.-]+)\ +([a-zA-Z0-9_.-]+)(\[([^\]]+)\])?(\[([^\]]+)\])?:\ +(.*) ]]; then
        local hostname="${BASH_REMATCH[1]}"
        local program="${BASH_REMATCH[2]}"
        local first_bracket="${BASH_REMATCH[4]}"
        local second_bracket="${BASH_REMATCH[6]}"
        local full_message="${BASH_REMATCH[7]}"
        
        # Parse session ID and tag from brackets
        local session_id="unknown"
        local tag=""
        
        # Determine which bracket contains session ID vs tag
        if [[ "$second_bracket" == "EVENT" || "$second_bracket" == "INFO" || "$second_bracket" == "DEBUG" ]]; then
            # Format: program[session_id][tag]
            session_id="$first_bracket"
            tag="$second_bracket"
        elif [[ "$first_bracket" == "EVENT" || "$first_bracket" == "INFO" || "$first_bracket" == "DEBUG" ]]; then
            # Format: program[tag] (no session ID)
            tag="$first_bracket"
        elif [[ -n "$first_bracket" ]]; then
            # Format: program[session_id] (assume first bracket is session ID if not a known tag)
            session_id="$first_bracket"
        fi
        
        # Only process valid hostnames (avoid partial matches)
        if [[ ${#hostname} -lt 3 || $hostname =~ ^[0-9\<\>]+$ ]]; then
            echo "[$timestamp] INVALID_HOST: $message" >> "$LOG_DIR/remote.log"
            return
        fi
        
        # Extract program name from EVENT messages for better file organization
        local log_program="$program"
        if [[ $tag == "EVENT" && $full_message =~ EVENT=\[[^\]]+\]\ +[A-Z_]+\ +.*PROC=([a-zA-Z0-9_.-]+) ]]; then
            log_program="${BASH_REMATCH[1]}"
        fi
        
        # Get session directory for this hostname and session ID
        local session_dir=$(get_session_dir "$hostname" "$session_id")
        
        # Write to session-specific log file
        echo "[$timestamp] $hostname $log_program: $full_message" >> "$session_dir/$log_program.log"
        
        # Also log to systemd journal with session info
        local session_name=$(basename "$session_dir")
        echo "$hostname[$session_name] $log_program: $full_message" | systemd-cat -t "remote-$log_program" -p info
    else
        # Fallback - log to general remote log with better filtering
        if [[ ${#message} -gt 5 ]]; then
            echo "[$timestamp] UNPARSED: $message" >> "$LOG_DIR/remote.log"
            echo "UNPARSED: $message" | systemd-cat -t "remote-unknown" -p info
        fi
    fi
}

# Listen on UDP port 514
echo "Starting session-based syslog UDP receiver on port 514..."

# Clean up old sessions every hour
(while true; do sleep 3600; cleanup_old_sessions; done) &

# Use a more robust UDP listener that handles complete packets
while true; do
    # Use socat instead of nc for better UDP packet handling
    if command -v socat >/dev/null 2>&1; then
        socat -u UDP-RECV:514 - | while IFS= read -r line; do
            parse_syslog "$line"
        done
    else
        # Fallback to nc with line buffering
        nc -lukp 514 | while IFS= read -r line; do
            # Only process non-empty lines
            if [[ -n "$line" ]]; then
                parse_syslog "$line"
            fi
        done
    fi
    
    # If we reach here, the listener died - restart after delay
    echo "Syslog receiver died, restarting in 5 seconds..." >&2
    sleep 5
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

# Create log rotation configuration (session-based logs are managed by syslog receiver)
echo "Setting up log rotation..."
cat > /etc/logrotate.d/remote-monitor << 'EOF'
# Remote Monitor Log Rotation Configuration
# Session-based logs are managed by the syslog receiver itself
# Only rotate the main remote.log file

/var/log/remote_monitor/remote.log {
    weekly
    missingok
    rotate 12
    compress
    delaycompress
    copytruncate
    create 644 root root
}

# NOTE: Session-based logs in /var/log/remote_monitor/hosts/*/ are managed
# by the syslog receiver script and should not be rotated by logrotate
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

# Create session-based log viewer script
echo "Creating session-based log viewer script..."
cat > /usr/local/bin/monitor-logs << 'EOF'
#!/bin/bash
#
# monitor-logs - View session-based monitor logs by hostname
#

LOG_DIR="/var/log/remote_monitor"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <hostname> [session|lines]"
    echo "       $0 list                    - show available hosts"
    echo "       $0 list <hostname>         - show sessions for hostname"
    echo "       $0 all                     - show all recent logs"
    echo "       $0 journal                 - show systemd journal remote logs"
    echo "       $0 <hostname> current      - show logs from current session"
    echo "       $0 <hostname> <session_name> - show logs from specific session"
    echo
    echo "Available hosts:"
    ls -1 $LOG_DIR/hosts/ 2>/dev/null
    exit 1
fi

case "$1" in
    "list")
        if [ -n "$2" ]; then
            # List sessions for specific hostname
            HOSTNAME="$2"
            if [ -d "$LOG_DIR/hosts/$HOSTNAME" ]; then
                echo "Sessions for $HOSTNAME:"
                # List all directories (both session_* and custom session names), excluding files
                for session_path in $LOG_DIR/hosts/$HOSTNAME/*/; do
                    if [ -d "$session_path" ]; then
                        session=$(basename "$session_path")
                        log_count=$(find "$session_path" -name "*.log" -type f 2>/dev/null | wc -l)
                        size=$(du -sh "$session_path" 2>/dev/null | cut -f1)
                        newest=$(find "$session_path" -name "*.log" -type f -printf "%T@ %p\n" 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
                        newest_time=$(stat -c "%y" "$session_path" 2>/dev/null | cut -d'.' -f1)
                        echo "  $session ($log_count files, $size, modified: $newest_time)"
                    fi
                done | sort -k4 -r  # Sort by modification time (newest first)
            else
                echo "No sessions found for hostname: $HOSTNAME"
            fi
        else
            # List all hosts
            echo "Available hosts:"
            for host_dir in $LOG_DIR/hosts/*/; do
                if [ -d "$host_dir" ]; then
                    hostname=$(basename "$host_dir")
                    # Count all directories, not just session_*
                    session_count=$(find "$host_dir" -maxdepth 1 -type d ! -path "$host_dir" 2>/dev/null | wc -l)
                    echo "  $hostname ($session_count sessions)"
                fi
            done
        fi
        ;;
    "all")
        echo "Recent logs from all hosts (current sessions):"
        for host_dir in $LOG_DIR/hosts/*/; do
            if [ -d "$host_dir" ]; then
                hostname=$(basename "$host_dir")
                # Find the most recently modified session directory (any name)
                current_session=$(find "$host_dir" -maxdepth 1 -type d ! -path "$host_dir" -printf "%T@ %f\n" 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2)
                if [ -n "$current_session" ]; then
                    echo "=== $hostname ($current_session) ==="
                    find "$host_dir/$current_session" -name "*.log" -type f -exec tail -5 {} + 2>/dev/null | head -20
                fi
            fi
        done
        ;;
    "journal")
        LINES="${2:-50}"
        echo "Recent systemd journal remote logs:"
        journalctl -t remote-monitor --no-pager -n $LINES
        ;;
    *)
        HOSTNAME="$1"
        SESSION_OR_LINES="${2:-current}"
        
        if [ ! -d "$LOG_DIR/hosts/$HOSTNAME" ]; then
            echo "No logs found for hostname: $HOSTNAME"
            echo "Available hosts:"
            ls -1 $LOG_DIR/hosts/ 2>/dev/null
            exit 1
        fi
        
        if [ "$SESSION_OR_LINES" = "current" ]; then
            # Show current (most recently modified) session
            current_session=$(find "$LOG_DIR/hosts/$HOSTNAME" -maxdepth 1 -type d ! -path "$LOG_DIR/hosts/$HOSTNAME" -printf "%T@ %f\n" 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2)
            if [ -n "$current_session" ]; then
                echo "Current session logs from $HOSTNAME ($current_session):"
                find "$LOG_DIR/hosts/$HOSTNAME/$current_session" -name "*.log" -type f -exec echo "=== {} ===" \; -exec tail -50 {} \; 2>/dev/null
            else
                echo "No sessions found for $HOSTNAME"
            fi
        elif [ -d "$LOG_DIR/hosts/$HOSTNAME/$SESSION_OR_LINES" ]; then
            # Show specific session (any session name)
            SESSION="$SESSION_OR_LINES"
            echo "Session logs from $HOSTNAME ($SESSION):"
            find "$LOG_DIR/hosts/$HOSTNAME/$SESSION" -name "*.log" -type f -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null
        elif [[ "$SESSION_OR_LINES" =~ ^[0-9]+$ ]]; then
            # Show recent lines from current session
            LINES="$SESSION_OR_LINES"
            current_session=$(find "$LOG_DIR/hosts/$HOSTNAME" -maxdepth 1 -type d ! -path "$LOG_DIR/hosts/$HOSTNAME" -printf "%T@ %f\n" 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2)
            if [ -n "$current_session" ]; then
                echo "Recent $LINES lines from $HOSTNAME ($current_session):"
                find "$LOG_DIR/hosts/$HOSTNAME/$current_session" -name "*.log" -type f -exec echo "=== {} ===" \; -exec tail -$LINES {} \; 2>/dev/null
            else
                echo "No sessions found for $HOSTNAME"
            fi
        else
            echo "Session '$SESSION_OR_LINES' not found for $HOSTNAME"
            echo "Available sessions:"
            find "$LOG_DIR/hosts/$HOSTNAME" -maxdepth 1 -type d ! -path "$LOG_DIR/hosts/$HOSTNAME" -printf "%f\n" 2>/dev/null | sort
            echo "\nOr use 'current' for most recent session, or a number for line count"
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
echo "Raspberry Pi is now configured as a session-based remote logging server using systemd"
echo "Log files will be organized in: $LOG_DIR/hosts/<hostname>/session_<timestamp>/"
echo "Each remote logging session creates a new timestamped directory"
echo "Systemd journal logs are also available via journalctl"
echo
echo "Useful commands:"
echo "  monitor-log-viewer             - Monitor live log activity"
echo "  monitor-logs <host> current    - View logs from current session"
echo "  monitor-logs list              - List available hosts"
echo "  monitor-logs list <host>       - List sessions for specific host"
echo "  monitor-logs <host> <session>  - View logs from specific session"
echo "  monitor-logs all               - View recent logs from all hosts"
echo "  monitor-logs journal           - View systemd journal remote logs"
echo "  journalctl -t remote-monitor -f  - Follow systemd journal logs"
echo
echo "Session management:"
echo "  Sessions are created automatically when new logs arrive"
echo "  Old sessions are cleaned up automatically (keeps last 10 per host)"
echo "  Sessions timeout after 10 minutes of inactivity"
echo
echo "Test the setup from a client with:"
echo "  logger -n <pi-ip> -P 514 -t monitor 'Test message from client'"
echo
echo "Service management:"
echo "  systemctl status syslog-receiver   - Check service status"
echo "  systemctl restart syslog-receiver  - Restart service"
echo "  journalctl -u syslog-receiver -f   - Follow service logs"
