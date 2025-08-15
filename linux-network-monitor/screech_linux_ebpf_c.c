//
// screech_linux_ebpf_c.c - Pure C implementation for ARM cross-compilation
// Linux eBPF network monitoring with rsyslog integration
//

// Feature test macros must be defined before any includes
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <pthread.h>
#include <regex.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>

// eBPF and libbpf includes
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Connection event structure (must match kernel-side)
struct connection_event {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint32_t pid;
    uint32_t uid;
    uint32_t gid;
    char comm[16];
    char filename[256];
    uint64_t timestamp;
    uint8_t event_type;
};

// Network tap parsed event structure
struct network_tap_event {
    char direction[16];     // "IN" or "OUT"
    char protocol[16];      // "TCP", "UDP", "ICMP", etc.
    char classification[32]; // "HTTP", "HTTPS", "SSH", "DNS", etc.
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    char interface[16];     // "eth0", "wlan0", etc.
    char mac_addr[18];      // MAC address
    uint32_t length;
    uint8_t ttl;
    uint8_t tos;
    uint64_t timestamp;
    char raw_log[1024];     // Original log line
};

// Operating modes
enum monitor_mode {
    MODE_EBPF_ONLY,
    MODE_NETWORK_TAP,
    MODE_COMBINED
};

// Global variables
static volatile int should_stop = 0;
static struct bpf_object *obj = NULL;
static struct ring_buffer *rb = NULL;
static enum monitor_mode current_mode = MODE_EBPF_ONLY;
static char tap_interface[16] = "any";
static pthread_t tap_thread;
static int tap_thread_running = 0;
static uint32_t interface_ip = 0; // IP address of the monitored interface
static int interface_index = 0; // Interface index for filtering

// Signal handler
void signal_handler(int signum) {
    printf("\nReceived signal %d, shutting down...\n", signum);
    should_stop = 1;
}

// Helper functions
const char* ip_to_string(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

const char* protocol_to_string(uint8_t protocol) {
    switch (protocol) {
        case 6: return "TCP";    // IPPROTO_TCP
        case 17: return "UDP";   // IPPROTO_UDP
        default: return "OTHER";
    }
}

const char* event_type_to_string(uint8_t event_type) {
    switch (event_type) {
        case 0: return "SOCKET_CREATE";
        case 1: return "CONNECT";
        case 2: return "SENDTO";
        default: return "UNKNOWN";
    }
}

// Check if interface exists (regardless of IP address)
int interface_exists(const char *interface_name) {
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;
    
    if (strcmp(interface_name, "any") == 0) {
        return 1;
    }
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 0;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, interface_name) == 0) {
            found = 1;
            break;
        }
    }
    
    freeifaddrs(ifaddr);
    return found;
}

// Get IP address of a specific interface
int get_interface_ip(const char *interface_name, uint32_t *ip_addr) {
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;
    
    *ip_addr = 0;
    
    if (strcmp(interface_name, "any") == 0) {
        return 1; // Don't filter for "any"
    }
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 0;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        if (strcmp(ifa->ifa_name, interface_name) == 0 && 
            ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)ifa->ifa_addr;
            *ip_addr = addr_in->sin_addr.s_addr;
            found = 1;
            break;
        }
    }
    
    freeifaddrs(ifaddr);
    return found;
}

// Check if an event should be filtered based on interface
int should_filter_event(const struct connection_event *event) {
    // If interface_ip is 0, no filtering ("any" interface)
    if (interface_ip == 0) {
        return 0;
    }
    
    // Filter based on source IP matching the interface IP
    // This covers outbound connections from the specified interface
    if (event->src_ip == interface_ip) {
        return 0; // Don't filter
    }
    
    // Also allow connections where the destination matches interface IP
    // This covers inbound connections to the interface
    if (event->dst_ip == interface_ip) {
        return 0; // Don't filter
    }
    
    // Filter out this event
    return 1;
}

// Log connection info to rsyslog with process separation
void log_connection_info(const struct connection_event *event) {
  printf("log connection info\n");
    char syslog_ident[64];
    char log_msg[512];
    
    // Determine process name for log separation
    const char *process_name = (strlen(event->comm) > 0) ? event->comm : "unknown";
    
    // Create syslog identifier - sanitize process name
    snprintf(syslog_ident, sizeof(syslog_ident), "screech-%.32s", process_name);
    
    // Replace invalid characters with underscores
    for (char *p = syslog_ident; *p; p++) {
        if (!(((*p >= 'a') && (*p <= 'z')) || 
              ((*p >= 'A') && (*p <= 'Z')) || 
              ((*p >= '0') && (*p <= '9')) || 
              (*p == '-') || (*p == '_'))) {
            *p = '_';
        }
    }
    
    // Prepare structured log message
    snprintf(log_msg, sizeof(log_msg),
             "EVENT=%s PID=%u UID=%u GID=%u PROC=%s PROTO=%s",
             event_type_to_string(event->event_type),
             event->pid, event->uid, event->gid,
             process_name, protocol_to_string(event->protocol));
    
    printf("log_msg: %s\n", log_msg);
    // Add connection details if available
    if (event->src_ip != 0 || event->dst_ip != 0 || event->src_port != 0 || event->dst_port != 0) {
        char conn_details[256];
        snprintf(conn_details, sizeof(conn_details),
                 " SRC=%s:%u DST=%s:%u",
                 ip_to_string(event->src_ip), event->src_port,
                 ip_to_string(event->dst_ip), event->dst_port);
        strncat(log_msg, conn_details, sizeof(log_msg) - strlen(log_msg) - 1);
    }
    
    // Add executable path if available
    if (strlen(event->filename) > 0) {
        char exec_info[300];
        snprintf(exec_info, sizeof(exec_info), " EXEC=%.256s", event->filename);
        strncat(log_msg, exec_info, sizeof(log_msg) - strlen(log_msg) - 1);
    }
    
    // Determine log priority based on event type
    int priority;
    switch (event->event_type) {
        case 1: // CONNECT
        case 2: // SENDTO
            priority = LOG_INFO;
            break;
        case 0: // SOCKET_CREATE
        default:
            priority = LOG_DEBUG;
            break;
    }
    
    // Send to syslog with process-specific identifier
    openlog(syslog_ident, LOG_PID | LOG_NDELAY, LOG_LOCAL0);
    syslog(priority, "%s", log_msg);
    closelog();
    
    // Also output to console for debugging (only connections)
    if (event->event_type == 1 || event->event_type == 2) {
        printf("[%s] %s\n", process_name, log_msg);
    }
}

// Ring buffer callback
static int handle_event(void *ctx __attribute__((unused)), void *data, size_t data_sz) {
  printf("incoming event\n");
    if (data_sz < sizeof(struct connection_event)) {
        fprintf(stderr, "Invalid event size: %zu\n", data_sz);
        return 0;
    }
    
    const struct connection_event *event = (const struct connection_event *)data;
    
    // Apply interface filtering for eBPF events
   // if (should_filter_event(event)) {
   //     return 0; // Skip this event
   // }
    
    log_connection_info(event);
    
    return 0;
}

// Check root privileges
int check_root(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This program requires root privileges to load eBPF programs.\n");
        fprintf(stderr, "Please run with sudo.\n");
        return 0;
    }
    return 1;
}

// Check BPF support
int check_bpf_support(void) {
    int map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, sizeof(int), sizeof(int), 1, NULL);
    if (map_fd < 0) {
        fprintf(stderr, "Error: eBPF is not supported on this system or kernel version is too old.\n");
        fprintf(stderr, "Minimum kernel version required: 4.1+\n");
        return 0;
    }
    close(map_fd);
    return 1;
}

// Verbose libbpf logging callback
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level <= LIBBPF_WARN) {
        return vfprintf(stderr, format, args);
    }
    return 0;
}

// Load and attach eBPF programs
int load_and_attach_programs(void) {
    struct bpf_program *tcp_connect_prog, *udp_sendmsg_prog, *socket_create_prog;
    struct bpf_map *connection_events_map;
    int ring_buffer_fd;
    int err;
    
    // Set up libbpf logging for debugging
    libbpf_set_print(libbpf_print_fn);
    
    // Load BPF object from file
    obj = bpf_object__open("./screech_ebpf.o");
    err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", strerror(-err));
        return -1;
    }
    
    // Load BPF programs into kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return -1;
    }
    
    // Find programs
    tcp_connect_prog = bpf_object__find_program_by_name(obj, "trace_tcp_connect");
    udp_sendmsg_prog = bpf_object__find_program_by_name(obj, "trace_udp_sendmsg");
    socket_create_prog = bpf_object__find_program_by_name(obj, "trace_socket_create");
    
    if (!tcp_connect_prog || !udp_sendmsg_prog || !socket_create_prog) {
        fprintf(stderr, "Failed to find BPF programs\n");
        bpf_object__close(obj);
        return -1;
    }
    
    // Find maps
    connection_events_map = bpf_object__find_map_by_name(obj, "connection_events");
    if (!connection_events_map) {
        fprintf(stderr, "Failed to find BPF maps\n");
        bpf_object__close(obj);
        return -1;
    }
    
    // Attach kprobes
    struct bpf_link *tcp_link = bpf_program__attach_kprobe(tcp_connect_prog, false, "tcp_v4_connect");
    struct bpf_link *udp_link = bpf_program__attach_kprobe(udp_sendmsg_prog, false, "udp_sendmsg");
    struct bpf_link *socket_link = bpf_program__attach_kprobe(socket_create_prog, false, "__sys_socket");
    
    if (libbpf_get_error(tcp_link) || libbpf_get_error(udp_link) || libbpf_get_error(socket_link)) {
        fprintf(stderr, "Failed to attach kprobes\n");
        bpf_object__close(obj);
        return -1;
    }
    
    // Set up ring buffer
    ring_buffer_fd = bpf_map__fd(connection_events_map);
    rb = ring_buffer__new(ring_buffer_fd, handle_event, NULL, NULL);
    printf("did ring buffer\n");
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        bpf_object__close(obj);
        return -1;
    }
    
    return 0;
}

// Parse network tap log line using regex
int parse_tap_log(const char *log_line, struct network_tap_event *event) {
    regex_t regex;
    regmatch_t matches[15];
    int ret;
    
    // Enhanced regex to capture nftables log format with detailed info
    // Example: TAP-OUT-HTTPS: IN=eth0 OUT= MAC=fa:b4:d9:42:2c:e9:dc:a6:32:c4:1b:88:08:00 SRC=192.168.1.34 DST=54.230.225.72 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=54321 DPT=443
    const char *pattern = "TAP-([A-Z]+)-([A-Z0-9]+):.*IN=([a-z0-9]+).*MAC=([a-f0-9:]+).*SRC=([0-9.]+).*DST=([0-9.]+).*LEN=([0-9]+).*TTL=([0-9]+).*TOS=0x([a-f0-9]+).*PROTO=([A-Z]+).*SPT=([0-9]+).*DPT=([0-9]+)";
    
    ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret) {
        return -1;
    }
    
    ret = regexec(&regex, log_line, 15, matches, 0);
    regfree(&regex);
    
    if (ret == REG_NOMATCH) {
        return -1;
    }
    
    // Extract matches
    char temp[256];
    
    // Direction (IN/OUT)
    int len = matches[1].rm_eo - matches[1].rm_so;
    strncpy(event->direction, log_line + matches[1].rm_so, len);
    event->direction[len] = '\0';
    
    // Classification (HTTP, HTTPS, SSH, etc.)
    len = matches[2].rm_eo - matches[2].rm_so;
    strncpy(event->classification, log_line + matches[2].rm_so, len);
    event->classification[len] = '\0';
    
    // Interface
    len = matches[3].rm_eo - matches[3].rm_so;
    strncpy(event->interface, log_line + matches[3].rm_so, len);
    event->interface[len] = '\0';
    
    // MAC address  
    len = matches[4].rm_eo - matches[4].rm_so;
    if (len > 17) len = 17;
    strncpy(event->mac_addr, log_line + matches[4].rm_so, len);
    event->mac_addr[len] = '\0';
    
    // Source IP
    len = matches[5].rm_eo - matches[5].rm_so;
    strncpy(temp, log_line + matches[5].rm_so, len);
    temp[len] = '\0';
    event->src_ip = inet_addr(temp);
    
    // Destination IP
    len = matches[6].rm_eo - matches[6].rm_so;
    strncpy(temp, log_line + matches[6].rm_so, len);
    temp[len] = '\0';
    event->dst_ip = inet_addr(temp);
    
    // Length
    len = matches[7].rm_eo - matches[7].rm_so;
    strncpy(temp, log_line + matches[7].rm_so, len);
    temp[len] = '\0';
    event->length = atoi(temp);
    
    // TTL
    len = matches[8].rm_eo - matches[8].rm_so;
    strncpy(temp, log_line + matches[8].rm_so, len);
    temp[len] = '\0';
    event->ttl = atoi(temp);
    
    // TOS
    len = matches[9].rm_eo - matches[9].rm_so;
    strncpy(temp, log_line + matches[9].rm_so, len);
    temp[len] = '\0';
    event->tos = strtol(temp, NULL, 16);
    
    // Protocol
    len = matches[10].rm_eo - matches[10].rm_so;
    strncpy(event->protocol, log_line + matches[10].rm_so, len);
    event->protocol[len] = '\0';
    
    // Source port
    len = matches[11].rm_eo - matches[11].rm_so;
    strncpy(temp, log_line + matches[11].rm_so, len);
    temp[len] = '\0';
    event->src_port = atoi(temp);
    
    // Destination port
    len = matches[12].rm_eo - matches[12].rm_so;
    strncpy(temp, log_line + matches[12].rm_so, len);
    temp[len] = '\0';
    event->dst_port = atoi(temp);
    
    // Store raw log
    strncpy(event->raw_log, log_line, sizeof(event->raw_log) - 1);
    event->raw_log[sizeof(event->raw_log) - 1] = '\0';
    
    // Set timestamp
    event->timestamp = time(NULL);
    
    return 0;
}

// Log network tap event with process inference
void log_tap_event(const struct network_tap_event *event) {
    char log_msg[1024];
    char process_info[256] = "UNKNOWN";
    
    // Try to infer process from port patterns
    if (strcmp(event->classification, "HTTP") == 0 || strcmp(event->classification, "HTTPS") == 0) {
        strcpy(process_info, "BROWSER/HTTP_CLIENT");
    } else if (strcmp(event->classification, "SSH") == 0) {
        strcpy(process_info, "SSH_CLIENT");
    } else if (strcmp(event->classification, "DNS") == 0) {
        strcpy(process_info, "DNS_RESOLVER");
    } else if (strcmp(event->classification, "EMAIL") == 0) {
        strcpy(process_info, "EMAIL_CLIENT");
    } else if (strcmp(event->classification, "DB") == 0) {
        strcpy(process_info, "DATABASE_CLIENT");
    } else {
        // Try to classify by port ranges
        if (strcmp(event->direction, "OUT") == 0) {
            if (event->src_port < 1024) {
                strcpy(process_info, "SYSTEM_SERVICE");
            } else if (event->src_port >= 32768) {
                strcpy(process_info, "USER_APPLICATION");
            } else {
                strcpy(process_info, "REGISTERED_SERVICE");
            }
        }
    }
    
    // Create structured log message
    snprintf(log_msg, sizeof(log_msg),
             "TAP_EVENT DIR=%s CLASS=%s PROTO=%s INFERRED_PROC=%s "
             "SRC=%s:%u DST=%s:%u IFACE=%s MAC=%s LEN=%u TTL=%u TOS=0x%02x",
             event->direction, event->classification, event->protocol, process_info,
             ip_to_string(event->src_ip), event->src_port,
             ip_to_string(event->dst_ip), event->dst_port,
             event->interface, event->mac_addr, event->length, event->ttl, event->tos);
    
    // Send to syslog with tap-specific identifier
    openlog("screech-tap", LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "%s", log_msg);
    closelog();
    
    // Output to console with color coding
    const char *color = "";
    const char *reset = "\033[0m";
    
    if (strcmp(event->classification, "HTTPS") == 0) {
        color = "\033[32m"; // Green for secure
    } else if (strcmp(event->classification, "HTTP") == 0) {
        color = "\033[33m"; // Yellow for HTTP
    } else if (strcmp(event->classification, "SSH") == 0) {
        color = "\033[36m"; // Cyan for SSH
    } else if (strcmp(event->classification, "DNS") == 0) {
        color = "\033[35m"; // Magenta for DNS
    } else {
        color = "\033[37m"; // White for other
    }
    
    printf("%s[TAP-%s-%s]%s %s:%u -> %s:%u (%s) [%s]\n",
           color, event->direction, event->classification, reset,
           ip_to_string(event->src_ip), event->src_port,
           ip_to_string(event->dst_ip), event->dst_port,
           event->protocol, process_info);
}

// Network tap monitoring thread
void* network_tap_monitor(void* arg __attribute__((unused))) {
    FILE *journal_fd;
    char line[2048];
    struct network_tap_event event;
    
    tap_thread_running = 1;
    
    printf("Network tap monitor thread started\n");
    
    // Monitor kernel logs for TAP events using journalctl
    journal_fd = popen("journalctl -k -f --no-pager | grep 'TAP-'", "r");
    if (!journal_fd) {
        fprintf(stderr, "Failed to start journalctl monitoring\n");
        tap_thread_running = 0;
        return NULL;
    }
    
    while (!should_stop && tap_thread_running) {
        if (fgets(line, sizeof(line), journal_fd) == NULL) {
            if (should_stop) break;
            usleep(100000); // 100ms
            continue;
        }
        
        // Parse and log the tap event
        if (parse_tap_log(line, &event) == 0) {
            log_tap_event(&event);
        }
    }
    
    pclose(journal_fd);
    tap_thread_running = 0;
    printf("Network tap monitor thread stopped\n");
    return NULL;
}

// Print usage information
void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nLinux Network Monitor - eBPF and Network Tap Support\n");
    printf("\nOPTIONS:\n");
    printf("  -m, --mode MODE        Monitor mode: ebpf, tap, combined (default: ebpf)\n");
    printf("  -i, --interface IFACE  Network interface to monitor (default: any)\n");
    printf("  -h, --help            Show this help message\n");
    printf("\nMODES:\n");
    printf("  ebpf      - eBPF kernel-level process monitoring (requires eBPF support)\n");
    printf("  tap       - Network tap monitoring via nftables logs (requires network tap)\n");
    printf("  combined  - Both eBPF and network tap monitoring\n");
    printf("\nEXAMPLES:\n");
    printf("  %s                          # eBPF monitoring only\n", program_name);
    printf("  %s --mode tap               # Network tap monitoring only\n", program_name);
    printf("  %s --mode combined -i eth0  # Combined monitoring on eth0\n", program_name);
    printf("\n");
}

// Main function
int main(int argc, char *argv[]) {
    int opt;
    int ebpf_initialized = 0;
    
    static struct option long_options[] = {
        {"mode", required_argument, 0, 'm'},
        {"interface", required_argument, 0, 'i'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    // Parse command line arguments
    while ((opt = getopt_long(argc, argv, "m:i:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                if (strcmp(optarg, "ebpf") == 0) {
                    current_mode = MODE_EBPF_ONLY;
                } else if (strcmp(optarg, "tap") == 0) {
                    current_mode = MODE_NETWORK_TAP;
                } else if (strcmp(optarg, "combined") == 0) {
                    current_mode = MODE_COMBINED;
                } else {
                    fprintf(stderr, "Invalid mode: %s\n", optarg);
                    print_usage(argv[0]);
                    return 1;
                }
                break;
            case 'i':
                strncpy(tap_interface, optarg, sizeof(tap_interface) - 1);
                tap_interface[sizeof(tap_interface) - 1] = '\0';
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Print startup banner
    printf("Linux Network Monitor - Enhanced Edition\n");
    switch (current_mode) {
        case MODE_EBPF_ONLY:
            printf("Mode: eBPF Process Monitoring\n");
            break;
        case MODE_NETWORK_TAP:
            printf("Mode: Network Tap Monitoring\n");
            break;
        case MODE_COMBINED:
            printf("Mode: Combined eBPF + Network Tap\n");
            break;
    }
    printf("Interface: %s\n", tap_interface);
    printf("Logs to rsyslog with process-separated identifiers\n");
    printf("Press Ctrl+C to stop\n");
    printf("========================================\n");
    
    // Install signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Check prerequisites
    if (!check_root()) {
        return 1;
    }
    
    // Resolve interface IP address for filtering (if specified)
    if (strcmp(tap_interface, "any") != 0) {
        // First check if the interface exists
        if (!interface_exists(tap_interface)) {
            fprintf(stderr, "Warning: Interface '%s' not found. Using 'any' instead.\n", tap_interface);
            strcpy(tap_interface, "any");
            interface_ip = 0;
        } else {
            // Interface exists, try to get its IP address
            if (get_interface_ip(tap_interface, &interface_ip)) {
                if (interface_ip != 0) {
                    printf("Interface %s resolved to IP: %s\n", tap_interface, ip_to_string(interface_ip));
                }
            } else {
                // Interface exists but has no IP address (e.g., network tap)
                printf("Interface %s found but has no IPv4 address (network tap mode)\n", tap_interface);
                if (current_mode == MODE_NETWORK_TAP || current_mode == MODE_COMBINED) {
                    printf("This is acceptable for network tap monitoring\n");
                    interface_ip = 0; // No IP-based filtering for eBPF
                } else {
                    fprintf(stderr, "Warning: Interface '%s' has no IPv4 address. eBPF filtering disabled.\n", tap_interface);
                    interface_ip = 0;
                }
            }
        }
    }
    
    // Initialize eBPF if needed
    if (current_mode == MODE_EBPF_ONLY || current_mode == MODE_COMBINED) {
        if (!check_bpf_support()) {
            if (current_mode == MODE_EBPF_ONLY) {
                return 1;
            } else {
                printf("Warning: eBPF not supported, falling back to network tap only\n");
                current_mode = MODE_NETWORK_TAP;
            }
        } else {
            printf("Initializing eBPF monitor...\n");
            openlog("screech-main", LOG_PID | LOG_NDELAY, LOG_LOCAL0);
            syslog(LOG_INFO, "Initializing eBPF monitor...");
            closelog();
            
            if (load_and_attach_programs() < 0) {
                if (current_mode == MODE_EBPF_ONLY) {
                    fprintf(stderr, "Failed to start eBPF monitor\n");
                    return 1;
                } else {
                    printf("Warning: Failed to initialize eBPF, falling back to network tap only\n");
                    current_mode = MODE_NETWORK_TAP;
                }
            } else {
                ebpf_initialized = 1;
                printf("eBPF monitor initialized successfully\n");
            }
        }
    }
    
    // Initialize network tap monitoring if needed
    if (current_mode == MODE_NETWORK_TAP || current_mode == MODE_COMBINED) {
        printf("Starting network tap monitor thread...\n");
        if (pthread_create(&tap_thread, NULL, network_tap_monitor, NULL) != 0) {
            fprintf(stderr, "Failed to create network tap monitoring thread\n");
            if (current_mode == MODE_NETWORK_TAP) {
                return 1;
            }
            // Continue with eBPF only if combined mode
        } else {
            printf("Network tap monitor thread started\n");
        }
    }
    
    // Log startup
    openlog("screech-main", LOG_PID | LOG_NDELAY, LOG_LOCAL0);
    syslog(LOG_INFO, "Linux Network Monitor started - PID: %d, Mode: %d", getpid(), current_mode);
    if (ebpf_initialized) {
        syslog(LOG_INFO, "eBPF monitoring active");
    }
    if (tap_thread_running) {
        syslog(LOG_INFO, "Network tap monitoring active");
    }
    closelog();
    
    printf("\nMonitor running... (logs are sent to rsyslog)\n");
    
    // Main event loop
    if (ebpf_initialized) {
        printf("eBPF event loop active\n");
        while (!should_stop) {
            int ret = ring_buffer__poll(rb, 100); // 100ms timeout
            if (ret < 0) {
                if (ret != -EINTR) {
                    fprintf(stderr, "Error polling ring buffer: %d\n", ret);
                    break;
                }
            }
        }
    } else {
        // Just wait for network tap events
        printf("Waiting for network tap events...\n");
        while (!should_stop) {
            usleep(100000); // 100ms
        }
    }
    
    printf("\nShutting down...\n");
    
    // Stop network tap thread
    if (tap_thread_running) {
        printf("Stopping network tap monitor thread...\n");
        tap_thread_running = 0;
        pthread_join(tap_thread, NULL);
    }
    
    // Cleanup eBPF
    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }
    
    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }
    
    // Log shutdown
    openlog("screech-main", LOG_PID | LOG_NDELAY, LOG_LOCAL0);
    syslog(LOG_INFO, "Linux Network Monitor stopped - PID: %d", getpid());
    closelog();
    
    printf("Monitor stopped.\n");
    return 0;
}
