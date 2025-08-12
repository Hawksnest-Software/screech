//
// screech_linux_ebpf_c.c - Pure C implementation for ARM cross-compilation
// Linux eBPF network monitoring with rsyslog integration
//

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

// Global variables
static volatile int should_stop = 0;
static struct bpf_object *obj = NULL;
static struct ring_buffer *rb = NULL;

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

// Log connection info to rsyslog with process separation
void log_connection_info(const struct connection_event *event) {
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
static int handle_event(void *ctx, void *data, size_t data_sz) {
    if (data_sz < sizeof(struct connection_event)) {
        fprintf(stderr, "Invalid event size: %zu\n", data_sz);
        return 0;
    }
    
    const struct connection_event *event = (const struct connection_event *)data;
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
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        bpf_object__close(obj);
        return -1;
    }
    
    return 0;
}

// Main function
int main(int argc, char *argv[]) {
    printf("Linux eBPF Network Monitor (Pure C)\n");
    printf("Logs to rsyslog using process-separated identifiers\n");
    printf("Press Ctrl+C to stop\n");
    printf("========================================\n");
    
    // Install signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Check prerequisites
    if (!check_root()) {
        return 1;
    }
    
    if (!check_bpf_support()) {
        return 1;
    }
    
    // Initialize and start monitoring
    openlog("screech-main", LOG_PID | LOG_NDELAY, LOG_LOCAL0);
    syslog(LOG_INFO, "Initializing eBPF monitor...");
    closelog();
    
    printf("Loading eBPF program...\n");
    
    if (load_and_attach_programs() < 0) {
        fprintf(stderr, "Failed to start eBPF monitor\n");
        return 1;
    }
    
    openlog("screech-main", LOG_PID | LOG_NDELAY, LOG_LOCAL0);
    syslog(LOG_INFO, "Linux eBPF Network Monitor started - PID: %d", getpid());
    syslog(LOG_INFO, "Monitoring network connections at kernel level...");
    closelog();
    
    printf("eBPF Linux Kernel Monitor started successfully\n");
    printf("Monitor running... (logs are sent to rsyslog)\n");
    
    // Main event loop
    while (!should_stop) {
        int ret = ring_buffer__poll(rb, 100); // 100ms timeout
        if (ret < 0) {
            if (ret != -EINTR) {
                fprintf(stderr, "Error polling ring buffer: %d\n", ret);
                break;
            }
        }
    }
    
    // Cleanup
    if (rb) {
        ring_buffer__free(rb);
    }
    
    if (obj) {
        bpf_object__close(obj);
    }
    
    openlog("screech-main", LOG_PID | LOG_NDELAY, LOG_LOCAL0);
    syslog(LOG_INFO, "Linux eBPF Network Monitor stopped - PID: %d", getpid());
    closelog();
    
    printf("Monitor stopped.\n");
    return 0;
}
