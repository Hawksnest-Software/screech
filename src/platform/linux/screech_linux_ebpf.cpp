#include <iostream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <unordered_set>
#include <fstream>
#include <chrono>
#include <sstream>
#include <csignal>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

// eBPF and libbpf includes
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Include our header for class declaration
#include "screech_linux_ebpf.h"

// Include stealth logging system
#include "stealth_logging.h"

// Global flag to handle SIGINT (externally managed)
extern std::atomic<bool> shouldStop;

// LinuxEBPFMonitor method implementations

// Constructor
LinuxEBPFMonitor::LinuxEBPFMonitor() : obj(nullptr), rb(nullptr) {}

// Destructor  
LinuxEBPFMonitor::~LinuxEBPFMonitor() {
    stop();
}

// Private helper methods
std::string LinuxEBPFMonitor::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::string LinuxEBPFMonitor::ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

std::string LinuxEBPFMonitor::protocolToString(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        default: return "OTHER";
    }
}

std::string LinuxEBPFMonitor::eventTypeToString(uint8_t event_type) {
    switch (event_type) {
        case 0: return "SOCKET_CREATE";
        case 1: return "CONNECT";
        case 2: return "SENDTO";
        default: return "UNKNOWN";
    }
}

void LinuxEBPFMonitor::logConnectionInfo(const connection_event& event) {
    std::string timestamp = getCurrentTimestamp();
    std::string src_ip_str = ipToString(event.src_ip);
    std::string dst_ip_str = ipToString(event.dst_ip);
    std::string protocol_str = protocolToString(event.protocol);
    std::string event_type_str = eventTypeToString(event.event_type);
    
    // Create log filename based on process name
    std::string process_name(event.comm);
    std::string logFileName = "screech_" + process_name + ".log";
    if (process_name.empty()) {
        logFileName = "screech_unknown_process.log";
    }
    
    // Only log actual connections (not just socket creation)
    if (event.event_type == 1 || event.event_type == 2) { // CONNECT or SENDTO
        std::ofstream logFile(logFileName, std::ios::app);
        if (logFile.is_open()) {
            // Write greppable log entry
            logFile << "[" << timestamp << "] "
                   << "CONN|" << protocol_str << "|"
                   << src_ip_str << ":" << event.src_port << "->"
                   << dst_ip_str << ":" << event.dst_port << "|"
                   << "PID:" << event.pid << "|"
                   << "PROC:" << process_name << "|"
                   << "UID:" << event.uid << "|"
                   << "PATH:" << std::string(event.filename) << std::endl;
            logFile.close();
        }
        
        // Also log to console using stealth logging
        STEALTH_LOG_INFO("[%s] NEW CONNECTION: %s %s:%d -> %s:%d (PID: %d, Process: %s)",
                          timestamp.c_str(), protocol_str.c_str(), src_ip_str.c_str(), event.src_port,
                          dst_ip_str.c_str(), event.dst_port, event.pid, process_name.c_str());
    } else {
        // Log socket creation for debugging
        STEALTH_LOG_DEBUG("[%s] %s: %s by %s (PID: %d)", 
                           timestamp.c_str(), event_type_str.c_str(), 
                           protocol_str.c_str(), process_name.c_str(), event.pid);
    }
}

int LinuxEBPFMonitor::handleEvent(void *ctx, void *data, size_t data_sz) {
    LinuxEBPFMonitor *monitor = static_cast<LinuxEBPFMonitor*>(ctx);
    
    if (data_sz < sizeof(connection_event)) {
        std::cerr << "Invalid event size: " << data_sz << std::endl;
        return 0;
    }
    
    const connection_event *event = static_cast<const connection_event*>(data);
    monitor->logConnectionInfo(*event);
    
    return 0;
}

int LinuxEBPFMonitor::loadAndAttachPrograms() {
    // Set up libbpf logging
    libbpf_set_print([](enum libbpf_print_level level, const char *format, va_list args) -> int {
        if (level >= LIBBPF_WARN) {
            return vfprintf(stderr, format, args);
        }
        return 0;
    });

    // Load BPF object from file
    obj = bpf_object__open("screech_ebpf.o");
    if (libbpf_get_error(obj)) {
        std::cerr << "Failed to open BPF object file" << std::endl;
        return -1;
    }

    // Load BPF programs into kernel
    if (bpf_object__load(obj)) {
        std::cerr << "Failed to load BPF object" << std::endl;
        bpf_object__close(obj);
        return -1;
    }

    // Find programs
    tcp_connect_prog = bpf_object__find_program_by_name(obj, "trace_tcp_connect");
    udp_sendmsg_prog = bpf_object__find_program_by_name(obj, "trace_udp_sendmsg");
    socket_create_prog = bpf_object__find_program_by_name(obj, "trace_socket_create");
    
    if (!tcp_connect_prog || !udp_sendmsg_prog || !socket_create_prog) {
        std::cerr << "Failed to find BPF programs" << std::endl;
        bpf_object__close(obj);
        return -1;
    }

    // Find maps
    connection_events_map = bpf_object__find_map_by_name(obj, "connection_events");
    seen_connections_map = bpf_object__find_map_by_name(obj, "seen_connections");
    
    if (!connection_events_map || !seen_connections_map) {
        std::cerr << "Failed to find BPF maps" << std::endl;
        bpf_object__close(obj);
        return -1;
    }

    // Attach kprobes
    struct bpf_link *tcp_link = bpf_program__attach_kprobe(tcp_connect_prog, false, "tcp_v4_connect");
    struct bpf_link *udp_link = bpf_program__attach_kprobe(udp_sendmsg_prog, false, "udp_sendmsg");
    struct bpf_link *socket_link = bpf_program__attach_kprobe(socket_create_prog, false, "__sys_socket");
    
    if (libbpf_get_error(tcp_link) || libbpf_get_error(udp_link) || libbpf_get_error(socket_link)) {
        std::cerr << "Failed to attach kprobes" << std::endl;
        bpf_object__close(obj);
        return -1;
    }

    // Set up ring buffer
    ring_buffer_fd = bpf_map__fd(connection_events_map);
    rb = ring_buffer__new(ring_buffer_fd, handleEvent, this, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer" << std::endl;
        bpf_object__close(obj);
        return -1;
    }

    return 0;
}

// Public method implementations
bool LinuxEBPFMonitor::initialize() {
    STEALTH_LOG_INFO("Initializing eBPF monitor...");
    return true;
}

bool LinuxEBPFMonitor::start() {
    STEALTH_LOG_INFO("Loading eBPF program...");
    
    if (loadAndAttachPrograms() < 0) {
        return false;
    }

    isRunning = true;
    STEALTH_LOG_INFO("eBPF Linux Kernel Monitor started successfully");
    STEALTH_LOG_INFO("Monitoring network connections at kernel level...");
    return true;
}

void LinuxEBPFMonitor::eventLoop() {
    while (!shouldStop && isRunning) {
        // Poll ring buffer for events
        int ret = ring_buffer__poll(rb, 100); // 100ms timeout
        if (ret < 0) {
            if (ret != -EINTR) {
                std::cerr << "Error polling ring buffer: " << ret << std::endl;
                break;
            }
        }
    }
}

void LinuxEBPFMonitor::stop() {
    if (!isRunning) return;
    
    isRunning = false;
    
    if (rb) {
        ring_buffer__free(rb);
        rb = nullptr;
    }
    
    if (obj) {
        bpf_object__close(obj);
        obj = nullptr;
    }
    
    STEALTH_LOG_INFO("eBPF Linux Monitor stopped");
}

bool LinuxEBPFMonitor::isMonitoring() const {
    return isRunning;
}

bool checkRoot() {
    if (geteuid() != 0) {
        STEALTH_LOG_ERROR("This program requires root privileges to load eBPF programs.");
        STEALTH_LOG_ERROR("Please run with sudo.");
        return false;
    }
    return true;
}

bool checkBPFSupport() {
    // Try to create a simple BPF map to test support
    int map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, sizeof(int), sizeof(int), 1, NULL);
    if (map_fd < 0) {
        STEALTH_LOG_ERROR("eBPF is not supported on this system or kernel version is too old.");
        STEALTH_LOG_ERROR("Minimum kernel version required: 4.1+");
        return false;
    }
    close(map_fd);
    return true;
}
