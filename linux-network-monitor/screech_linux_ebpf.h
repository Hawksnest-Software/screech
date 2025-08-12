//
// screech_linux_ebpf.h - eBPF Monitor Library Interface
// Linux eBPF-based network monitoring for screech
//

#ifndef SCREECH_LINUX_EBPF_H
#define SCREECH_LINUX_EBPF_H

#include <atomic>
#include <string>
#include <cstdint>
#include <unordered_set>

// Forward declarations for BPF structures
struct bpf_object;
struct bpf_program;
struct bpf_map;
struct ring_buffer;

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

class LinuxEBPFMonitor {
private:
    struct bpf_object *obj;
    struct bpf_program *tcp_connect_prog;
    struct bpf_program *udp_sendmsg_prog;  
    struct bpf_program *socket_create_prog;
    struct bpf_map *connection_events_map;
    struct bpf_map *seen_connections_map;
    int ring_buffer_fd;
    struct ring_buffer *rb;
    std::unordered_set<std::string> seenConnections;
    std::atomic<bool> isRunning{false};

    std::string getCurrentTimestamp();
    std::string ipToString(uint32_t ip);
    std::string protocolToString(uint8_t protocol);
    std::string eventTypeToString(uint8_t event_type);
    void logConnectionInfo(const connection_event& event);
    static int handleEvent(void *ctx, void *data, size_t data_sz);
    int loadAndAttachPrograms();

public:
    LinuxEBPFMonitor();
    ~LinuxEBPFMonitor();
    
    // Library interface methods
    bool initialize();
    bool start();
    void stop();
    void eventLoop();
    bool isMonitoring() const;
    
};

// Utility functions
bool checkRoot();
bool checkBPFSupport();

#endif // SCREECH_LINUX_EBPF_H
