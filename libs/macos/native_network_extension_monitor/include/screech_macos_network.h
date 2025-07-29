//
// screech_macos_network.h - Header for macOS Network Monitoring Library
// Provides types, functions, and structures for network monitoring
//

#ifndef SCREECH_MACOS_NETWORK_H
#define SCREECH_MACOS_NETWORK_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __APPLE__
#include <EndpointSecurity/EndpointSecurity.h>
#endif

#ifdef ENABLE_LIBPCAP
#include <pcap/pcap.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Network connection event types
typedef enum {
    MACOS_NET_EVENT_TCP_CONNECT = 1,
    MACOS_NET_EVENT_TCP_BIND,
    MACOS_NET_EVENT_UDP_CONNECT,
    MACOS_NET_EVENT_UDP_BIND,
    MACOS_NET_EVENT_UIPC_CONNECT,
    MACOS_NET_EVENT_UIPC_BIND,
    MACOS_NET_EVENT_XPC_CONNECT,
    MACOS_NET_EVENT_PACKET_IN,
    MACOS_NET_EVENT_PACKET_OUT,
    MACOS_NET_EVENT_DNS_QUERY,
    MACOS_NET_EVENT_DNS_RESPONSE
} macos_net_event_type_t;

// Network connection event structure
typedef struct {
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
    macos_net_event_type_t event_type;
    char service_name[128];
    uint32_t domain;
    uint32_t socket_type;
    size_t data_len;
    uint8_t data[1500];
} macos_connection_event_t;

// Process information structure
typedef struct {
    pid_t pid;
    char name[256];
    char path[1024];
    uid_t uid;
    gid_t gid;
    char code_signature[128];
    bool is_signed;
    char team_id[64];
} macos_process_info_t;

// Network interface information
typedef struct {
    char name[64];
    char description[256];
    uint32_t flags;
    bool is_up;
    bool is_loopback;
    uint8_t mac_addr[6];
    uint32_t mtu;
    uint32_t speed;
} macos_interface_info_t;

// DNS query information
typedef struct {
    char query_name[256];
    uint16_t query_type;
    uint16_t query_class;
    uint32_t response_code;
    uint32_t ttl;
    char response_data[512];
    bool is_response;
} macos_dns_info_t;

// Packet capture statistics
typedef struct {
    uint64_t packets_received;
    uint64_t packets_dropped;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_packets;
    uint64_t bytes_captured;
    double capture_duration;
} macos_capture_stats_t;

// Event callback function types
typedef void (*macos_network_event_callback_t)(const macos_connection_event_t* event, void* user_data);
typedef void (*macos_process_event_callback_t)(const macos_process_info_t* process, void* user_data);
typedef void (*macos_dns_event_callback_t)(const macos_dns_info_t* dns, void* user_data);
typedef void (*macos_packet_callback_t)(const uint8_t* packet, uint32_t length, uint64_t timestamp, void* user_data);

// Network monitor context
typedef struct macos_network_monitor macos_network_monitor_t;

// Core network monitoring functions
macos_network_monitor_t* macos_network_monitor_create(void);
void macos_network_monitor_destroy(macos_network_monitor_t* monitor);

// Configuration functions
bool macos_network_monitor_set_interface(macos_network_monitor_t* monitor, const char* interface_name);
bool macos_network_monitor_set_filter(macos_network_monitor_t* monitor, const char* bpf_filter);
bool macos_network_monitor_set_promiscuous(macos_network_monitor_t* monitor, bool promiscuous);
bool macos_network_monitor_set_buffer_size(macos_network_monitor_t* monitor, int buffer_size);
bool macos_network_monitor_set_timeout(macos_network_monitor_t* monitor, int timeout_ms);

// Callback registration
void macos_network_monitor_set_network_callback(macos_network_monitor_t* monitor, 
                                               macos_network_event_callback_t callback, 
                                               void* user_data);
void macos_network_monitor_set_process_callback(macos_network_monitor_t* monitor, 
                                              macos_process_event_callback_t callback, 
                                              void* user_data);
void macos_network_monitor_set_dns_callback(macos_network_monitor_t* monitor, 
                                           macos_dns_event_callback_t callback, 
                                           void* user_data);
void macos_network_monitor_set_packet_callback(macos_network_monitor_t* monitor, 
                                              macos_packet_callback_t callback, 
                                              void* user_data);

// Monitoring control
bool macos_network_monitor_start(macos_network_monitor_t* monitor);
void macos_network_monitor_stop(macos_network_monitor_t* monitor);
bool macos_network_monitor_is_running(const macos_network_monitor_t* monitor);

// EndpointSecurity integration
bool macos_network_monitor_enable_endpoint_security(macos_network_monitor_t* monitor);
void macos_network_monitor_disable_endpoint_security(macos_network_monitor_t* monitor);

// Interface discovery
int macos_network_get_interfaces(macos_interface_info_t* interfaces, int max_interfaces);
char** macos_network_get_interface_names(int* count);
void macos_network_free_interface_names(char** names, int count);

// Statistics and monitoring
void macos_network_monitor_get_stats(const macos_network_monitor_t* monitor, macos_capture_stats_t* stats);
void macos_network_monitor_reset_stats(macos_network_monitor_t* monitor);

// Utility functions
const char* macos_network_event_type_to_string(macos_net_event_type_t type);
const char* macos_network_protocol_to_string(uint8_t protocol);
char* macos_network_ip_to_string(uint32_t ip);
bool macos_network_parse_dns_packet(const uint8_t* packet, uint32_t length, macos_dns_info_t* dns_info);

// Process information helpers
bool macos_network_get_process_info(pid_t pid, macos_process_info_t* info);
bool macos_network_get_process_code_signature(pid_t pid, char* signature, size_t signature_len);
bool macos_network_verify_process_signature(pid_t pid);

// Packet capture helpers
#if defined(__APPLE__) && defined(ENABLE_LIBPCAP)
pcap_t* macos_network_open_live_capture(const char* device, int snaplen, int promisc, int timeout, char* errbuf);
pcap_t* macos_network_open_file_capture(const char* filename, char* errbuf);
void macos_network_close_capture(pcap_t* handle);
int macos_network_set_capture_filter(pcap_t* handle, const char* filter);
#endif

// Error handling
const char* macos_network_get_last_error(const macos_network_monitor_t* monitor);
void macos_network_clear_error(macos_network_monitor_t* monitor);

// Advanced features
bool macos_network_monitor_enable_ssl_analysis(macos_network_monitor_t* monitor);
bool macos_network_monitor_enable_http_analysis(macos_network_monitor_t* monitor);
bool macos_network_monitor_enable_dns_analysis(macos_network_monitor_t* monitor);

// Flow tracking
typedef struct {
    uint32_t flow_id;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t start_time;
    uint64_t last_seen;
    bool is_active;
} macos_network_flow_t;

int macos_network_monitor_get_active_flows(const macos_network_monitor_t* monitor, 
                                          macos_network_flow_t* flows, 
                                          int max_flows);

// Real-time alerting
typedef enum {
    MACOS_NET_ALERT_SUSPICIOUS_CONNECTION,
    MACOS_NET_ALERT_HIGH_VOLUME_TRAFFIC,
    MACOS_NET_ALERT_UNUSUAL_PROTOCOL,
    MACOS_NET_ALERT_DNS_TUNNELING,
    MACOS_NET_ALERT_POTENTIAL_EXFILTRATION
} macos_network_alert_type_t;

typedef struct {
    macos_network_alert_type_t type;
    char description[512];
    uint64_t timestamp;
    macos_process_info_t process;
    macos_connection_event_t connection;
    uint32_t severity;
} macos_network_alert_t;

typedef void (*macos_network_alert_callback_t)(const macos_network_alert_t* alert, void* user_data);

void macos_network_monitor_set_alert_callback(macos_network_monitor_t* monitor, 
                                             macos_network_alert_callback_t callback, 
                                             void* user_data);
bool macos_network_monitor_enable_alerting(macos_network_monitor_t* monitor);
void macos_network_monitor_disable_alerting(macos_network_monitor_t* monitor);

#ifdef __cplusplus
}
#endif

#endif // SCREECH_MACOS_NETWORK_H

