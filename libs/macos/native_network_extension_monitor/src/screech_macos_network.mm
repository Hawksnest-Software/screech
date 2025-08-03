#include <iostream>
#include <thread>
#include <atomic>
#include <unordered_set>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <csignal>
#include <string>
#include <cstring>
#include "screech_macos_network.h"
#include "event_logger/EventLogger.h"

#ifdef __APPLE__
#include <EndpointSecurity/EndpointSecurity.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <dispatch/dispatch.h>
#include <os/log.h>
#include <bsm/libbsm.h>
#endif


// Network connection event structure (similar to Linux eBPF version)
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

// Structure to hold process information
struct ProcessInfo {
    pid_t pid;
    std::string name;
    std::string path;
    uid_t uid;
    gid_t gid;
};

// Structure to hold event information
struct EventInfo {
    std::string eventType;
    std::string timestamp;
    ProcessInfo process;
    std::string networkDetails;
};

class MacOSNetworkMonitor {
private:
#ifdef __APPLE__
    es_client_t* esClient;
    dispatch_queue_t monitorQueue;
#endif
    std::atomic<bool> isRunning{false};
    std::unordered_set<std::string> seenConnections;
    
    // Static instance for use in static callback
    static MacOSNetworkMonitor* s_instance;

    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

#ifdef __APPLE__
    ProcessInfo getProcessInfo(pid_t pid) {
        ProcessInfo info = {};
        info.pid = pid;
        
        // Get process name and path using libproc
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
            info.path = std::string(pathbuf);
            
            // Extract name from path
            size_t lastSlash = info.path.find_last_of('/');
            if (lastSlash != std::string::npos) {
                info.name = info.path.substr(lastSlash + 1);
            } else {
                info.name = info.path;
            }
        }
        
        // Get process credentials
        struct proc_bsdinfo procInfo;
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) > 0) {
            info.uid = procInfo.pbi_uid;
            info.gid = procInfo.pbi_gid;
            if (info.name.empty()) {
                info.name = std::string(procInfo.pbi_comm);
            }
        }
        
        return info;
    }

    std::string ipToString(uint32_t ip) {
        struct in_addr addr;
        addr.s_addr = ip;
        return std::string(inet_ntoa(addr));
    }

    std::string protocolToString(uint8_t protocol) {
        switch (protocol) {
            case IPPROTO_TCP: return "TCP";
            case IPPROTO_UDP: return "UDP";
            case IPPROTO_ICMP: return "ICMP";
            default: return "OTHER";
        }
    }

    std::string extractNetworkInfo(const es_message_t* message) {
        std::stringstream ss;
        
        switch (message->event_type) {
            case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
                // Unix IPC connection
                ss << "UIPC_CONNECT domain:" << message->event.uipc_connect.domain 
                   << " type:" << message->event.uipc_connect.type
                   << " protocol:" << message->event.uipc_connect.protocol;
                break;
                
            case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
                // Unix IPC bind - structure changed in newer ES versions
                ss << "UIPC_BIND (details unavailable in this ES version)";
                break;
                
            case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
                // XPC connection - use newer API structure
                if (message->event.xpc_connect->service_name.data && message->event.xpc_connect->service_name.length > 0) {
                    std::string serviceName(message->event.xpc_connect->service_name.data, message->event.xpc_connect->service_name.length);
                    ss << "XPC_CONNECT service:" << serviceName;
                } else {
                    ss << "XPC_CONNECT service:(unknown)";
                }
                break;
                
            default:
                break;
        }
        
        return ss.str();
    }

    void handleEvent(const es_message_t* message) {
        if (!message) return;
        
        EventInfo eventInfo;
        eventInfo.timestamp = getCurrentTimestamp();
        
        // Get process information
        pid_t pid = audit_token_to_pid(message->process->audit_token);
        eventInfo.process = getProcessInfo(pid);
        
        // Handle network-related events (similar to Linux eBPF version)
        switch (message->event_type) {
            case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
                eventInfo.eventType = "UIPC_CONNECT";
                eventInfo.networkDetails = extractNetworkInfo(message);
                logNetworkEvent(eventInfo);
                break;
                
            case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
                eventInfo.eventType = "UIPC_BIND";
                eventInfo.networkDetails = extractNetworkInfo(message);
                logNetworkEvent(eventInfo);
                break;
                
            case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
                eventInfo.eventType = "XPC_CONNECT";
                eventInfo.networkDetails = extractNetworkInfo(message);
                logNetworkEvent(eventInfo);
                break;
                
            case ES_EVENT_TYPE_NOTIFY_EXEC:
                eventInfo.eventType = "EXEC";
                logProcessEvent(eventInfo);
                break;
                
            case ES_EVENT_TYPE_NOTIFY_FORK:
                eventInfo.eventType = "FORK";
                logProcessEvent(eventInfo);
                break;
                
            case ES_EVENT_TYPE_NOTIFY_EXIT:
                eventInfo.eventType = "EXIT";
                logProcessEvent(eventInfo);
                break;
                
            default:
                // Skip other events for network monitoring focus
                break;
        }
    }

    void logNetworkEvent(const EventInfo& eventInfo) {
        // Create connection identifier to avoid duplicates (like Linux eBPF version)
        std::string connectionId = eventInfo.networkDetails + "|" + std::to_string(eventInfo.process.pid);
        
        // Check if we've seen this connection before
        if (seenConnections.find(connectionId) != seenConnections.end()) {
            return; // Skip duplicate connections
        }
        seenConnections.insert(connectionId);
        
        // Check if remote logging is enabled
        EventLogger::EventLoggerEngine& logger = EventLogger::getGlobalLogger();
        
        if (logger.isRemoteLoggingEnabled()) {
            // Remote logging enabled - send to EventLogger for remote transmission
            std::string details = "CONN|" + eventInfo.networkDetails + "|" +
                                "PID:" + std::to_string(eventInfo.process.pid) + "|" +
                                "PROC:" + eventInfo.process.name + "|" +
                                "UID:" + std::to_string(eventInfo.process.uid) + "|" +
                                "PATH:" + eventInfo.process.path;
            
            logger.logNetworkEvent(eventInfo.eventType, eventInfo.process.name, 
                                 eventInfo.process.path, details);
        } else {
            // Remote logging disabled - write to local file without screech_ prefix
            std::string logFileName = eventInfo.process.name + ".log";
            if (eventInfo.process.name.empty()) {
                logFileName = "unknown_process.log";
            }
            
            std::ofstream logFile(logFileName, std::ios::app);
            if (logFile.is_open()) {
                // Write greppable log entry (matching Linux eBPF format)
                logFile << "[" << eventInfo.timestamp << "] "
                       << "CONN|" << eventInfo.networkDetails << "|"
                       << "PID:" << eventInfo.process.pid << "|"
                       << "PROC:" << eventInfo.process.name << "|"
                       << "UID:" << eventInfo.process.uid << "|"
                       << "PATH:" << eventInfo.process.path << std::endl;
                logFile.close();
            }
        }
        
        // Always log to console (matching Linux eBPF format)
        std::cout << "[" << eventInfo.timestamp << "] NEW CONNECTION: "
                  << eventInfo.networkDetails
                  << " (PID: " << eventInfo.process.pid << ", Process: " << eventInfo.process.name << ")"
                  << std::endl;
    }

    void logProcessEvent(const EventInfo& eventInfo) {
        // Check if remote logging is enabled
        EventLogger::EventLoggerEngine& logger = EventLogger::getGlobalLogger();
        
        if (logger.isRemoteLoggingEnabled()) {
            // Remote logging enabled - send to EventLogger for remote transmission
            std::string details = "EVENT|" + eventInfo.eventType + "|" +
                                "PID:" + std::to_string(eventInfo.process.pid) + "|" +
                                "PROC:" + eventInfo.process.name + "|" +
                                "UID:" + std::to_string(eventInfo.process.uid) + "|" +
                                "PATH:" + eventInfo.process.path;
            
            logger.logProcessEvent(eventInfo.eventType, eventInfo.process.name, 
                                 eventInfo.process.path, details);
        } else {
            // Remote logging disabled - write to local file without screech_ prefix
            std::string logFileName = eventInfo.process.name + ".log";
            if (eventInfo.process.name.empty()) {
                logFileName = "unknown_process.log";
            }
            
            std::ofstream logFile(logFileName, std::ios::app);
            if (logFile.is_open()) {
                // Write greppable log entry
                logFile << "[" << eventInfo.timestamp << "] "
                       << "EVENT|" << eventInfo.eventType << "|"
                       << "PID:" << eventInfo.process.pid << "|"
                       << "PROC:" << eventInfo.process.name << "|"
                       << "UID:" << eventInfo.process.uid << "|"
                       << "PATH:" << eventInfo.process.path << std::endl;
                logFile.close();
            }
        }
        
        // Always log to console
        std::cout << "[" << eventInfo.timestamp << "] " << eventInfo.eventType << ": "
                  << eventInfo.process.name << " (PID: " << eventInfo.process.pid << ")"
                  << std::endl;
    }

    static void staticHandleEvent(const es_message_t* message) {
        // Use static instance to handle the event
        if (s_instance && message) {
            s_instance->handleEvent(message);
        }
    }
#endif

public:
    MacOSNetworkMonitor() {
#ifdef __APPLE__
        esClient = nullptr;
        monitorQueue = dispatch_queue_create("screech.network.monitor", DISPATCH_QUEUE_SERIAL);
#endif
    }

    ~MacOSNetworkMonitor() {
        stop();
#ifdef __APPLE__
        // monitorQueue will be automatically released by ARC
#endif
    }

    bool start() {
#ifdef __APPLE__
        // Create ES client with handler block
        es_handler_block_t handler = ^(es_client_t * _Nonnull client, const es_message_t * _Nonnull message) {
            (void)client; // Suppress unused parameter warning
            this->handleEvent(message);
        };
        
        es_new_client_result_t result = es_new_client(&esClient, handler);
        if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
            std::cerr << "Failed to create Endpoint Security client: " << result << std::endl;
            return false;
        }

        // Subscribe to network and process events (similar to Linux eBPF version)
        es_event_type_t events[] = {
            ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
            ES_EVENT_TYPE_NOTIFY_UIPC_BIND,
            ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT
        };

        es_return_t subscribe_result = es_subscribe(esClient, events, sizeof(events) / sizeof(events[0]));
        if (subscribe_result != ES_RETURN_SUCCESS) {
            std::cerr << "Failed to subscribe to events: " << subscribe_result << std::endl;
            es_delete_client(esClient);
            esClient = nullptr;
            return false;
        }
        
        isRunning = true;
        std::cout << "macOS Network Monitor started successfully" << std::endl;
        std::cout << "Monitoring network connections like Linux eBPF version..." << std::endl;
        return true;
#else
        std::cerr << "This monitor only works on macOS" << std::endl;
        return false;
#endif
    }

    void stop() {
        if (!isRunning) return;
        
        isRunning = false;
        
#ifdef __APPLE__
        if (esClient) {
            es_delete_client(esClient);
            esClient = nullptr;
        }
#endif
        
        std::cout << "macOS Network Monitor stopped" << std::endl;
    }

    bool isMonitoring() const {
        return isRunning;
    }
};

// Static member definition
MacOSNetworkMonitor* MacOSNetworkMonitor::s_instance = nullptr;

// C wrapper functions to bridge to the C++ class
extern "C" {

macos_network_monitor_t* macos_network_monitor_create(void) {
    return reinterpret_cast<macos_network_monitor_t*>(new MacOSNetworkMonitor());
}

void macos_network_monitor_destroy(macos_network_monitor_t* monitor) {
    if (monitor) {
        delete reinterpret_cast<MacOSNetworkMonitor*>(monitor);
    }
}

bool macos_network_monitor_start(macos_network_monitor_t* monitor) {
    if (monitor) {
        return reinterpret_cast<MacOSNetworkMonitor*>(monitor)->start();
    }
    return false;
}

void macos_network_monitor_stop(macos_network_monitor_t* monitor) {
    if (monitor) {
        reinterpret_cast<MacOSNetworkMonitor*>(monitor)->stop();
    }
}

bool macos_network_monitor_is_running(const macos_network_monitor_t* monitor) {
    if (monitor) {
        return reinterpret_cast<const MacOSNetworkMonitor*>(monitor)->isMonitoring();
    }
    return false;
}

void macos_network_monitor_set_network_callback(macos_network_monitor_t* monitor, 
                                               macos_network_event_callback_t callback, 
                                               void* user_data) {
    // For now, this is a stub implementation
    // The C++ class would need to be extended to support callbacks
    (void)monitor;
    (void)callback;
    (void)user_data;
}

// Stub implementations for other declared functions
void macos_network_monitor_get_stats(const macos_network_monitor_t* monitor, macos_capture_stats_t* stats) {
    (void)monitor;
    if (stats) {
        memset(stats, 0, sizeof(*stats));
    }
}

const char* macos_network_get_last_error(const macos_network_monitor_t* monitor) {
    (void)monitor;
    return "No error";
}

} // extern "C"

