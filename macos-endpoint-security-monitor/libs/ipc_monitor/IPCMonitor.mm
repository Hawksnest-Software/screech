//
// IPCMonitor.mm - IPC Monitoring Library Implementation
//

#include "IPCMonitor.h"
#include "debug_logging.h"
#include "../endpoint_security_core/EndpointSecurityCore.h"
#include <iostream>
#include <sstream>
#include <atomic>

#ifdef __APPLE__
#include <dispatch/dispatch.h>
#include <bsm/libbsm.h>
#endif

namespace IPCMonitor {

class IPCMonitorEngine::Impl {
public:
    Impl() : esClient(nullptr), isActive(false) {
#ifdef __APPLE__
        monitorQueue = dispatch_queue_create("ipc.monitor", DISPATCH_QUEUE_SERIAL);
#endif
    }
    
    ~Impl() {
        stop();
#ifdef __APPLE__
        // monitorQueue will be automatically released by ARC
#endif
    }
    
    bool initialize() {
#ifdef __APPLE__
        es_handler_block_t handler = ^(es_client_t * _Nonnull client, const es_message_t * _Nonnull message) {
            (void)client;
            handleEvent(message);
        };
        
        es_new_client_result_t result = es_new_client(&esClient, handler);
        if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
            DEBUG_LOG_ERROR("Failed to create IPC Endpoint Security client: %d", result);
            return false;
        }
        
        // Subscribe only to IPC-related events
        es_event_type_t events[] = {
            ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
            ES_EVENT_TYPE_NOTIFY_UIPC_BIND,
            ES_EVENT_TYPE_NOTIFY_XPC_CONNECT
        };
        
        es_return_t subscribe_result = es_subscribe(esClient, events, sizeof(events) / sizeof(events[0]));
        if (subscribe_result != ES_RETURN_SUCCESS) {
            DEBUG_LOG_ERROR("Failed to subscribe to IPC events: %d", subscribe_result);
            es_delete_client(esClient);
            esClient = nullptr;
            return false;
        }
        
        DEBUG_LOG_IPC("IPC monitoring initialized successfully");
        return true;
#else
        DEBUG_LOG_ERROR("IPC monitoring only supported on macOS");
        return false;
#endif
    }
    
    bool start() {
        if (!esClient) return false;
        isActive = true;
        DEBUG_LOG_IPC("IPC monitoring started");
        return true;
    }
    
    void stop() {
        isActive = false;
#ifdef __APPLE__
        if (esClient) {
            es_delete_client(esClient);
            esClient = nullptr;
        }
#endif
        DEBUG_LOG_IPC("IPC monitoring stopped");
    }
    
    bool isRunning() const {
        return isActive;
    }
    
    void setEventCallback(IPCEventCallback cb) {
        callback = cb;
    }
    
private:
#ifdef __APPLE__
    es_client_t* esClient;
    dispatch_queue_t monitorQueue;
#endif
    std::atomic<bool> isActive;
    IPCEventCallback callback;
    
#ifdef __APPLE__
    
    std::string extractIPCDetails(const es_message_t* message) {
        std::stringstream ss;
        
        switch (message->event_type) {
            case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
                // Unix IPC connection
                ss << "domain:" << message->event.uipc_connect.domain 
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
                    ss << "service:" << serviceName;
                } else {
                    ss << "service:(unknown)";
                }
                break;
                
            default:
                break;
        }
        
        return ss.str();
    }
    
    void logIPCEvent(const IPCEvent& event) {
        // Debug logging
        const char* eventTypeStr = "";
        switch (event.type) {
            case IPCEvent::UIPC_CONNECT: eventTypeStr = "UIPC_CONNECT"; break;
            case IPCEvent::UIPC_BIND: eventTypeStr = "UIPC_BIND"; break;
            case IPCEvent::XPC_CONNECT: eventTypeStr = "XPC_CONNECT"; break;
        }
        
        DEBUG_LOG_IPC("%s: %s (PID: %d, Process: %s)", 
                       eventTypeStr, event.details.c_str(), event.process.pid, event.process.name.c_str());
        
        // Use EndpointSecurityCore logging
        EndpointSecurityCore::EndpointSecurityCoreEngine::logIPCEvent(
            eventTypeStr, event.details, event.process, event.timestamp);
    }
    
    void handleEvent(const es_message_t* message) {
        if (!message) return;
        
        IPCEvent event;
        event.timestamp = EndpointSecurityCore::EndpointSecurityCoreEngine::getCurrentTimestamp();
        
        // Get process information
        pid_t pid = audit_token_to_pid(message->process->audit_token);
        event.process = EndpointSecurityCore::EndpointSecurityCoreEngine::getProcessInfo(pid);
        
        // Handle IPC events
        switch (message->event_type) {
            case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
                event.type = IPCEvent::UIPC_CONNECT;
                event.details = extractIPCDetails(message);
                logIPCEvent(event);
                break;
                
            case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
                event.type = IPCEvent::UIPC_BIND;
                event.details = extractIPCDetails(message);
                logIPCEvent(event);
                break;
                
            case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
                event.type = IPCEvent::XPC_CONNECT;
                event.details = extractIPCDetails(message);
                logIPCEvent(event);
                break;
                
            default:
                return;
        }
        
        if (callback) {
            callback(event);
        }
    }
#endif
};

IPCMonitorEngine::IPCMonitorEngine() : pImpl(std::make_unique<Impl>()) {}
IPCMonitorEngine::~IPCMonitorEngine() = default;

bool IPCMonitorEngine::initialize() { return pImpl->initialize(); }
bool IPCMonitorEngine::start() { return pImpl->start(); }
void IPCMonitorEngine::stop() { pImpl->stop(); }
bool IPCMonitorEngine::isRunning() const { return pImpl->isRunning(); }
void IPCMonitorEngine::setEventCallback(IPCEventCallback callback) { pImpl->setEventCallback(callback); }

} // namespace IPCMonitor

// C API implementation
extern "C" {
    ipc_monitor_t* ipc_monitor_create() {
        return reinterpret_cast<ipc_monitor_t*>(new IPCMonitor::IPCMonitorEngine());
    }
    
    void ipc_monitor_destroy(ipc_monitor_t* monitor) {
        delete reinterpret_cast<IPCMonitor::IPCMonitorEngine*>(monitor);
    }
    
    bool ipc_monitor_initialize(ipc_monitor_t* monitor) {
        return reinterpret_cast<IPCMonitor::IPCMonitorEngine*>(monitor)->initialize();
    }
    
    bool ipc_monitor_start(ipc_monitor_t* monitor) {
        return reinterpret_cast<IPCMonitor::IPCMonitorEngine*>(monitor)->start();
    }
    
    void ipc_monitor_stop(ipc_monitor_t* monitor) {
        reinterpret_cast<IPCMonitor::IPCMonitorEngine*>(monitor)->stop();
    }
    
    bool ipc_monitor_is_running(const ipc_monitor_t* monitor) {
        return reinterpret_cast<const IPCMonitor::IPCMonitorEngine*>(monitor)->isRunning();
    }
    
    void ipc_monitor_set_callback(ipc_monitor_t* monitor, ipc_event_callback_t callback, void* user_data) {
        if (monitor && callback) {
            auto engine = reinterpret_cast<IPCMonitor::IPCMonitorEngine*>(monitor);
            engine->setEventCallback([callback, user_data](const IPCMonitor::IPCEvent& event) {
                callback(&event, user_data);
            });
        }
    }
}
