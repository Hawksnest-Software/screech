//
// ProcessMonitor.cpp - Process Monitoring Library Implementation
//

#include "ProcessMonitor.h"
#include "debug_logging.h"
#include "../endpoint_security_core/EndpointSecurityCore.h"
#include <iostream>
#include <atomic>

#ifdef __APPLE__
#include <dispatch/dispatch.h>
#include <bsm/libbsm.h>
#endif

namespace ProcessMonitor {

class ProcessMonitorEngine::Impl {
public:
    Impl() : esClient(nullptr), isActive(false) {
#ifdef __APPLE__
        monitorQueue = dispatch_queue_create("process.monitor", DISPATCH_QUEUE_SERIAL);
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
            DEBUG_LOG_ERROR("Failed to create Process Endpoint Security client: %d", result);
            return false;
        }
        
        es_event_type_t events[] = {
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT
        };
        
        es_return_t subscribe_result = es_subscribe(esClient, events, sizeof(events) / sizeof(events[0]));
        if (subscribe_result != ES_RETURN_SUCCESS) {
            DEBUG_LOG_ERROR("Failed to subscribe to process events: %d", subscribe_result);
            es_delete_client(esClient);
            esClient = nullptr;
            return false;
        }
        
        DEBUG_LOG_PROCESS("Process monitoring initialized successfully");
        return true;
#else
        DEBUG_LOG_ERROR("Process monitoring only supported on macOS");
        return false;
#endif
    }
    
    bool start() {
        if (!esClient) return false;
        isActive = true;
        DEBUG_LOG_PROCESS("Process monitoring started");
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
        DEBUG_LOG_PROCESS("Process monitoring stopped");
    }
    
    bool isRunning() const {
        return isActive;
    }
    
    void setEventCallback(ProcessEventCallback cb) {
        callback = cb;
    }
    
private:
#ifdef __APPLE__
    es_client_t* esClient;
    dispatch_queue_t monitorQueue;
#endif
    std::atomic<bool> isActive;
    ProcessEventCallback callback;
    
#ifdef __APPLE__
    void logProcessEvent(const ProcessEvent& event) {
        // Debug logging
        const char* eventTypeStr = "";
        switch (event.type) {
            case ProcessEvent::EXEC: eventTypeStr = "PROCESS_EXEC"; break;
            case ProcessEvent::FORK: eventTypeStr = "PROCESS_FORK"; break;
            case ProcessEvent::EXIT: eventTypeStr = "PROCESS_EXIT"; break;
        }
        
        DEBUG_LOG_PROCESS("%s: %s (PID: %d, Process: %s)", 
                         eventTypeStr, event.details.c_str(), event.process.pid, event.process.name.c_str());
        
        // Use EndpointSecurityCore logging
        EndpointSecurityCore::EndpointSecurityCoreEngine::logProcessEvent(
            eventTypeStr, event.details, event.process, event.timestamp);
    }
    
    void handleEvent(const es_message_t* message) {
        if (!message) return;
        
        ProcessEvent event;
        event.timestamp = EndpointSecurityCore::EndpointSecurityCoreEngine::getCurrentTimestamp();

        pid_t pid = audit_token_to_pid(message->process->audit_token);
        event.process = EndpointSecurityCore::EndpointSecurityCoreEngine::getProcessInfo(pid);
        
        switch (message->event_type) {
            case ES_EVENT_TYPE_NOTIFY_EXEC:
                event.type = ProcessEvent::EXEC;
                if (message->event.exec.target->executable && message->event.exec.target->executable->path.data) {
                    event.details = "exec_path:" + std::string(message->event.exec.target->executable->path.data, 
                                                              message->event.exec.target->executable->path.length);
                }
                break;

            case ES_EVENT_TYPE_NOTIFY_FORK:
                event.type = ProcessEvent::FORK;
                event.details = "child_pid:" + std::to_string(message->event.fork.child->audit_token.val[5]);
                break;

            case ES_EVENT_TYPE_NOTIFY_EXIT:
                event.type = ProcessEvent::EXIT;
                event.details = "exit_status:" + std::to_string(message->event.exit.stat);
                break;

            default:
                return;
        }

        // Log the process event
        logProcessEvent(event);

        // Call the callback if set
        if (callback) {
            callback(event);
        }
    }
#endif
};

ProcessMonitorEngine::ProcessMonitorEngine() : pImpl(std::make_unique<Impl>()) {}
ProcessMonitorEngine::~ProcessMonitorEngine() = default;

bool ProcessMonitorEngine::initialize() { return pImpl->initialize(); }
bool ProcessMonitorEngine::start() { return pImpl->start(); }
void ProcessMonitorEngine::stop() { pImpl->stop(); }
bool ProcessMonitorEngine::isRunning() const { return pImpl->isRunning(); }
void ProcessMonitorEngine::setEventCallback(ProcessEventCallback callback) { pImpl->setEventCallback(callback); }

// C API implementation
extern "C" {
    void* process_monitor_create() {
        return new ProcessMonitorEngine();
    }
    
    void process_monitor_destroy(void* monitor) {
        delete static_cast<ProcessMonitorEngine*>(monitor);
    }
    
    bool process_monitor_initialize(void* monitor) {
        return static_cast<ProcessMonitorEngine*>(monitor)->initialize();
    }
    
    bool process_monitor_start(void* monitor) {
        return static_cast<ProcessMonitorEngine*>(monitor)->start();
    }
    
    void process_monitor_stop(void* monitor) {
        static_cast<ProcessMonitorEngine*>(monitor)->stop();
    }
    
    void process_monitor_set_callback(void* monitor, process_event_callback_t callback) {
        static_cast<ProcessMonitorEngine*>(monitor)->setEventCallback([callback](const ProcessEvent& event) {
            callback(&event);
        });
    }
}

} // namespace ProcessMonitor
