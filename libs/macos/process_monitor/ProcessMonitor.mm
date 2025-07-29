//
// ProcessMonitor.cpp - Process Monitoring Library Implementation
//

#include "ProcessMonitor.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
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
        if (monitorQueue) {
            dispatch_release(monitorQueue);
        }
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
            std::cerr << "Failed to create Endpoint Security client: " << result << std::endl;
            return false;
        }
        
        es_event_type_t events[] = {
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT
        };
        
        es_return_t subscribe_result = es_subscribe(esClient, events, sizeof(events) / sizeof(events[0]));
        if (subscribe_result != ES_RETURN_SUCCESS) {
            std::cerr << "Failed to subscribe to process events: " << subscribe_result << std::endl;
            es_delete_client(esClient);
            esClient = nullptr;
            return false;
        }
        
        return true;
#else
        std::cerr << "Process monitoring only supported on macOS" << std::endl;
        return false;
#endif
    }
    
    bool start() {
        if (!esClient) return false;
        isActive = true;
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
        
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
            info.path = std::string(pathbuf);
            
            size_t lastSlash = info.path.find_last_of('/');
            if (lastSlash != std::string::npos) {
                info.name = info.path.substr(lastSlash + 1);
            } else {
                info.name = info.path;
            }
        }
        
        struct proc_bsdinfo procInfo;
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) > 0) {
            info.uid = procInfo.pbi_uid;
            info.gid = procInfo.pbi_gid;
            info.parent_pid = procInfo.pbi_ppid;
            if (info.name.empty()) {
                info.name = std::string(procInfo.pbi_comm);
            }
        }
        
        return info;
    }
    
    void handleEvent(const es_message_t* message) {
        if (!message || !callback) return;
        
        ProcessEvent event;
        event.timestamp = getCurrentTimestamp();
        
        pid_t pid = audit_token_to_pid(message->process->audit_token);
        event.process = getProcessInfo(pid);
        
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
        
        callback(event);
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
