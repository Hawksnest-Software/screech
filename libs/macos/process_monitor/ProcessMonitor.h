//
// ProcessMonitor.h - Process Monitoring Library
// Monitors process creation, termination, and activity
//

#ifndef PROCESS_MONITOR_H
#define PROCESS_MONITOR_H

#include <string>
#include <functional>
#include <memory>

#ifdef __APPLE__
#include <EndpointSecurity/EndpointSecurity.h>
#include <libproc.h>
#include <sys/proc_info.h>
#endif

namespace ProcessMonitor {

struct ProcessInfo {
    pid_t pid;
    std::string name;
    std::string path;
    uid_t uid;
    gid_t gid;
    pid_t parent_pid;
};

struct ProcessEvent {
    enum Type {
        EXEC,
        FORK,
        EXIT
    } type;
    
    std::string timestamp;
    ProcessInfo process;
    std::string details;
};

using ProcessEventCallback = std::function<void(const ProcessEvent&)>;

class ProcessMonitorEngine {
public:
    ProcessMonitorEngine();
    ~ProcessMonitorEngine();
    
    bool initialize();
    bool start();
    void stop();
    bool isRunning() const;
    
    void setEventCallback(ProcessEventCallback callback);
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// C API for compatibility
extern "C" {
    typedef void (*process_event_callback_t)(const ProcessEvent* event);
    
    void* process_monitor_create();
    void process_monitor_destroy(void* monitor);
    bool process_monitor_initialize(void* monitor);
    bool process_monitor_start(void* monitor);
    void process_monitor_stop(void* monitor);
    void process_monitor_set_callback(void* monitor, process_event_callback_t callback);
}

} // namespace ProcessMonitor

#endif // PROCESS_MONITOR_H
