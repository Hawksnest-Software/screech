//
// IPCMonitor.h - IPC Monitoring Library (UIPC/XPC Events)
//

#ifndef IPC_MONITOR_H
#define IPC_MONITOR_H

#include <string>
#include <functional>
#include <memory>
#include "../endpoint_security_core/EndpointSecurityCore.h"

#ifdef __APPLE__
#include <EndpointSecurity/EndpointSecurity.h>
#include <libproc.h>
#endif

namespace IPCMonitor {

// Use the common ProcessInfo from EndpointSecurityCore
using ProcessInfo = EndpointSecurityCore::ProcessInfo;

struct IPCEvent {
    enum Type {
        UIPC_CONNECT,
        UIPC_BIND,
        XPC_CONNECT
    };
    
    Type type;
    std::string timestamp;
    ProcessInfo process;
    std::string details;
};

// Callback function type for IPC events
using IPCEventCallback = std::function<void(const IPCEvent&)>;

class IPCMonitorEngine {
public:
    IPCMonitorEngine();
    ~IPCMonitorEngine();

    // Core functionality
    bool initialize();
    bool start();
    void stop();
    bool isRunning() const;

    // Event handling
    void setEventCallback(IPCEventCallback callback);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace IPCMonitor

// C API for compatibility with existing code
extern "C" {
    typedef struct ipc_monitor_t ipc_monitor_t;
    typedef void (*ipc_event_callback_t)(const void* event, void* user_data);

    // Core functions
    ipc_monitor_t* ipc_monitor_create(void);
    void ipc_monitor_destroy(ipc_monitor_t* monitor);
    bool ipc_monitor_initialize(ipc_monitor_t* monitor);
    bool ipc_monitor_start(ipc_monitor_t* monitor);
    void ipc_monitor_stop(ipc_monitor_t* monitor);
    bool ipc_monitor_is_running(const ipc_monitor_t* monitor);
    
    // Event handling
    void ipc_monitor_set_callback(ipc_monitor_t* monitor, ipc_event_callback_t callback, void* user_data);
}

#endif // IPC_MONITOR_H
