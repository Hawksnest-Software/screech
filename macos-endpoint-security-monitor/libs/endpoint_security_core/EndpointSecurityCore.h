//
// EndpointSecurityCore.h - Common Endpoint Security Core Library
//

#ifndef ENDPOINT_SECURITY_CORE_H
#define ENDPOINT_SECURITY_CORE_H

#include <string>
#include <cstdint>

#ifdef __APPLE__
#include <sys/types.h>
#include <libproc.h>
#include <sys/proc_info.h>
#endif

namespace EndpointSecurityCore {

// Common process information structure
struct ProcessInfo {
    pid_t pid = 0;
    std::string name;
    std::string path;
    uid_t uid = 0;
    gid_t gid = 0;
    pid_t parent_pid = 0;
};

// Event logging types
enum class EventType {
    FILE_SYSTEM,
    PROCESS,
    NETWORK,
    IPC_SECURITY
};

// Core utility class for Endpoint Security monitoring
class EndpointSecurityCoreEngine {
public:
    EndpointSecurityCoreEngine();
    ~EndpointSecurityCoreEngine();

    // Timestamp utilities
    static std::string getCurrentTimestamp();

    // Process information utilities
#ifdef __APPLE__
    static ProcessInfo getProcessInfo(pid_t pid);
#endif

    // Event logging utilities
    static void logEvent(EventType eventType, const std::string& eventName, 
                        const std::string& details, const ProcessInfo& processInfo,
                        const std::string& timestamp, const std::string& additionalInfo = "");

    // Specialized logging methods
    static void logFileSystemEvent(const std::string& eventName, const std::string& filePath,
                                  const std::string& details, const ProcessInfo& processInfo,
                                  const std::string& timestamp);

    static void logProcessEvent(const std::string& eventName, const std::string& details,
                               const ProcessInfo& processInfo, const std::string& timestamp);

    static void logNetworkEvent(const std::string& eventName, const std::string& networkDetails,
                               const ProcessInfo& processInfo, const std::string& timestamp);

    static void logIPCEvent(const std::string& eventName, const std::string& ipcDetails,
                           const ProcessInfo& processInfo, const std::string& timestamp);

private:
    // Private helper functions if needed in future
};

} // namespace EndpointSecurityCore

#endif // ENDPOINT_SECURITY_CORE_H
