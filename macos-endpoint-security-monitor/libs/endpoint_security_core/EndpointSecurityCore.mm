//
// EndpointSecurityCore.mm - Common Endpoint Security Core Library Implementation
//

#include "EndpointSecurityCore.h"
#include "../../debug_logging.h"
#include "../event_logger/EventLogger.h"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>

#ifdef __APPLE__
#include <libproc.h>
#include <sys/proc_info.h>
#endif

namespace EndpointSecurityCore {

EndpointSecurityCoreEngine::EndpointSecurityCoreEngine() {
    // Constructor - currently no initialization needed
}

EndpointSecurityCoreEngine::~EndpointSecurityCoreEngine() {
    // Destructor - currently no cleanup needed
}

std::string EndpointSecurityCoreEngine::getCurrentTimestamp() {
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
ProcessInfo EndpointSecurityCoreEngine::getProcessInfo(pid_t pid) {
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
#endif

void EndpointSecurityCoreEngine::logEvent(EventType eventType, const std::string& eventName,
                                         const std::string& details, const ProcessInfo& processInfo,
                                         const std::string& timestamp, const std::string& additionalInfo) {
    // Suppress unused parameter warning
    (void)timestamp;
    // Get EventLogger instance
    EventLogger::EventLoggerEngine& logger = EventLogger::getGlobalLogger();
    
    // Create detailed log message
    std::string logDetails = eventName + "|" + details + "|" +
                           "PID:" + std::to_string(processInfo.pid) + "|" +
                           "PROC:" + processInfo.name + "|" +
                           "UID:" + std::to_string(processInfo.uid) + "|" +
                           "PATH:" + processInfo.path;
    
    if (!additionalInfo.empty()) {
        logDetails += "|" + additionalInfo;
    }
    
    // Always use the centralized EventLogger - it handles both remote and local logging
    switch (eventType) {
        case EventType::FILE_SYSTEM:
            logger.logFileEvent(eventName, processInfo.name, processInfo.path, details);
            break;
        case EventType::PROCESS:
            logger.logProcessEvent(eventName, processInfo.name, processInfo.path, logDetails);
            break;
        case EventType::IPC_SECURITY:
            logger.logSecurityEvent(eventName, logDetails);
            break;
    }
}

void EndpointSecurityCoreEngine::logFileSystemEvent(const std::string& eventName, const std::string& filePath,
                                                   const std::string& details, const ProcessInfo& processInfo,
                                                   const std::string& timestamp) {
    std::string fullDetails = "FILE|" + eventName + "|" + filePath + "|" + details;
    logEvent(EventType::FILE_SYSTEM, eventName, fullDetails, processInfo, timestamp);
}

void EndpointSecurityCoreEngine::logProcessEvent(const std::string& eventName, const std::string& details,
                                                const ProcessInfo& processInfo, const std::string& timestamp) {
    std::string fullDetails = "PROC|" + eventName + "|" + details;
    logEvent(EventType::PROCESS, eventName, fullDetails, processInfo, timestamp);
}

void EndpointSecurityCoreEngine::logNetworkEvent(const std::string& eventName, const std::string& networkDetails,
                                                const ProcessInfo& processInfo, const std::string& timestamp) {
    std::string fullDetails = "NET|" + eventName + "|" + networkDetails;
    logEvent(EventType::NETWORK, eventName, fullDetails, processInfo, timestamp);
}

void EndpointSecurityCoreEngine::logIPCEvent(const std::string& eventName, const std::string& ipcDetails,
                                            const ProcessInfo& processInfo, const std::string& timestamp) {
    std::string fullDetails = "IPC|" + eventName + "|" + ipcDetails;
    logEvent(EventType::IPC_SECURITY, eventName, fullDetails, processInfo, timestamp);
}


} // namespace EndpointSecurityCore
