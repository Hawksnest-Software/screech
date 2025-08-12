//
// EventLogger.cpp - Centralized Remote Event Logging Implementation
//

#include "EventLogger.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <mutex>

#ifdef __APPLE__
#include <os/log.h>
#else
#include <syslog.h>
#endif

namespace EventLogger {

class EventLoggerEngine::Impl {
public:
    bool remoteLoggingEnabled = false;
    RemoteLogging::RemoteLoggerEngine* remoteLogger = nullptr;
    mutable std::mutex logMutex; // Thread safety for concurrent logging
    
    std::string extractAppBundleName(const std::string& path) {
        // Extract app bundle name from path (e.g., /Applications/Safari.app/Contents/MacOS/Safari -> Safari.app)
        size_t appPos = path.find(".app/");
        if (appPos != std::string::npos) {
            size_t lastSlash = path.rfind('/', appPos);
            if (lastSlash != std::string::npos) {
                return path.substr(lastSlash + 1, appPos - lastSlash + 3); // +3 for ".app"
            }
        }
        
        // If no .app bundle found, extract just the executable name
        size_t lastSlash = path.find_last_of('/');
        if (lastSlash != std::string::npos) {
            return path.substr(lastSlash + 1);
        }
        
        return path.empty() ? "unknown" : path;
    }
    
    std::string getEventTypeLabel(const std::string& eventType) {
        // Map event types to appropriate labels
        if (eventType.find("FILE_") == 0 || eventType.find("FILE") != std::string::npos) {
            return "[FILESYSTEM]";
        } else if (eventType.find("PROC_") == 0 || eventType.find("PROCESS") != std::string::npos ||
                   eventType.find("EXEC") != std::string::npos || eventType.find("FORK") != std::string::npos ||
                   eventType.find("EXIT") != std::string::npos) {
            return "[PROCESS]";
        } else if (eventType.find("XPC_") == 0 || eventType.find("UIPC_") == 0 || 
                   eventType.find("IPC") != std::string::npos) {
            return "[IPC]";
        } else {
            return "[INFO]";
        }
    }
    
    void writeEventToLog(const std::string& eventType, const std::string& processName, 
                         const std::string& processPath, const std::string& details) {
        // Thread safety - lock for the entire logging operation
        std::lock_guard<std::mutex> lock(logMutex);
        
        // Get appropriate label for this event type
        std::string eventLabel = getEventTypeLabel(eventType);
        
        // Send to remote logger if enabled - this is the primary logging mechanism
        if (remoteLoggingEnabled && remoteLogger && remoteLogger->isConnected()) {
            try {
                // Extract app bundle name first (for macOS), then fall back to process name
                std::string programNameForLog = extractAppBundleName(processPath);
                if (programNameForLog.empty() || programNameForLog == "unknown") {
                    programNameForLog = processName.empty() ? "unknown_process" : processName;
                }
                
                // Include event label in remote logging
                std::string remoteEventType = eventLabel + " " + eventType;
                remoteLogger->logEventWithProgramName(programNameForLog, remoteEventType, processName, processPath, details);
                return; // Successfully logged remotely
            } catch (const std::exception& e) {
                // Remote logging failed, fall through to system logging
            }
        }
        
        // If remote logging is not enabled or failed, log to system logs only
#ifdef __APPLE__
        // Use os_log on macOS
        os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_INFO, 
            "%s %s|PROC:%s|PATH:%s|DETAILS:%s",
            eventLabel.c_str(), eventType.c_str(), processName.c_str(), 
            processPath.c_str(), details.c_str());
#else
        // Use syslog on Linux
        openlog("monitor", LOG_PID, LOG_USER);
        syslog(LOG_INFO, "%s %s|PROC:%s|PATH:%s|DETAILS:%s",
            eventLabel.c_str(), eventType.c_str(), processName.c_str(), 
            processPath.c_str(), details.c_str());
        closelog();
#endif
    }
};

EventLoggerEngine::EventLoggerEngine() : pImpl(std::make_unique<Impl>()) {}
EventLoggerEngine::~EventLoggerEngine() = default;

bool EventLoggerEngine::initialize() {
    return true;
}

bool EventLoggerEngine::enableRemoteLogging(const std::string& serverHost, int serverPort) {
    if (!pImpl->remoteLogger) {
        pImpl->remoteLogger = &RemoteLogging::getGlobalRemoteLogger();
    }
    
    RemoteLogging::RemoteLogConfig config;
    config.serverHost = serverHost;
    config.serverPort = serverPort;
    config.facility = "local0";
    config.appName = "monitor";
    config.useHostnamePrefix = true;
    config.fallbackToLocal = true;
    
    if (pImpl->remoteLogger->initialize(config)) {
        pImpl->remoteLoggingEnabled = true;
        return true;
    }
    
    return false;
}

void EventLoggerEngine::disableRemoteLogging() {
    if (pImpl->remoteLogger) {
        pImpl->remoteLogger->shutdown();
    }
    pImpl->remoteLoggingEnabled = false;
}

bool EventLoggerEngine::isRemoteLoggingEnabled() const {
    return pImpl->remoteLoggingEnabled && pImpl->remoteLogger && pImpl->remoteLogger->isConnected();
}

void EventLoggerEngine::logProcessEvent(const std::string& eventType, const std::string& processName, 
                                        const std::string& processPath, const std::string& details) {
    pImpl->writeEventToLog(eventType, processName, processPath, details);
}

void EventLoggerEngine::logFileEvent(const std::string& eventType, const std::string& processName, 
                                     const std::string& processPath, const std::string& filePath, 
                                     const std::string& details) {
    std::string fileDetails = "file:" + filePath;
    if (!details.empty()) {
        fileDetails += " " + details;
    }
    pImpl->writeEventToLog(eventType, processName, processPath, fileDetails);
}

void EventLoggerEngine::logSecurityEvent(const std::string& alertType, const std::string& details) {
    pImpl->writeEventToLog("SECURITY_ALERT", "system", "", alertType + " " + details);
}

EventLoggerEngine& getGlobalLogger() {
    static EventLoggerEngine instance;
    return instance;
}

} // namespace EventLogger
