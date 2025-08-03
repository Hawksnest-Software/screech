//
// EventLogger.cpp - Centralized Event Logging Implementation
// Creates log files based on monitored application names
//

#include "EventLogger.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <cstdlib>
#include <unistd.h>

namespace EventLogger {

class EventLoggerEngine::Impl {
public:
    std::string logDirectory;
    bool remoteLoggingEnabled = false;
    RemoteLogging::RemoteLoggerEngine* remoteLogger = nullptr;
    
    Impl() {
        // Use current user's home directory by default
        const char* homeDir = getenv("HOME");
        if (homeDir) {
            logDirectory = std::string(homeDir) + "/";
        } else {
            logDirectory = "/tmp/";
        }
    }
    
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
    
    std::string getTimestampForFilename() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S");
        return ss.str();
    }
    
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
    
    void writeEventToLog(const std::string& eventType, const std::string& processName, 
                         const std::string& processPath, const std::string& details) {
        // Skip events from our own monitoring process or temp processes
        if (processPath.find("/tmp/") != std::string::npos) {
            return;
        }
        
        // Send to remote logger if enabled
        if (remoteLoggingEnabled && remoteLogger && remoteLogger->isConnected()) {
            // Extract app bundle name first (for macOS), then fall back to process name
            std::string programNameForLog = extractAppBundleName(processPath);
            if (programNameForLog.empty() || programNameForLog == "unknown") {
                programNameForLog = processName.empty() ? "unknown_process" : processName;
            }
            remoteLogger->logEventWithProgramName(programNameForLog, eventType, processName, processPath, details);
        }
        
        // Also write to local file
        std::string appName = extractAppBundleName(processPath);
        std::string timestamp = getTimestampForFilename();
        
        // Create log filename without any identifying prefixes - looks like normal app logs
        std::string logFileName = logDirectory + timestamp + "_" + appName + ".log";
        
        std::ofstream logFile(logFileName, std::ios::app);
        if (logFile.is_open()) {
            logFile << "[" << getCurrentTimestamp() << "] "
                   << eventType << "|"
                   << "PROC:" << processName << "|"
                   << "PATH:" << processPath << "|"
                   << "DETAILS:" << details << std::endl;
            logFile.close();
        }
    }
};

EventLoggerEngine::EventLoggerEngine() : pImpl(std::make_unique<Impl>()) {}
EventLoggerEngine::~EventLoggerEngine() = default;

bool EventLoggerEngine::initialize() {
    return true;
}

void EventLoggerEngine::setLogDirectory(const std::string& directory) {
    pImpl->logDirectory = directory;
    if (!pImpl->logDirectory.empty() && pImpl->logDirectory.back() != '/') {
        pImpl->logDirectory += "/";
    }
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

void EventLoggerEngine::logEvent(EventType type, const std::string& processName, 
                                 const std::string& processPath, const std::string& details) {
    // Convert EventType enum to string for logging
    std::string eventTypeStr;
    switch (type) {
        case EventType::PROCESS_EXEC:
            eventTypeStr = "PROC_EXEC";
            break;
        case EventType::PROCESS_FORK:
            eventTypeStr = "PROC_FORK";
            break;
        case EventType::PROCESS_EXIT:
            eventTypeStr = "PROC_EXIT";
            break;
        case EventType::FILE_OPEN:
            eventTypeStr = "FILE_OPEN";
            break;
        case EventType::FILE_CLOSE:
            eventTypeStr = "FILE_CLOSE";
            break;
        case EventType::FILE_WRITE:
            eventTypeStr = "FILE_WRITE";
            break;
        case EventType::FILE_CREATE:
            eventTypeStr = "FILE_CREATE";
            break;
        case EventType::FILE_DELETE:
            eventTypeStr = "FILE_DELETE";
            break;
        case EventType::FILE_RENAME:
            eventTypeStr = "FILE_RENAME";
            break;
        case EventType::NETWORK_CONNECT:
            eventTypeStr = "NET_CONN";
            break;
        case EventType::NETWORK_DISCONNECT:
            eventTypeStr = "NET_DISCONN";
            break;
        case EventType::NETWORK_DATA:
            eventTypeStr = "NET_DATA";
            break;
        case EventType::NETWORK_INTERFACE_CHANGE:
            eventTypeStr = "NET_IFACE";
            break;
        case EventType::NETWORK_DNS:
            eventTypeStr = "NET_DNS";
            break;
        case EventType::SECURITY_ALERT:
            eventTypeStr = "SECURITY";
            break;
        default:
            eventTypeStr = "UNKNOWN";
            break;
    }
    
    pImpl->writeEventToLog(eventTypeStr, processName, processPath, details);
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

void EventLoggerEngine::logNetworkEvent(const std::string& eventType, const std::string& processName, 
                                        const std::string& processPath, const std::string& connectionDetails) {
    pImpl->writeEventToLog(eventType, processName, processPath, connectionDetails);
}

void EventLoggerEngine::logSecurityEvent(const std::string& alertType, const std::string& details) {
    pImpl->writeEventToLog("SECURITY_ALERT", "system", "", alertType + " " + details);
}

EventLoggerEngine& getGlobalLogger() {
    static EventLoggerEngine instance;
    return instance;
}

} // namespace EventLogger
