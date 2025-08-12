//
// EventLogger.h - Centralized Remote Event Logging Library
//

#ifndef EVENT_LOGGER_H
#define EVENT_LOGGER_H

#include <string>
#include <memory>
#include "../remote_logging/RemoteLogger.h"

namespace EventLogger {

enum class EventType {
    PROCESS_EXEC,
    PROCESS_FORK,
    PROCESS_EXIT,
    FILE_OPEN,
    FILE_CLOSE,
    FILE_WRITE,
    FILE_CREATE,
    FILE_DELETE,
    FILE_RENAME,
    SECURITY_ALERT
};

class EventLoggerEngine {
public:
    EventLoggerEngine();
    ~EventLoggerEngine();
    
    bool initialize();
    
    // Remote logging configuration
    bool enableRemoteLogging(const std::string& serverHost, int serverPort = 514);
    void disableRemoteLogging();
    bool isRemoteLoggingEnabled() const;
    
    // Logging functions for endpoint security events
    void logProcessEvent(const std::string& eventType, const std::string& processName, 
                        const std::string& processPath, const std::string& details);
    void logFileEvent(const std::string& eventType, const std::string& processName, 
                     const std::string& processPath, const std::string& filePath, 
                     const std::string& details = "");
    void logSecurityEvent(const std::string& alertType, const std::string& details);
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Singleton access
EventLoggerEngine& getGlobalLogger();

} // namespace EventLogger

#endif // EVENT_LOGGER_H
