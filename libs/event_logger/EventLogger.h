//
// EventLogger.h - Centralized Event Logging Library
// Creates log files based on monitored application names
//

#ifndef EVENT_LOGGER_H
#define EVENT_LOGGER_H

#include <string>
#include <functional>
#include <memory>

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
    NETWORK_CONNECT,
    NETWORK_DISCONNECT,
    NETWORK_DATA,
    NETWORK_INTERFACE_CHANGE,
    NETWORK_DNS,
    SECURITY_ALERT
};

struct LogEvent {
    EventType type;
    std::string timestamp;
    std::string processName;
    std::string processPath;
    std::string details;
};

class EventLoggerEngine {
public:
    EventLoggerEngine();
    ~EventLoggerEngine();
    
    bool initialize();
    void setLogDirectory(const std::string& directory);
    
    // Main logging function
    void logEvent(EventType type, const std::string& processName, 
                  const std::string& processPath, const std::string& details);
    
    // Convenience functions for different event types
    void logProcessEvent(const std::string& eventType, const std::string& processName, 
                        const std::string& processPath, const std::string& details);
    void logFileEvent(const std::string& eventType, const std::string& processName, 
                     const std::string& processPath, const std::string& filePath, 
                     const std::string& details = "");
    void logNetworkEvent(const std::string& eventType, const std::string& processName, 
                        const std::string& processPath, const std::string& connectionDetails);
    void logSecurityEvent(const std::string& alertType, const std::string& details);
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Singleton access
EventLoggerEngine& getGlobalLogger();

} // namespace EventLogger

#endif // EVENT_LOGGER_H
