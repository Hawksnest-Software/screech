//
// RemoteLogger.h - Remote Logging Client
// Sends logs to remote syslog server with hostname-based organization
//

#ifndef REMOTE_LOGGER_H
#define REMOTE_LOGGER_H

#include <string>
#include <memory>
#include <functional>

namespace RemoteLogging {

enum class LogLevel {
    EMERGENCY = 0,    // System is unusable
    ALERT = 1,        // Action must be taken immediately
    CRITICAL = 2,     // Critical conditions
    ERROR = 3,        // Error conditions
    WARNING = 4,      // Warning conditions
    NOTICE = 5,       // Normal but significant condition
    INFO = 6,         // Informational messages
    DEBUG_LEVEL = 7   // Debug-level messages
};

struct RemoteLogConfig {
    std::string serverHost;
    int serverPort = 514;           // Standard syslog port
    std::string facility = "local0"; // Syslog facility
    std::string appName = "monitor";
    bool useHostnamePrefix = true;   // Prefix logs with hostname
    int timeoutMs = 5000;           // Connection timeout
    bool fallbackToLocal = true;    // Fall back to local logging on failure
};

class RemoteLoggerEngine {
public:
    RemoteLoggerEngine();
    ~RemoteLoggerEngine();
    
    bool initialize(const RemoteLogConfig& config);
    void shutdown();
    
    // Main logging function
    bool logMessage(LogLevel level, const std::string& message);
    bool logMessage(LogLevel level, const std::string& tag, const std::string& message);
    
    // EventLogger integration - format and send event logs
    bool logEvent(const std::string& eventType, const std::string& processName,
                  const std::string& processPath, const std::string& details);
    
    // Log event with custom program name for dynamic file routing
    bool logEventWithProgramName(const std::string& programName, const std::string& eventType, 
                                 const std::string& processName, const std::string& processPath, 
                                 const std::string& details);
    
    // Health check
    bool isConnected() const;
    std::string getLastError() const;
    
    // Statistics
    size_t getTotalMessagesSent() const;
    size_t getFailedMessages() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Singleton access for global use
RemoteLoggerEngine& getGlobalRemoteLogger();

// Helper function to convert EventLogger events to remote logs
void forwardEventToRemoteLogger(const std::string& eventType, 
                               const std::string& processName,
                               const std::string& processPath, 
                               const std::string& details);

} // namespace RemoteLogging

#endif // REMOTE_LOGGER_H
