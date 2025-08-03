//
// RemoteLogger.cpp - Remote Logging Client Implementation
// Sends logs to remote syslog server using UDP protocol
//

#include "RemoteLogger.h"
#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <thread>
#include <mutex>
#include <atomic>

namespace RemoteLogging {

class RemoteLoggerEngine::Impl {
public:
    RemoteLogConfig config;
    int socketFd = -1;
    struct sockaddr_in serverAddr;
    std::string hostname;
    std::string lastError;
    std::atomic<size_t> totalMessagesSent{0};
    std::atomic<size_t> failedMessages{0};
    std::atomic<bool> connected{false};
    std::mutex sendMutex;
    
    Impl() {
        // Get local hostname
        char hostBuffer[256];
        if (gethostname(hostBuffer, sizeof(hostBuffer)) == 0) {
            hostname = std::string(hostBuffer);
        } else {
            hostname = "unknown-host";
        }
    }
    
    ~Impl() {
        shutdown();
    }
    
    bool initialize(const RemoteLogConfig& cfg) {
        config = cfg;
        
        // Create UDP socket
        socketFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (socketFd < 0) {
            lastError = "Failed to create socket: " + std::string(strerror(errno));
            return false;
        }
        
        // Set socket timeout
        struct timeval timeout;
        timeout.tv_sec = config.timeoutMs / 1000;
        timeout.tv_usec = (config.timeoutMs % 1000) * 1000;
        
        if (setsockopt(socketFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
            lastError = "Failed to set socket timeout: " + std::string(strerror(errno));
            close(socketFd);
            socketFd = -1;
            return false;
        }
        
        // Set up server address
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(config.serverPort);
        
        // Try to parse as IP address first
        if (inet_aton(config.serverHost.c_str(), &serverAddr.sin_addr) == 0) {
            // Not an IP address, try hostname resolution
            struct hostent* hostEntry = gethostbyname(config.serverHost.c_str());
            if (!hostEntry) {
                lastError = "Failed to resolve hostname: " + config.serverHost;
                close(socketFd);
                socketFd = -1;
                return false;
            }
            memcpy(&serverAddr.sin_addr.s_addr, hostEntry->h_addr_list[0], hostEntry->h_length);
        }
        
        connected = true;
        lastError.clear();
        
        
        return true;
    }
    
    void shutdown() {
        if (socketFd >= 0) {
            close(socketFd);
            socketFd = -1;
        }
        connected = false;
    }
    
    std::string formatSyslogMessage(LogLevel level, const std::string& tag, const std::string& message) {
        return formatSyslogMessageWithProgramName(config.appName, level, tag, message);
    }
    
    std::string formatSyslogMessageWithProgramName(const std::string& programName, LogLevel level, const std::string& tag, const std::string& message) {
        // RFC 3164 syslog format: <priority>timestamp hostname tag: message
        
        // Calculate priority (facility * 8 + severity)
        int facilityNum = getFacilityNumber(config.facility);
        int priority = facilityNum * 8 + static_cast<int>(level);
        
        // Get current timestamp
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream timestamp;
        timestamp << std::put_time(std::localtime(&time_t), "%b %d %H:%M:%S");
        
        // Build syslog message
        std::stringstream syslogMessage;
        syslogMessage << "<" << priority << ">"
                     << timestamp.str() << " ";
        
        if (config.useHostnamePrefix) {
            syslogMessage << hostname << " ";
        }
        
        syslogMessage << programName;
        if (!tag.empty()) {
            syslogMessage << "[" << tag << "]";
        }
        syslogMessage << ": " << message;
        
        return syslogMessage.str();
    }
    
    bool sendMessage(const std::string& syslogMessage) {
        std::lock_guard<std::mutex> lock(sendMutex);
        
        if (socketFd < 0 || !connected) {
            failedMessages++;
            if (config.fallbackToLocal) {
                std::cout << "[REMOTE_LOG_FAILED] " << syslogMessage << std::endl;
            }
            return false;
        }
        
        ssize_t sent = sendto(socketFd, syslogMessage.c_str(), syslogMessage.length(),
                             0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        
        if (sent < 0) {
            lastError = "Failed to send message: " + std::string(strerror(errno));
            failedMessages++;
            
            if (config.fallbackToLocal) {
                std::cout << "[REMOTE_LOG_FAILED] " << syslogMessage << std::endl;
            }
            return false;
        }
        
        totalMessagesSent++;
        return true;
    }
    
    int getFacilityNumber(const std::string& facility) {
        if (facility == "kern") return 0;
        if (facility == "user") return 1;
        if (facility == "mail") return 2;
        if (facility == "daemon") return 3;
        if (facility == "auth") return 4;
        if (facility == "syslog") return 5;
        if (facility == "lpr") return 6;
        if (facility == "news") return 7;
        if (facility == "uucp") return 8;
        if (facility == "cron") return 9;
        if (facility == "authpriv") return 10;
        if (facility == "ftp") return 11;
        if (facility == "local0") return 16;
        if (facility == "local1") return 17;
        if (facility == "local2") return 18;
        if (facility == "local3") return 19;
        if (facility == "local4") return 20;
        if (facility == "local5") return 21;
        if (facility == "local6") return 22;
        if (facility == "local7") return 23;
        return 16; // Default to local0
    }
};

RemoteLoggerEngine::RemoteLoggerEngine() : pImpl(std::make_unique<Impl>()) {}
RemoteLoggerEngine::~RemoteLoggerEngine() = default;

bool RemoteLoggerEngine::initialize(const RemoteLogConfig& config) {
    return pImpl->initialize(config);
}

void RemoteLoggerEngine::shutdown() {
    pImpl->shutdown();
}

bool RemoteLoggerEngine::logMessage(LogLevel level, const std::string& message) {
    return logMessage(level, "", message);
}

bool RemoteLoggerEngine::logMessage(LogLevel level, const std::string& tag, const std::string& message) {
    if (!pImpl->connected) {
        return false;
    }
    
    std::string syslogMessage = pImpl->formatSyslogMessage(level, tag, message);
    return pImpl->sendMessage(syslogMessage);
}

bool RemoteLoggerEngine::logEvent(const std::string& eventType, const std::string& processName,
                                 const std::string& processPath, const std::string& details) {
    std::stringstream eventMessage;
    eventMessage << "EVENT=" << eventType 
                << " PROC=" << processName
                << " PATH=" << processPath
                << " DETAILS=" << details;
    
    LogLevel level = LogLevel::INFO;
    if (eventType.find("ERROR") != std::string::npos || 
        eventType.find("SECURITY") != std::string::npos) {
        level = LogLevel::ERROR;
    } else if (eventType.find("WARN") != std::string::npos) {
        level = LogLevel::WARNING;
    }
    
    return logMessage(level, "EVENT", eventMessage.str());
}

bool RemoteLoggerEngine::logEventWithProgramName(const std::string& programName, const std::string& eventType, 
                                                 const std::string& processName, const std::string& processPath, 
                                                 const std::string& details) {
    if (!pImpl->connected) {
        return false;
    }
    
    std::stringstream eventMessage;
    eventMessage << "EVENT=" << eventType 
                << " PROC=" << processName
                << " PATH=" << processPath
                << " DETAILS=" << details;
    
    LogLevel level = LogLevel::INFO;
    if (eventType.find("ERROR") != std::string::npos || 
        eventType.find("SECURITY") != std::string::npos) {
        level = LogLevel::ERROR;
    } else if (eventType.find("WARN") != std::string::npos) {
        level = LogLevel::WARNING;
    }
    
    std::string syslogMessage = pImpl->formatSyslogMessageWithProgramName(programName, level, "EVENT", eventMessage.str());
    return pImpl->sendMessage(syslogMessage);
}

bool RemoteLoggerEngine::isConnected() const {
    return pImpl->connected;
}

std::string RemoteLoggerEngine::getLastError() const {
    return pImpl->lastError;
}

size_t RemoteLoggerEngine::getTotalMessagesSent() const {
    return pImpl->totalMessagesSent;
}

size_t RemoteLoggerEngine::getFailedMessages() const {
    return pImpl->failedMessages;
}

RemoteLoggerEngine& getGlobalRemoteLogger() {
    static RemoteLoggerEngine instance;
    return instance;
}

void forwardEventToRemoteLogger(const std::string& eventType, 
                               const std::string& processName,
                               const std::string& processPath, 
                               const std::string& details) {
    auto& remoteLogger = getGlobalRemoteLogger();
    if (remoteLogger.isConnected()) {
        remoteLogger.logEvent(eventType, processName, processPath, details);
    }
}

} // namespace RemoteLogging
