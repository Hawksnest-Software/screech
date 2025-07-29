//
// unified_monitor.cpp - Unified Monitoring System
// Integrates process, file, network monitoring with obfuscation
//

#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <csignal>
#include <fstream>
#include <iomanip>
#include <sstream>

// Include all monitoring libraries based on enabled features
#ifdef ENABLE_ENDPOINT_SECURITY
#include "libs/macos/process_monitor/ProcessMonitor.h"
#include "libs/macos/file_monitor/FileMonitor.h"
#endif
#ifdef ENABLE_LIBPCAP
#include "libs/libpcap_monitor/NetworkMonitor.h"
#endif
#ifdef ENABLE_NETWORK_EXTENSION
#include "libs/macos/native_network_extension_monitor/include/screech_macos_network.h"
#endif
#ifdef ENABLE_OBFUSCATION
#include "libs/obfuscation/ObfuscationEngine.h"
#endif

// Global flag for graceful shutdown
static std::atomic<bool> shouldStop(false);

void signalHandler(int signal) {
    if (signal == SIGINT) {
        std::cout << "\nReceived SIGINT, stopping unified monitoring..." << std::endl;
        shouldStop = true;
    }
}

class UnifiedMonitor {
private:
#ifdef ENABLE_ENDPOINT_SECURITY
    ProcessMonitor::ProcessMonitorEngine processMonitor;
    FileMonitor::FileMonitorEngine fileMonitor;
#endif
#ifdef ENABLE_LIBPCAP
    LibpcapNetworkMonitor::NetworkMonitorEngine libpcapNetworkMonitor;
#endif
#ifdef ENABLE_NETWORK_EXTENSION
    MacOSNetworkMonitor networkExtensionMonitor;
#endif
#ifdef ENABLE_OBFUSCATION
    ObfuscationEngine::SecurityEngine securityEngine;
#endif
    
    std::atomic<bool> isRunning{false};
    
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
        // Skip events from our own monitoring process
        if (processName.find("unified_monitor") != std::string::npos ||
            processName.find("enhanced") != std::string::npos ||
            processPath.find("/tmp/") != std::string::npos) {
            return;
        }
        
        std::string appName = extractAppBundleName(processPath);
        std::string timestamp = getTimestampForFilename();
        std::string logFileName = "monitor_" + timestamp + "_" + appName + ".log";
        
        std::ofstream logFile(logFileName, std::ios::app);
        if (logFile.is_open()) {
            logFile << "[" << getCurrentTimestamp() << "] "
                   << eventType << "|"
                   << "PROC:" << processName << "|"
                   << "PATH:" << processPath << "|"
                   << "DETAILS:" << details << std::endl;
            logFile.close();
        }
        
        // Also log to console (but not for our own process)
        std::cout << "[" << getCurrentTimestamp() << "] " << eventType << ": "
                  << processName << " -> " << logFileName;
        if (!details.empty()) {
            std::cout << " - " << details;
        }
        std::cout << std::endl;
    }
    
public:
    UnifiedMonitor() = default;
    
    bool initialize() {
        std::cout << "Initializing Unified Monitoring System..." << std::endl;
        
#ifdef ENABLE_OBFUSCATION
        // Initialize security engine first for protection
        if (!securityEngine.initialize()) {
            std::cerr << "Failed to initialize security engine" << std::endl;
            return false;
        }
        
        // Set up threat detection callback
        securityEngine.setThreatCallback([this](const ObfuscationEngine::ThreatInfo& threat) {
            std::string threatType;
            switch (threat.type) {
                case ObfuscationEngine::ThreatInfo::DEBUGGER_DETECTED:
                    threatType = "DEBUGGER_DETECTED";
                    break;
                case ObfuscationEngine::ThreatInfo::VM_DETECTED:
                    threatType = "VM_DETECTED";
                    break;
                case ObfuscationEngine::ThreatInfo::INTEGRITY_VIOLATION:
                    threatType = "INTEGRITY_VIOLATION";
                    break;
                case ObfuscationEngine::ThreatInfo::HOOK_DETECTED:
                    threatType = "HOOK_DETECTED";
                    break;
                case ObfuscationEngine::ThreatInfo::ANALYSIS_TOOL_DETECTED:
                    threatType = "ANALYSIS_TOOL_DETECTED";
                    break;
            }
            
            std::cout << "[SECURITY ALERT] " << threatType << ": " << threat.details 
                      << " (Severity: " << threat.severityLevel << ")" << std::endl;
        });
        
        // Initialize monitoring engines
        if (!processMonitor.initialize()) {
            std::cerr << "Failed to initialize process monitor" << std::endl;
            return false;
        }
        
        if (!fileMonitor.initialize()) {
            std::cerr << "Failed to initialize file monitor" << std::endl;
            return false;
        }
        
        if (!networkMonitor.initialize()) {
            std::cerr << "Failed to initialize network monitor" << std::endl;
            return false;
        }
        
        // Set up event callbacks
        processMonitor.setEventCallback([this](const ProcessMonitor::ProcessEvent& event) {
            std::string eventTypeStr;
            switch (event.type) {
                case ProcessMonitor::ProcessEvent::EXEC:
                    eventTypeStr = "PROCESS_EXEC";
                    break;
                case ProcessMonitor::ProcessEvent::FORK:
                    eventTypeStr = "PROCESS_FORK";
                    break;
                case ProcessMonitor::ProcessEvent::EXIT:
                    eventTypeStr = "PROCESS_EXIT";
                    break;
            }
            
            writeEventToLog(eventTypeStr, event.process.name, event.process.path, event.details);
        });
        
        fileMonitor.setEventCallback([this](const FileMonitor::FileEvent& event) {
            std::string eventTypeStr;
            switch (event.type) {
                case FileMonitor::FileEvent::OPEN:
                    eventTypeStr = "FILE_OPEN";
                    break;
                case FileMonitor::FileEvent::CLOSE:
                    eventTypeStr = "FILE_CLOSE";
                    break;
                case FileMonitor::FileEvent::WRITE:
                    eventTypeStr = "FILE_WRITE";
                    break;
                case FileMonitor::FileEvent::CREATE:
                    eventTypeStr = "FILE_CREATE";
                    break;
                case FileMonitor::FileEvent::DELETE:
                    eventTypeStr = "FILE_DELETE";
                    break;
                case FileMonitor::FileEvent::RENAME:
                    eventTypeStr = "FILE_RENAME";
                    break;
            }
            
            std::string details = "file:" + event.filePath;
            if (!event.details.empty()) {
                details += " " + event.details;
            }
            
            writeEventToLog(eventTypeStr, event.process.name, event.process.path, details);
        });
        
        networkMonitor.setEventCallback([this](const NetworkMonitor::NetworkEvent& event) {
            std::string eventTypeStr;
            switch (event.type) {
                case NetworkMonitor::NetworkEvent::CONNECTION_ESTABLISHED:
                    eventTypeStr = "NETWORK_CONNECT";
                    break;
                case NetworkMonitor::NetworkEvent::CONNECTION_CLOSED:
                    eventTypeStr = "NETWORK_DISCONNECT";
                    break;
                case NetworkMonitor::NetworkEvent::DATA_TRANSFER:
                    eventTypeStr = "NETWORK_DATA";
                    break;
                case NetworkMonitor::NetworkEvent::INTERFACE_CHANGE:
                    eventTypeStr = "NETWORK_INTERFACE_CHANGE";
                    break;
                case NetworkMonitor::NetworkEvent::DNS_QUERY:
                    eventTypeStr = "NETWORK_DNS";
                    break;
            }
            
            std::string details = event.connection.protocol + " " + 
                                event.connection.remoteAddress + ":" + 
                                std::to_string(event.connection.remotePort);
            if (!event.details.empty()) {
                details += " " + event.details;
            }
            
            writeEventToLog(eventTypeStr, event.process.name, event.process.path, details);
        });
        
        std::cout << "All monitoring engines initialized successfully" << std::endl;
        return true;
    }
    
    bool start() {
        if (!securityEngine.start()) {
            std::cerr << "Failed to start security engine" << std::endl;
            return false;
        }
        
        if (!processMonitor.start()) {
            std::cerr << "Failed to start process monitor" << std::endl;
            return false;
        }
        
        if (!fileMonitor.start()) {
            std::cerr << "Failed to start file monitor" << std::endl;
            return false;
        }
        
        if (!networkMonitor.start()) {
            std::cerr << "Failed to start network monitor" << std::endl;
            return false;
        }
        
        isRunning = true;
        std::cout << "Unified Monitoring System started successfully" << std::endl;
        std::cout << "Monitoring: Process Events | File Operations | Network Connections" << std::endl;
        std::cout << "Security: Anti-Debug | Anti-VM | Integrity Monitoring" << std::endl;
        return true;
    }
    
    void stop() {
        if (!isRunning) return;
        
        isRunning = false;
        
        networkMonitor.stop();
        fileMonitor.stop();
        processMonitor.stop();
        securityEngine.stop();
        
        std::cout << "Unified Monitoring System stopped" << std::endl;
    }
    
    bool isMonitoring() const {
        return isRunning;
    }
    
    void performSecurityCheck() {
        // Insert anti-disassembly barriers periodically
        securityEngine.insertAntiDisassemblyBarrier();
        
        // Check for threats
        if (securityEngine.detectDebugger()) {
            std::cout << "[SECURITY ALERT] Debugger detected!" << std::endl;
        }
        
        if (securityEngine.detectVirtualMachine()) {
            std::cout << "[SECURITY ALERT] Virtual machine detected!" << std::endl;
        }
        
        if (!securityEngine.validateCodeIntegrity()) {
            std::cout << "[SECURITY ALERT] Code integrity violation detected!" << std::endl;
        }
    }
};

int main() {
    // Register signal handler for graceful shutdown
    signal(SIGINT, signalHandler);
    
    std::cout << "Starting Unified Monitoring System" << std::endl;
    std::cout << "Integrating: Process | File | Network | Security Monitoring" << std::endl;
    std::cout << "Note: Requires proper entitlements and may need SIP configuration" << std::endl;
    
    UnifiedMonitor monitor;
    
    if (!monitor.initialize()) {
        std::cerr << "Failed to initialize unified monitor" << std::endl;
        return 1;
    }
    
    if (!monitor.start()) {
        std::cerr << "Failed to start unified monitor" << std::endl;
        return 1;
    }
    
    std::cout << "Unified monitoring active... Press Ctrl+C to stop." << std::endl;
    
    // Main monitoring loop with periodic security checks
    while (!shouldStop && monitor.isMonitoring()) {
        monitor.performSecurityCheck();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    
    monitor.stop();
    
    std::cout << "Monitoring stopped." << std::endl;
    return 0;
}
