//
// macOS Endpoint Security Monitor
// Simple, standalone endpoint security monitoring with remote logging
//

#include <iostream>
#include <memory>
#include <string>
#include <atomic>
#include <csignal>
#include <thread>
#include <chrono>
#include <getopt.h>
#include <unistd.h>

// Objective-C++ support
#import <Foundation/Foundation.h>

// Endpoint Security Framework
#include <EndpointSecurity/EndpointSecurity.h>

// Shared components
#include "libs/event_logger/EventLogger.h"
#include "debug_logging.h"
#include "libs/remote_logging/RemoteLogger.h"

// Global state
static std::atomic<bool> g_shouldStop(false);

// Configuration
struct MonitorConfig {
    std::string remoteLogServer;
    int remoteLogPort = 514;
    bool enableRemoteLogging = false;
    bool showHelp = false;
    int verboseLevel = 0;
};

// Signal handler
void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        DEBUG_LOG_INFO("Received termination signal, initiating shutdown");
        g_shouldStop.store(true);
    }
}

// Helper to extract PID from audit token
static pid_t extract_pid_from_audit_token(const audit_token_t& token) {
    return (pid_t)token.val[5];
}

// Simple endpoint security monitor class
class EndpointSecurityMonitor {
private:
    es_client_t* m_esClient = nullptr;
    EventLogger::EventLoggerEngine* m_logger = nullptr;
    
public:
    bool initialize(const MonitorConfig& config) {
        DEBUG_LOG_INFO("Initializing macOS Endpoint Security Monitor");
        
        // Initialize logger
        m_logger = &EventLogger::getGlobalLogger();
        m_logger->initialize();
        
        // Configure remote logging if requested
        if (config.enableRemoteLogging) {
            if (m_logger->enableRemoteLogging(config.remoteLogServer, config.remoteLogPort)) {
                DEBUG_LOG_INFO("Remote logging enabled to %s:%d", 
                             config.remoteLogServer.c_str(), config.remoteLogPort);
            } else {
                DEBUG_LOG_WARNING("Failed to enable remote logging");
            }
        }
        
        // Initialize endpoint security
        return initializeEndpointSecurity();
    }
    
    bool initializeEndpointSecurity() {
        DEBUG_LOG_INFO("Creating endpoint security client");
        
        // Define events to monitor
        es_event_type_t events[] = {
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_OPEN,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_UNLINK,
            ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_MMAP,
            ES_EVENT_TYPE_NOTIFY_SIGNAL
        };
        
        // Create endpoint security client
        es_new_client_result_t result = es_new_client(&m_esClient, ^(es_client_t *client, const es_message_t *message) {
            (void)client;
            handleEndpointSecurityEvent(message);
        });
        
        if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
            DEBUG_LOG_ERROR("Failed to create endpoint security client: %d", result);
            return false;
        }
        
        // Subscribe to events
        es_return_t subscribe_result = es_subscribe(m_esClient, events, sizeof(events) / sizeof(events[0]));
        if (subscribe_result != ES_RETURN_SUCCESS) {
            DEBUG_LOG_ERROR("Failed to subscribe to endpoint security events: %d", subscribe_result);
            es_delete_client(m_esClient);
            m_esClient = nullptr;
            return false;
        }
        
        DEBUG_LOG_INFO("Endpoint security client initialized successfully");
        return true;
    }
    
    void handleEndpointSecurityEvent(const es_message_t* message) {
        if (!message || !m_logger) return;
        
        switch (message->event_type) {
            case ES_EVENT_TYPE_NOTIFY_EXEC: {
                const es_event_exec_t* exec = &message->event.exec;
                std::string processPath = exec->target->executable->path.data ? 
                    std::string(exec->target->executable->path.data, exec->target->executable->path.length) : "unknown";
                std::string processName = processPath.substr(processPath.find_last_of('/') + 1);
                
                m_logger->logProcessEvent("PROCESS_EXEC", processName, processPath, 
                    "Process executed - PID: " + std::to_string(extract_pid_from_audit_token(exec->target->audit_token)));
                break;
            }
            
            case ES_EVENT_TYPE_NOTIFY_FORK: {
                const es_event_fork_t* fork = &message->event.fork;
                pid_t parent_pid = extract_pid_from_audit_token(message->process->audit_token);
                pid_t child_pid = extract_pid_from_audit_token(fork->child->audit_token);
                
                m_logger->logProcessEvent("PROCESS_FORK", "fork", "system", 
                    "Process forked - Parent PID: " + std::to_string(parent_pid) + ", Child PID: " + std::to_string(child_pid));
                break;
            }
            
            case ES_EVENT_TYPE_NOTIFY_EXIT: {
                const es_event_exit_t* exit = &message->event.exit;
                pid_t pid = extract_pid_from_audit_token(message->process->audit_token);
                
                m_logger->logProcessEvent("PROCESS_EXIT", "exit", "system", 
                    "Process exited - PID: " + std::to_string(pid) + ", Exit code: " + std::to_string(exit->stat));
                break;
            }
            
            case ES_EVENT_TYPE_NOTIFY_OPEN: {
                const es_event_open_t* open = &message->event.open;
                std::string filePath = open->file->path.data ? 
                    std::string(open->file->path.data, open->file->path.length) : "unknown";
                pid_t pid = extract_pid_from_audit_token(message->process->audit_token);
                
                m_logger->logFileEvent("FILE_OPEN", "open", filePath, 
                    "File opened by PID: " + std::to_string(pid));
                break;
            }
            
            case ES_EVENT_TYPE_NOTIFY_WRITE: {
                const es_event_write_t* write = &message->event.write;
                std::string filePath = write->target->path.data ? 
                    std::string(write->target->path.data, write->target->path.length) : "unknown";
                pid_t pid = extract_pid_from_audit_token(message->process->audit_token);
                
                m_logger->logFileEvent("FILE_WRITE", "write", filePath, 
                    "File written by PID: " + std::to_string(pid));
                break;
            }
            
            default:
                // Log other events at debug level
                DEBUG_LOG_ENDPOINT_SECURITY("Endpoint security event: type=%d", message->event_type);
                break;
        }
    }
    
    void run() {
        DEBUG_LOG_INFO("Starting endpoint security monitoring loop");
        
        while (!g_shouldStop.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    void shutdown() {
        DEBUG_LOG_INFO("Shutting down endpoint security monitor");
        
        if (m_esClient) {
            es_delete_client(m_esClient);
            m_esClient = nullptr;
        }
        
        if (m_logger) {
            m_logger->disableRemoteLogging();
        }
    }
    
    ~EndpointSecurityMonitor() {
        shutdown();
    }
};

// Command line parsing
MonitorConfig parseCommandLine(int argc, char* argv[]) {
    MonitorConfig config;
    
    static struct option long_options[] = {
        {"remote-log-server", required_argument, 0, 'r'},
        {"remote-log-port", required_argument, 0, 'p'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "r:p:vh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'r':
                config.remoteLogServer = optarg;
                config.enableRemoteLogging = true;
                break;
            case 'p':
                config.remoteLogPort = std::stoi(optarg);
                break;
            case 'v':
                config.verboseLevel++;
                break;
            case 'h':
                config.showHelp = true;
                break;
            default:
                config.showHelp = true;
                break;
        }
    }
    
    return config;
}

void printUsage(const char* programName) {
    std::cout << "macOS Endpoint Security Monitor\n"
              << "Usage: " << programName << " [OPTIONS]\n"
              << "\nOptions:\n"
              << "  -r, --remote-log-server HOST   Remote syslog server hostname/IP\n"
              << "  -p, --remote-log-port PORT     Remote syslog server port (default: 514)\n"
              << "  -v, --verbose                  Enable verbose output\n"
              << "  -h, --help                     Show this help message\n"
              << "\nExamples:\n"
              << "  " << programName << " --remote-log-server 192.168.1.42\n"
              << "  " << programName << " -r 192.168.1.42 -p 514 -v\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    @autoreleasepool {
        // Parse command line
        MonitorConfig config = parseCommandLine(argc, argv);
        
        if (config.showHelp) {
            printUsage(argv[0]);
            return 0;
        }
        
        // Initialize debug logging
        debug_log_init();
        debug_log_set_level(config.verboseLevel > 0 ? DEBUG_LOG_LEVEL_ENDPOINT_SECURITY : DEBUG_LOG_LEVEL_INFO);
        
        // Set up signal handlers
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        
        DEBUG_LOG_INFO("macOS Endpoint Security Monitor starting");
        
        try {
            EndpointSecurityMonitor monitor;
            
            if (!monitor.initialize(config)) {
                DEBUG_LOG_ERROR("Failed to initialize endpoint security monitor");
                return 1;
            }
            
            monitor.run();
            
        } catch (const std::exception& e) {
            DEBUG_LOG_ERROR("Exception in monitor: %s", e.what());
            return 1;
        }
        
        DEBUG_LOG_INFO("macOS Endpoint Security Monitor shutdown complete");
        return 0;
    }
}
