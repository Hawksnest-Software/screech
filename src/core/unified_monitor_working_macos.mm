//
// unified_monitor_working_macos.mm - macOS-specific Unified Monitoring System (Objective-C++)
// Properly handles conditional compilation for all features including VPN mimicry
//

#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <csignal>
#include <string>
#include <cstring>
#include <getopt.h>

// Include debug logging system (moved from obfuscation)
#include "debug_logging.h"
#include "EventLogger.h"

// Include all monitoring libraries based on enabled features
#ifdef ENABLE_ENDPOINT_SECURITY
#include "libs/macos/process_monitor/ProcessMonitor.h"
#include "libs/macos/file_monitor/FileMonitor.h"
#endif
#ifdef ENABLE_LIBPCAP
#include "NetworkMonitor.h"
#endif
#ifdef ENABLE_NETWORK_EXTENSION
#include "libs/macos/native_network_extension_monitor/include/screech_macos_network.h"

// VPN Mimicry Framework for stealth on macOS Network Extension
#ifdef ENABLE_VPN_MIMICRY
#include "screech_network_extension/Shared/VPNMimicryFramework.h"
#include "screech_network_extension/MainApp/ScreechMainApp.h"
#endif

// Simple wrapper class for MacOSNetworkMonitor to make compilation work
class MacOSNetworkMonitor {
private:
    std::atomic<bool> isRunning{false};
public:
    MacOSNetworkMonitor() = default;
    ~MacOSNetworkMonitor() = default;
    bool start() { 
        isRunning = true; 
        DEBUG_LOG_INFO("MacOSNetworkMonitor started (stub)");
        return true; 
    }
    void stop() { 
        isRunning = false; 
        DEBUG_LOG_INFO("MacOSNetworkMonitor stopped (stub)");
    }
    bool isMonitoring() const { return isRunning; }
};
#endif
#ifdef ENABLE_OBFUSCATION
#include "obfuscation_engine.h"
#include "obfuscation_config.h"
#endif

// Global flag for graceful shutdown
std::atomic<bool> shouldStop(false);

void signalHandler(int signal) {
    if (signal == SIGINT) {
DEBUG_LOG_INFO("\nReceived SIGINT, stopping unified monitoring...");
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
    bool libpcapActive;
#endif
#ifdef ENABLE_NETWORK_EXTENSION
    MacOSNetworkMonitor networkExtensionMonitor;
#ifdef ENABLE_VPN_MIMICRY
    VPNMimicryService* vpnMimicryService;
    ScreechMainApp* screechMainApp;
#endif
#endif
#ifdef ENABLE_OBFUSCATION
    bool obfuscationInitialized;
#endif
    
    std::atomic<bool> isRunning{false};
    
public:
    UnifiedMonitor() = default;
    
    bool initialize() {
DEBUG_LOG_INFO("Initializing Unified Monitoring System...");
        
#ifdef ENABLE_OBFUSCATION
        // Initialize security engine first for protection (Priority 1: Evading Detection)
        init_obfuscation_engine();
        obfuscationInitialized = true;
DEBUG_LOG_INFO("✓ Security engine initialized (Anti-Debug/Anti-VM)");
#endif

#ifdef ENABLE_ENDPOINT_SECURITY
        // Initialize endpoint security monitors (Priority 2: Gathering Information)
        if (!processMonitor.initialize()) {
            DEBUG_LOG_ERROR("Failed to initialize process monitor");
            return false;
        }
        
        // Set up process event logging callback
        processMonitor.setEventCallback([](const ProcessMonitor::ProcessEvent& event) {
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
            EventLogger::getGlobalLogger().logProcessEvent(eventTypeStr, event.process.name, event.process.path, event.details);
        });
        
DEBUG_LOG_INFO("✓ Process monitor initialized");
        
        if (!fileMonitor.initialize()) {
            DEBUG_LOG_ERROR("Failed to initialize file monitor");
            return false;
        }
        
        // Set up file event logging callback
        fileMonitor.setEventCallback([](const FileMonitor::FileEvent& event) {
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
            EventLogger::getGlobalLogger().logFileEvent(eventTypeStr, event.process.name, event.process.path, event.filePath, event.details);
        });
        
DEBUG_LOG_INFO("✓ File monitor initialized");
#endif

#ifdef ENABLE_NETWORK_EXTENSION
        // Initialize network extension monitor (macOS native)
        if (!networkExtensionMonitor.start()) {
            DEBUG_LOG_ERROR("Failed to initialize network extension monitor");
            return false;
        }
DEBUG_LOG_INFO("✓ NetworkExtension monitor initialized");

#ifdef ENABLE_VPN_MIMICRY
        // Initialize VPN mimicry service for stealth (Priority 1: Evading Detection)
        vpnMimicryService = [VPNMimicryService sharedService];
        [vpnMimicryService loadClientProfile:VPNClientTypeExpressVPN];
        DEBUG_LOG_INFO("✓ VPN mimicry service initialized (ExpressVPN profile)");
        
        // Initialize Screech main app for macOS
        screechMainApp = [[ScreechMainApp alloc] init];
        DEBUG_LOG_INFO("✓ Screech main app initialized");
#endif
#endif

#ifdef ENABLE_LIBPCAP
        // Initialize libpcap monitor (cross-platform)
        libpcapActive = false;
DEBUG_LOG_INFO("✓ Libpcap network monitor initialized");
#endif
        
DEBUG_LOG_INFO("All enabled monitoring engines initialized successfully");
        return true;
    }
    
    bool start() {
DEBUG_LOG_INFO("Starting Unified Monitoring System...");
        
#ifdef ENABLE_OBFUSCATION
        if (obfuscationInitialized) {
DEBUG_LOG_INFO("✓ Security engine started");
        }
#endif

#ifdef ENABLE_ENDPOINT_SECURITY
        if (!processMonitor.start()) {
            DEBUG_LOG_ERROR("Failed to start process monitor");
            return false;
        }
DEBUG_LOG_INFO("✓ Process monitor started");
        
        if (!fileMonitor.start()) {
            DEBUG_LOG_ERROR("Failed to start file monitor");
            return false;
        }
DEBUG_LOG_INFO("✓ File monitor started");
#endif

#ifdef ENABLE_LIBPCAP
        if (start_network_monitoring("any")) {
            libpcapActive = true;
DEBUG_LOG_INFO("✓ Libpcap network monitor started");
        } else {
            DEBUG_LOG_ERROR("Failed to start libpcap network monitor");
            return false;
        }
#endif
        
DEBUG_LOG_INFO("All enabled monitoring engines started successfully");
        isRunning = true;
        return true;
    }
    
    void stop() {
DEBUG_LOG_INFO("Stopping Unified Monitoring System...");
        isRunning = false;
        
#ifdef ENABLE_ENDPOINT_SECURITY
        processMonitor.stop();
        fileMonitor.stop();
DEBUG_LOG_INFO("✓ Endpoint security monitors stopped");
#endif

#ifdef ENABLE_NETWORK_EXTENSION
        networkExtensionMonitor.stop();
DEBUG_LOG_INFO("✓ NetworkExtension monitor stopped");
#endif

#ifdef ENABLE_LIBPCAP
        if (libpcapActive) {
            stop_network_monitoring();
            libpcapActive = false;
DEBUG_LOG_INFO("✓ Libpcap network monitor stopped");
        }
#endif
        
DEBUG_LOG_INFO("Unified monitoring system stopped gracefully");
    }
    
    bool isMonitoringActive() const {
        return isRunning;
    }
    
    void displayStatus() {
DEBUG_LOG_INFO("=== Unified Monitor Status ===");
        
#ifdef ENABLE_OBFUSCATION
        if (obfuscationInitialized) {
            DEBUG_LOG_INFO("Security Engine: ACTIVE");
        } else {
            DEBUG_LOG_INFO("Security Engine: INACTIVE");
        }
#endif

#ifdef ENABLE_ENDPOINT_SECURITY
        // Process and file monitors are always running if initialized
        DEBUG_LOG_INFO("Process Monitor: ACTIVE");
        DEBUG_LOG_INFO("File Monitor: ACTIVE");
#endif

#ifdef ENABLE_NETWORK_EXTENSION
        if (networkExtensionMonitor.isMonitoring()) {
            DEBUG_LOG_INFO("NetworkExtension Monitor: ACTIVE");
        } else {
            DEBUG_LOG_INFO("NetworkExtension Monitor: INACTIVE");
        }
#endif

#ifdef ENABLE_LIBPCAP
        if (libpcapActive) {
            DEBUG_LOG_INFO("Libpcap Monitor: ACTIVE");
        } else {
            DEBUG_LOG_INFO("Libpcap Monitor: INACTIVE");
        }
#endif

DEBUG_LOG_INFO("==============================");
    }
};

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n";
    std::cout << "\nObfuscation Configuration Options:\n";
    std::cout << "  --obfuscation=LEVEL              Set obfuscation level (minimal, moderate, full)\n";
    std::cout << "  --disable-integrity              Disable integrity monitoring thread\n";
    std::cout << "  --disable-detection              Disable all detection mechanisms\n";
    std::cout << "  --disable-syscalls               Disable direct syscall obfuscation\n";
    std::cout << "  --enable-ptrace                  Enable ptrace protection\n";
    std::cout << "\nIndividual Feature Controls:\n";
    std::cout << "  --enable-function-pointers       Enable function pointer obfuscation\n";
    std::cout << "  --enable-anti-disassembly        Enable anti-disassembly code\n";
    std::cout << "  --enable-syscall-randomization   Enable syscall randomization\n";
    std::cout << "  --enable-debugger-detection      Enable debugger detection\n";
    std::cout << "  --enable-vm-detection            Enable VM detection\n";
    std::cout << "  --enable-env-checks              Enable environment checks\n";
    std::cout << "  --enable-integrity-monitoring    Enable integrity monitoring thread\n";
    std::cout << "  --enable-variant-generation      Enable function variant generation\n";
    std::cout << "  --enable-timing-obfuscation      Enable timing obfuscation\n";
    std::cout << "  --enable-direct-syscalls         Enable direct syscall obfuscation\n";
    std::cout << "  --enable-ptrace-protection       Enable ptrace protection\n";
    std::cout << "  --enable-anti-debug-ptrace       Enable anti-debug ptrace\n";
    std::cout << "  --help                           Show this help message\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " --obfuscation=minimal\n";
    std::cout << "  " << program_name << " --obfuscation=moderate --disable-integrity\n";
    std::cout << "  " << program_name << " --obfuscation=minimal --enable-debugger-detection\n";
}

int main(int argc, char* argv[]) {
    // Set default obfuscation configuration before parsing arguments
#ifdef ENABLE_OBFUSCATION
    obfuscation_config_init_minimal();  // Start with safest configuration
#endif
    
    // Parse command line arguments
    static struct option long_options[] = {
        {"obfuscation", required_argument, 0, 'o'},
        {"disable-integrity", no_argument, 0, 'i'},
        {"disable-detection", no_argument, 0, 'd'},
        {"disable-syscalls", no_argument, 0, 's'},
        {"enable-ptrace", no_argument, 0, 'p'},
        // Individual feature enables
        {"enable-function-pointers", no_argument, 0, 1001},
        {"enable-anti-disassembly", no_argument, 0, 1002},
        {"enable-syscall-randomization", no_argument, 0, 1003},
        {"enable-debugger-detection", no_argument, 0, 1004},
        {"enable-vm-detection", no_argument, 0, 1005},
        {"enable-env-checks", no_argument, 0, 1006},
        {"enable-integrity-monitoring", no_argument, 0, 1007},
        {"enable-variant-generation", no_argument, 0, 1008},
        {"enable-timing-obfuscation", no_argument, 0, 1009},
        {"enable-direct-syscalls", no_argument, 0, 1010},
        {"enable-ptrace-protection", no_argument, 0, 1011},
        {"enable-anti-debug-ptrace", no_argument, 0, 1012},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "o:idsh", long_options, nullptr)) != -1) {
        switch (c) {
            case 'o':
#ifdef ENABLE_OBFUSCATION
                if (strcmp(optarg, "minimal") == 0) {
                    obfuscation_config_init_minimal();
                } else if (strcmp(optarg, "moderate") == 0) {
                    obfuscation_config_init_moderate();
                } else if (strcmp(optarg, "full") == 0) {
                    obfuscation_config_init_full();
                } else {
                    std::cerr << "Invalid obfuscation level: " << optarg << std::endl;
                    print_usage(argv[0]);
                    return 1;
                }
#endif
                break;
            case 'i':
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_integrity_monitoring = false;
                std::cout << "Integrity monitoring disabled\n";
#endif
                break;
            case 'd':
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_debugger_detection = false;
                g_obfuscation_config.enable_vm_detection = false;
                g_obfuscation_config.enable_env_checks = false;
                std::cout << "All detection mechanisms disabled\n";
#endif
                break;
            case 's':
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_direct_syscalls = false;
                g_obfuscation_config.enable_ptrace_protection = false;
                g_obfuscation_config.enable_anti_debug_ptrace = false;
                std::cout << "Direct syscall obfuscation disabled\n";
#endif
                break;
            case 'p':
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_ptrace_protection = true;
                g_obfuscation_config.enable_anti_debug_ptrace = true;
                std::cout << "Ptrace protection enabled\n";
#endif
                break;
            case 1001: // enable-function-pointers
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_function_pointer_obfuscation = true;
                std::cout << "Function pointer obfuscation enabled\n";
#endif
                break;
            case 1002: // enable-anti-disassembly
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_anti_disassembly = true;
                std::cout << "Anti-disassembly enabled\n";
#endif
                break;
            case 1003: // enable-syscall-randomization
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_syscall_randomization = true;
                std::cout << "Syscall randomization enabled\n";
#endif
                break;
            case 1004: // enable-debugger-detection
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_debugger_detection = true;
                std::cout << "Debugger detection enabled\n";
#endif
                break;
            case 1005: // enable-vm-detection
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_vm_detection = true;
                std::cout << "VM detection enabled\n";
#endif
                break;
            case 1006: // enable-env-checks
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_env_checks = true;
                std::cout << "Environment checks enabled\n";
#endif
                break;
            case 1007: // enable-integrity-monitoring
#ifdef ENABLE_OBFUSCATION
    #ifdef ENABLE_INTEGRITY_MONITORING
                g_obfuscation_config.enable_integrity_monitoring = true;
                std::cout << "Integrity monitoring enabled\n";
    #else
                std::cerr << "Integrity monitoring not available (disabled at compile time)\n";
    #endif
#endif
                break;
            case 1008: // enable-variant-generation
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_variant_generation = true;
                std::cout << "Variant generation enabled\n";
#endif
                break;
            case 1009: // enable-timing-obfuscation
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_timing_obfuscation = true;
                std::cout << "Timing obfuscation enabled\n";
#endif
                break;
            case 1010: // enable-direct-syscalls
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_direct_syscalls = true;
                std::cout << "Direct syscalls enabled\n";
#endif
                break;
            case 1011: // enable-ptrace-protection
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_ptrace_protection = true;
                std::cout << "Ptrace protection enabled\n";
#endif
                break;
            case 1012: // enable-anti-debug-ptrace
#ifdef ENABLE_OBFUSCATION
                g_obfuscation_config.enable_anti_debug_ptrace = true;
                std::cout << "Anti-debug ptrace enabled\n";
#endif
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case '?':
                print_usage(argv[0]);
                return 1;
            default:
                break;
        }
    }
    
    // Install signal handler for graceful shutdown
    std::signal(SIGINT, signalHandler);
    
DEBUG_LOG_INFO("Screech Unified Monitor v2.0 - macOS Build");
DEBUG_LOG_INFO("Configuration: macOS with VPN Mimicry and Zoom Entitlements");
    
    // Create and initialize the unified monitor
    UnifiedMonitor monitor;
    
    if (!monitor.initialize()) {
        DEBUG_LOG_ERROR("Failed to initialize unified monitor");
        return 1;
    }
    
    if (!monitor.start()) {
        DEBUG_LOG_ERROR("Failed to start unified monitor");
        return 1;
    }
    
DEBUG_LOG_INFO("Unified monitoring is now active. Press Ctrl+C to stop.");
    
    // Main monitoring loop
    while (!shouldStop && monitor.isMonitoringActive()) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        monitor.displayStatus();
    }
    
    // Graceful shutdown
    monitor.stop();
DEBUG_LOG_INFO("Screech unified monitor terminated");
    
    return 0;
}
