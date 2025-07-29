//
// unified_monitor_working.cpp - Simplified Unified Monitoring System
// Properly handles conditional compilation for all features
//

#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <csignal>
#include <string>

// Include stealth logging system
#include "stealth_logging.h"

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
#if defined(TARGET_OS_MAC) && defined(ENABLE_NETWORK_EXTENSION) && defined(__OBJC__)
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
        STEALTH_LOG_INFO("MacOSNetworkMonitor started (stub)");
        return true; 
    }
    void stop() { 
        isRunning = false; 
        STEALTH_LOG_INFO("MacOSNetworkMonitor stopped (stub)");
    }
    bool isMonitoring() const { return isRunning; }
};
#endif
#ifdef ENABLE_EBPF
#include "src/platform/linux/screech_linux_ebpf.h"
#endif
#ifdef ENABLE_OBFUSCATION
#include "obfuscation_engine.h"
#endif

// Global flag for graceful shutdown
std::atomic<bool> shouldStop(false);

void signalHandler(int signal) {
    if (signal == SIGINT) {
STEALTH_LOG_INFO("\nReceived SIGINT, stopping unified monitoring...");
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
#if defined(TARGET_OS_MAC) && defined(ENABLE_NETWORK_EXTENSION) && defined(__OBJC__)
    VPNMimicryService* vpnMimicryService;
    ScreechMainApp* screechMainApp;
#endif
#endif
#ifdef ENABLE_EBPF
    LinuxEBPFMonitor ebpfMonitor;
#endif
#ifdef ENABLE_OBFUSCATION
    bool obfuscationInitialized;
#endif
    
    std::atomic<bool> isRunning{false};
    
public:
    UnifiedMonitor() = default;
    
    bool initialize() {
STEALTH_LOG_INFO("Initializing Unified Monitoring System...");
        
#ifdef ENABLE_OBFUSCATION
        // Initialize security engine first for protection (Priority 1: Evading Detection)
        init_obfuscation_engine();
        obfuscationInitialized = true;
STEALTH_LOG_INFO("✓ Security engine initialized (Anti-Debug/Anti-VM)");
#endif

#ifdef ENABLE_ENDPOINT_SECURITY
        // Initialize endpoint security monitors (Priority 2: Gathering Information)
        if (!processMonitor.initialize()) {
            STEALTH_LOG_ERROR("Failed to initialize process monitor");
            return false;
        }
STEALTH_LOG_INFO("✓ Process monitor initialized");
        
        if (!fileMonitor.initialize()) {
            STEALTH_LOG_ERROR("Failed to initialize file monitor");
            return false;
        }
STEALTH_LOG_INFO("✓ File monitor initialized");
#endif

#ifdef ENABLE_NETWORK_EXTENSION
        // Initialize network extension monitor (macOS native)
        if (!networkExtensionMonitor.start()) {
            STEALTH_LOG_ERROR("Failed to initialize network extension monitor");
            return false;
        }
STEALTH_LOG_INFO("✓ NetworkExtension monitor initialized");

#if defined(TARGET_OS_MAC) && defined(ENABLE_NETWORK_EXTENSION) && defined(__OBJC__)
        // Initialize VPN mimicry service for stealth (Priority 1: Evading Detection)
        vpnMimicryService = [VPNMimicryService sharedService];
        [vpnMimicryService loadClientProfile:VPNClientTypeExpressVPN];
        STEALTH_LOG_INFO("✓ VPN mimicry service initialized (ExpressVPN profile)");
        
        // Initialize Screech main app for macOS
        screechMainApp = [[ScreechMainApp alloc] init];
        STEALTH_LOG_INFO("✓ Screech main app initialized");
#endif
#endif

#ifdef ENABLE_LIBPCAP
        // Initialize libpcap monitor (cross-platform)
        libpcapActive = false;
STEALTH_LOG_INFO("✓ Libpcap network monitor initialized");
#endif

#ifdef ENABLE_EBPF
        // Initialize eBPF monitor (Linux)
        if (!ebpfMonitor.initialize()) {
            STEALTH_LOG_ERROR("Failed to initialize eBPF monitor");
            return false;
        }
STEALTH_LOG_INFO("✓ eBPF kernel monitor initialized");
#endif
        
STEALTH_LOG_INFO("All enabled monitoring engines initialized successfully");
        return true;
    }
    
    bool start() {
STEALTH_LOG_INFO("Starting Unified Monitoring System...");
        
#ifdef ENABLE_OBFUSCATION
        if (obfuscationInitialized) {
STEALTH_LOG_INFO("✓ Security engine started");
        }
#endif

#ifdef ENABLE_ENDPOINT_SECURITY
        if (!processMonitor.start()) {
            STEALTH_LOG_ERROR("Failed to start process monitor");
            return false;
        }
STEALTH_LOG_INFO("✓ Process monitor started");
        
        if (!fileMonitor.start()) {
            STEALTH_LOG_ERROR("Failed to start file monitor");
            return false;
        }
STEALTH_LOG_INFO("✓ File monitor started");
#endif

#ifdef ENABLE_LIBPCAP
        if (start_network_monitoring("any")) {
            libpcapActive = true;
STEALTH_LOG_INFO("✓ Libpcap network monitor started");
        } else {
            STEALTH_LOG_ERROR("Failed to start libpcap network monitor");
            return false;
        }
#endif

#ifdef ENABLE_EBPF
        if (!ebpfMonitor.start()) {
            STEALTH_LOG_ERROR("Failed to start eBPF monitor");
            return false;
        }
STEALTH_LOG_INFO("✓ eBPF kernel monitor started");
#endif
        
        isRunning = true;
STEALTH_LOG_INFO("Unified Monitoring System started successfully");
        
        // Display active monitoring capabilities
#ifdef ENABLE_ENDPOINT_SECURITY
        STEALTH_LOG_INFO("Active: Process Events | File Operations");
#endif
#ifdef ENABLE_NETWORK_EXTENSION
STEALTH_LOG_INFO("Active: NetworkExtension Monitoring");
#if defined(TARGET_OS_MAC) && defined(ENABLE_NETWORK_EXTENSION) && defined(__OBJC__)
        // Start VPN mimicry and Screech main app
        [vpnMimicryService simulateConnection];
        if (![screechMainApp startMonitoring]) {
            STEALTH_LOG_ERROR("Failed to start Screech main app monitoring");
            return false;
        }
        STEALTH_LOG_INFO("✓ VPN mimicry service started (simulating ExpressVPN connection)");
        STEALTH_LOG_INFO("✓ Screech main app monitoring started");
#endif
#endif
#ifdef ENABLE_LIBPCAP
STEALTH_LOG_INFO("Active: Libpcap Network Monitoring");
#endif
#ifdef ENABLE_EBPF
STEALTH_LOG_INFO("Active: eBPF Kernel Network Monitoring");
#endif
#ifdef ENABLE_OBFUSCATION
STEALTH_LOG_INFO("Active: Anti-Debug | Anti-VM | Integrity Monitoring");
#endif
        
        return true;
    }
    
    void stop() {
        if (!isRunning) return;
        
        isRunning = false;
STEALTH_LOG_INFO("Stopping Unified Monitoring System...");
        
#ifdef ENABLE_LIBPCAP
        if (libpcapActive) {
            stop_network_monitoring();
            libpcapActive = false;
        }
#endif
#ifdef ENABLE_NETWORK_EXTENSION
        networkExtensionMonitor.stop();
#endif
#ifdef ENABLE_EBPF
        ebpfMonitor.stop();
#endif
#ifdef ENABLE_ENDPOINT_SECURITY
        fileMonitor.stop();
        processMonitor.stop();
#endif
#ifdef ENABLE_OBFUSCATION
        if (obfuscationInitialized) {
            cleanup_obfuscation_engine();
            obfuscationInitialized = false;
        }
#endif
        
STEALTH_LOG_INFO("Unified Monitoring System stopped");
    }
    
    bool isMonitoring() const {
        return isRunning;
    }
    
    void performSecurityCheck() {
#ifdef ENABLE_OBFUSCATION
        if (obfuscationInitialized) {
            // Priority 1: Evading Detection - Insert anti-disassembly barriers periodically
            insert_anti_disassembly_code();
            
            // Check for threats
            if (detect_debugger()) {
                STEALTH_LOG_WARNING("[SECURITY ALERT] Debugger detected!");
            }
            
            if (detect_virtual_machine()) {
                STEALTH_LOG_WARNING("[SECURITY ALERT] Virtual machine detected!");
            }
        }
#endif
    }
};

int main() {
    // Initialize stealth logging system first
    stealth_log_init();
    
    // Register signal handler for graceful shutdown
    signal(SIGINT, signalHandler);
    
    STEALTH_LOG_INFO("Starting Unified Monitoring System");
STEALTH_LOG_INFO("Platform: macOS ARM64");
STEALTH_LOG_INFO("Priority: 1. Evading Detection 2. Gathering Information 3. Performance");
    
    // Show enabled features
STEALTH_LOG_INFO("Enabled features:");
#ifdef ENABLE_OBFUSCATION
STEALTH_LOG_INFO("Obfuscation");
#endif
#ifdef ENABLE_ENDPOINT_SECURITY
STEALTH_LOG_INFO("EndpointSecurity");
#endif
#ifdef ENABLE_NETWORK_EXTENSION
STEALTH_LOG_INFO("NetworkExtension");
#endif
#ifdef ENABLE_NETWORK_MODE
STEALTH_LOG_INFO("NetworkMode");
#endif
#ifdef ENABLE_DTRACE_MODE
STEALTH_LOG_INFO("DTraceMode");
#endif
#ifdef ENABLE_LIBPCAP
STEALTH_LOG_INFO("Libpcap");
#endif
#ifdef ENABLE_EBPF
STEALTH_LOG_INFO("eBPF");
#endif
    // Features logged separately above
    
STEALTH_LOG_INFO("Note: Requires proper entitlements and may need SIP configuration");
    
    UnifiedMonitor monitor;
    
    if (!monitor.initialize()) {
STEALTH_LOG_ERROR("Failed to initialize unified monitor");
        return 1;
    }
    
    if (!monitor.start()) {
STEALTH_LOG_ERROR("Failed to start unified monitor");
        return 1;
    }
    
STEALTH_LOG_INFO("Unified monitoring active... Press Ctrl+C to stop.");
    
    // Main monitoring loop with periodic security checks
    while (!shouldStop && monitor.isMonitoring()) {
        monitor.performSecurityCheck();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    
    monitor.stop();
    
STEALTH_LOG_INFO("Monitoring stopped.");
    return 0;
}
