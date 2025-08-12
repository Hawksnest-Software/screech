//
// main.cpp - Linux eBPF Network Monitor Main Entry Point
// Standalone network monitoring using eBPF with rsyslog integration
//

#include <iostream>
#include <atomic>
#include <csignal>
#include <unistd.h>
#include <syslog.h>
#include "screech_linux_ebpf.h"

// Global signal flag
std::atomic<bool> shouldStop(false);

void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ", shutting down..." << std::endl;
    shouldStop = true;
}

int main(int argc, char* argv[]) {
    std::cout << "Linux eBPF Network Monitor" << std::endl;
    std::cout << "Logs to rsyslog using process-separated identifiers" << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Install signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    // Check prerequisites
    if (!checkRoot()) {
        return 1;
    }
    
    if (!checkBPFSupport()) {
        return 1;
    }
    
    // Create and initialize monitor
    LinuxEBPFMonitor monitor;
    
    if (!monitor.initialize()) {
        std::cerr << "Failed to initialize eBPF monitor" << std::endl;
        return 1;
    }
    
    if (!monitor.start()) {
        std::cerr << "Failed to start eBPF monitor" << std::endl;
        return 1;
    }
    
    // Log startup to syslog
    openlog("screech-main", LOG_PID | LOG_NDELAY, LOG_LOCAL0);
    syslog(LOG_INFO, "Linux eBPF Network Monitor started - PID: %d", getpid());
    syslog(LOG_INFO, "Logging network events to rsyslog with process separation");
    closelog();
    
    // Main event loop
    std::cout << "Monitor running... (logs are sent to rsyslog)" << std::endl;
    monitor.eventLoop();
    
    // Cleanup
    monitor.stop();
    
    // Log shutdown to syslog
    openlog("screech-main", LOG_PID | LOG_NDELAY, LOG_LOCAL0);
    syslog(LOG_INFO, "Linux eBPF Network Monitor stopped - PID: %d", getpid());
    closelog();
    
    std::cout << "Monitor stopped." << std::endl;
    return 0;
}
