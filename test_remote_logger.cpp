#include "libs/remote_logging/RemoteLogger.h"
#include "libs/event_logger/EventLogger.h"
#include <iostream>

int main() {
    std::cout << "Testing RemoteLogger directly..." << std::endl;
    
    // Test EventLogger remote logging
    EventLogger::EventLoggerEngine& logger = EventLogger::getGlobalLogger();
    logger.initialize();
    
    bool success = logger.enableRemoteLogging("192.168.1.28", 514);
    std::cout << "Remote logging enabled: " << (success ? "true" : "false") << std::endl;
    
    if (success) {
        std::cout << "Is remote logging enabled: " << (logger.isRemoteLoggingEnabled() ? "true" : "false") << std::endl;
        
        // Send test messages
        logger.logSecurityEvent("TEST", "Direct RemoteLogger test from C++ program");
        logger.logProcessEvent("TEST_PROC", "test_process", "/usr/bin/test", "Direct process event test");
        logger.logNetworkEvent("TEST_NET", "test_process", "/usr/bin/test", "Direct network event test");
        
        std::cout << "Test messages sent" << std::endl;
    }
    
    return 0;
}
