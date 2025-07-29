#pragma once

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include "monitoring_interface.h"

// Forward declarations
class MonitoringInterface;
class UnifiedMonitor;

/**
 * Registry for managing different monitoring implementations
 * Provides a centralized way to register, discover, and instantiate monitors
 */
class MonitoringRegistry {
public:
    using MonitorFactory = std::function<std::unique_ptr<MonitoringInterface>()>;
    
    static MonitoringRegistry& getInstance();
    
    // Register a monitoring implementation
    void registerMonitor(const std::string& name, MonitorFactory factory);
    
    // Create a monitor instance by name
    std::unique_ptr<MonitoringInterface> createMonitor(const std::string& name);
    
    // Get list of available monitor names
    std::vector<std::string> getAvailableMonitors() const;
    
    // Check if a monitor is registered
    bool isMonitorAvailable(const std::string& name) const;
    
    // Get default monitor based on platform capabilities
    std::string getDefaultMonitor() const;
    
private:
    MonitoringRegistry() = default;
    ~MonitoringRegistry() = default;
    MonitoringRegistry(const MonitoringRegistry&) = delete;
    MonitoringRegistry& operator=(const MonitoringRegistry&) = delete;
    
    std::unordered_map<std::string, MonitorFactory> m_monitors;
};

// Convenience macros for registering monitors
#define REGISTER_MONITOR(name, class_name) \
    static bool registered_##class_name = []() { \
        MonitoringRegistry::getInstance().registerMonitor(name, []() { \
            return std::make_unique<class_name>(); \
        }); \
        return true; \
    }();
