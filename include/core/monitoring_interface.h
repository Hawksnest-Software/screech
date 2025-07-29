//
// monitoring_interface.h - Abstract interface for polymorphic monitoring implementations
// Allows runtime selection between different monitoring modes
//

#ifndef MONITORING_INTERFACE_H
#define MONITORING_INTERFACE_H

#include <string>
#include <memory>
#include <functional>
#include <map>

namespace screech {

// Forward declarations
struct MonitoringEvent;

// Event types that can be monitored
enum class EventType {
    NETWORK_CONNECTION,
    FILE_ACCESS,
    PROCESS_EXECUTION,
    SYSTEM_CALL,
    SECURITY_EVENT
};

// Monitoring event structure
struct MonitoringEvent {
    EventType type;
    std::string timestamp;
    std::string process_name;
    pid_t process_id;
    uid_t user_id;
    std::string details;
    std::map<std::string, std::string> metadata;
};

// Callback function for event handling
using EventCallback = std::function<void(const MonitoringEvent&)>;

// Abstract base class for all monitoring implementations
class MonitoringInterface {
public:
    virtual ~MonitoringInterface() = default;
    
    // Core monitoring operations
    virtual bool initialize() = 0;
    virtual bool start() = 0;
    virtual void stop() = 0;
    virtual bool isRunning() const = 0;
    
    // Event handling
    virtual void setEventCallback(EventCallback callback) = 0;
    
    // Implementation info
    virtual std::string getName() const = 0;
    virtual std::string getDescription() const = 0;
    virtual std::string getVersion() const = 0;
    
    // Configuration
    virtual void setConfiguration(const std::map<std::string, std::string>& config) = 0;
    virtual std::map<std::string, std::string> getConfiguration() const = 0;
    
    // Capabilities
    virtual bool supportsEventType(EventType type) const = 0;
    virtual std::vector<EventType> getSupportedEventTypes() const = 0;
};

// Factory function type for creating monitoring implementations
using MonitoringFactory = std::function<std::unique_ptr<MonitoringInterface>()>;

// Registry for monitoring implementations
class MonitoringRegistry {
public:
    static MonitoringRegistry& getInstance();
    
    void registerImplementation(const std::string& name, MonitoringFactory factory);
    std::unique_ptr<MonitoringInterface> createImplementation(const std::string& name);
    std::vector<std::string> getAvailableImplementations() const;
    bool isImplementationAvailable(const std::string& name) const;
    
private:
    std::map<std::string, MonitoringFactory> implementations_;
};

// Macro to register implementations
#define REGISTER_MONITORING_IMPLEMENTATION(name, class_name) \
    namespace { \
        struct class_name##_registrar { \
            class_name##_registrar() { \
                MonitoringRegistry::getInstance().registerImplementation( \
                    name, []() -> std::unique_ptr<MonitoringInterface> { \
                        return std::make_unique<class_name>(); \
                    }); \
            } \
        }; \
        static class_name##_registrar class_name##_reg; \
    }

} // namespace screech

#endif // MONITORING_INTERFACE_H
