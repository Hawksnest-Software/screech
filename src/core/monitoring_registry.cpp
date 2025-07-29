//
// monitoring_registry.cpp - Implementation of the monitoring registry
//

#include "monitoring_interface.h"
#include <stdexcept>
#include <iostream>

namespace screech {

MonitoringRegistry& MonitoringRegistry::getInstance() {
    static MonitoringRegistry instance;
    return instance;
}

void MonitoringRegistry::registerImplementation(const std::string& name, MonitoringFactory factory) {
    implementations_[name] = factory;
    std::cout << "[Registry] Registered implementation: " << name << std::endl;
}

std::unique_ptr<MonitoringInterface> MonitoringRegistry::createImplementation(const std::string& name) {
    auto it = implementations_.find(name);
    if (it == implementations_.end()) {
        throw std::runtime_error("Unknown monitoring implementation: " + name);
    }
    
    try {
        return it->second();
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to create implementation '" + name + "': " + e.what());
    }
}

std::vector<std::string> MonitoringRegistry::getAvailableImplementations() const {
    std::vector<std::string> implementations;
    for (const auto& pair : implementations_) {
        implementations.push_back(pair.first);
    }
    return implementations;
}

bool MonitoringRegistry::isImplementationAvailable(const std::string& name) const {
    return implementations_.find(name) != implementations_.end();
}

} // namespace screech
