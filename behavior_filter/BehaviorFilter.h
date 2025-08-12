//
// BehaviorFilter.h - Intelligent Behavior Analysis and Filtering System
// Distinguishes between normal system behavior and potentially malicious activity
//

#ifndef BEHAVIOR_FILTER_H
#define BEHAVIOR_FILTER_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>

#ifdef __APPLE__
#include <libproc.h>
#endif

namespace BehaviorFilter {

// Risk levels for events
enum class RiskLevel {
    NORMAL = 0,     // Expected system behavior
    LOW = 1,        // Slightly unusual but likely benign
    MEDIUM = 2,     // Suspicious activity requiring attention
    HIGH = 3,       // Likely malicious behavior
    CRITICAL = 4    // Definite threat detected
};

// Event types for analysis
enum class EventType {
    PROCESS_EXEC,
    PROCESS_FORK,
    PROCESS_EXIT,
    FILE_OPEN,
    FILE_WRITE,
    FILE_CREATE,
    FILE_DELETE,
    NETWORK_CONNECTION,
    NETWORK_DATA_TRANSFER
};

// Process behavior characteristics
struct ProcessProfile {
    std::string name;
    std::string path;
    std::string signature;
    bool is_system_process;
    bool is_signed;
    std::set<std::string> typical_file_paths;
    std::set<std::string> typical_network_destinations;
    std::map<std::string, int> child_processes;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
    int execution_count;
    double average_runtime_seconds;
    bool has_network_access;
    bool accesses_sensitive_files;
};

// File access pattern analysis
struct FileAccessPattern {
    std::string path;
    std::set<std::string> accessing_processes;
    std::map<std::string, int> access_types; // read, write, create, delete
    std::chrono::system_clock::time_point last_access;
    bool is_sensitive_location;
    bool is_system_file;
    bool is_user_document;
};

// Network behavior analysis
struct NetworkBehaviorPattern {
    std::string process_name;
    std::string destination_ip;
    uint16_t destination_port;
    std::string protocol;
    int connection_count;
    uint64_t bytes_transferred;
    std::chrono::system_clock::time_point first_connection;
    std::chrono::system_clock::time_point last_connection;
    bool is_known_service;
    bool is_local_network;
};

// Behavioral analysis result
struct BehaviorAnalysisResult {
    RiskLevel risk_level;
    double confidence_score; // 0.0 to 1.0
    std::vector<std::string> reasons;
    std::string primary_concern;
    bool should_alert;
    bool should_block;
    std::map<std::string, std::string> metadata;
};

// Main behavior filter engine
class BehaviorFilterEngine {
public:
    BehaviorFilterEngine();
    ~BehaviorFilterEngine();

    // Initialize the behavior learning system
    bool initialize();
    void shutdown();

    // Learning mode controls
    void enableLearningMode(bool enable = true);
    bool isLearningMode() const;
    void setLearningPeriod(std::chrono::hours hours);

    // Process analysis
    BehaviorAnalysisResult analyzeProcessEvent(
        EventType event_type,
        const std::string& process_name,
        const std::string& process_path,
        pid_t pid,
        pid_t parent_pid,
        const std::string& command_line = "",
        const std::string& signature = ""
    );

    // File access analysis
    BehaviorAnalysisResult analyzeFileEvent(
        EventType event_type,
        const std::string& file_path,
        const std::string& process_name,
        pid_t pid,
        const std::string& operation_details = ""
    );

    // Network activity analysis
    BehaviorAnalysisResult analyzeNetworkEvent(
        EventType event_type,
        const std::string& process_name,
        pid_t pid,
        const std::string& local_addr,
        uint16_t local_port,
        const std::string& remote_addr,
        uint16_t remote_port,
        const std::string& protocol,
        uint64_t data_size = 0
    );

    // Behavioral pattern management
    void saveLearnedBehaviors(const std::string& file_path);
    bool loadLearnedBehaviors(const std::string& file_path);
    void resetLearnedBehaviors();

    // Configuration
    void setRiskThreshold(RiskLevel min_level);
    void enableAlertingForRiskLevel(RiskLevel level, bool enable = true);
    void addTrustedProcess(const std::string& process_name, const std::string& path = "");
    void addSensitiveFile(const std::string& file_path);
    void addTrustedNetworkDestination(const std::string& ip_or_domain);

    // Statistics and reporting
    std::map<std::string, int> getProcessStatistics() const;
    std::map<std::string, int> getFileAccessStatistics() const;
    std::map<std::string, int> getNetworkStatistics() const;
    int getTotalEventsAnalyzed() const;
    int getSuspiciousEventsDetected() const;

    // Advanced analysis features
    void enableTemporalAnalysis(bool enable = true);
    void enableProcessTreeAnalysis(bool enable = true);
    void enableAnomalyDetection(bool enable = true);
    void setAnomalyThreshold(double threshold); // 0.0 to 1.0

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Utility functions
namespace Utils {
    bool isSystemProcess(const std::string& process_name, const std::string& path);
    bool isSensitiveFile(const std::string& file_path);
    bool isSystemFile(const std::string& file_path);
    bool isUserDocument(const std::string& file_path);
    bool isKnownService(const std::string& destination, uint16_t port);
    bool isLocalNetwork(const std::string& ip_address);
    std::string getProcessSignature(pid_t pid);
    std::vector<std::string> getProcessCommandLine(pid_t pid);
}

// Pre-defined behavior profiles for common system processes
namespace SystemProfiles {
    extern const std::map<std::string, ProcessProfile> macOS_system_processes;
    extern const std::map<std::string, ProcessProfile> linux_system_processes;
    extern const std::set<std::string> sensitive_file_paths;
    extern const std::set<std::string> system_file_paths;
    extern const std::map<uint16_t, std::string> known_network_services;
}

} // namespace BehaviorFilter

#endif // BEHAVIOR_FILTER_H
