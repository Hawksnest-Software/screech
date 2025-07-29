//
// FileMonitor.h - File System Monitoring Library
// Monitors file operations, I/O events, and filesystem changes
//

#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include <string>
#include <functional>
#include <memory>

#ifdef __APPLE__
#include <EndpointSecurity/EndpointSecurity.h>
#include <libproc.h>
#endif

namespace FileMonitor {

struct ProcessInfo {
    pid_t pid;
    std::string name;
    std::string path;
    uid_t uid;
    gid_t gid;
};

struct FileEvent {
    enum Type {
        OPEN,
        CLOSE,
        WRITE,
        CREATE,
        DELETE,
        RENAME
    } type;
    
    std::string timestamp;
    ProcessInfo process;
    std::string filePath;
    std::string details;
};

using FileEventCallback = std::function<void(const FileEvent&)>;

class FileMonitorEngine {
public:
    FileMonitorEngine();
    ~FileMonitorEngine();
    
    bool initialize();
    bool start();
    void stop();
    bool isRunning() const;
    
    void setEventCallback(FileEventCallback callback);
    void addWatchPath(const std::string& path);
    void removeWatchPath(const std::string& path);
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// C API for compatibility
extern "C" {
    typedef void (*file_event_callback_t)(const FileEvent* event);
    
    void* file_monitor_create();
    void file_monitor_destroy(void* monitor);
    bool file_monitor_initialize(void* monitor);
    bool file_monitor_start(void* monitor);
    void file_monitor_stop(void* monitor);
    void file_monitor_set_callback(void* monitor, file_event_callback_t callback);
    void file_monitor_add_watch_path(void* monitor, const char* path);
    void file_monitor_remove_watch_path(void* monitor, const char* path);
}

} // namespace FileMonitor

#endif // FILE_MONITOR_H
