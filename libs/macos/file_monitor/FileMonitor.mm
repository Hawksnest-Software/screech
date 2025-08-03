//
// FileMonitor.cpp - File System Monitoring Library Implementation
//

#include "FileMonitor.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <atomic>
#include <set>

#ifdef __APPLE__
#include <dispatch/dispatch.h>
#include <bsm/libbsm.h>
#include <sys/proc_info.h>
#endif

namespace FileMonitor {

class FileMonitorEngine::Impl {
public:
    Impl() : esClient(nullptr), isActive(false) {
#ifdef __APPLE__
        monitorQueue = dispatch_queue_create("file.monitor", DISPATCH_QUEUE_SERIAL);
#endif
    }
    
    ~Impl() {
        stop();
#ifdef __APPLE__
        // monitorQueue will be automatically released by ARC
#endif
    }
    
    bool initialize() {
#ifdef __APPLE__
        es_handler_block_t handler = ^(es_client_t * _Nonnull client, const es_message_t * _Nonnull message) {
            (void)client;
            handleEvent(message);
        };
        
        es_new_client_result_t result = es_new_client(&esClient, handler);
        if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
            std::cerr << "Failed to create Endpoint Security client: " << result << std::endl;
            return false;
        }
        
        es_event_type_t events[] = {
            ES_EVENT_TYPE_NOTIFY_OPEN,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_UNLINK,
            ES_EVENT_TYPE_NOTIFY_RENAME
        };
        
        es_return_t subscribe_result = es_subscribe(esClient, events, sizeof(events) / sizeof(events[0]));
        if (subscribe_result != ES_RETURN_SUCCESS) {
            std::cerr << "Failed to subscribe to file events: " << subscribe_result << std::endl;
            es_delete_client(esClient);
            esClient = nullptr;
            return false;
        }
        
        return true;
#else
        std::cerr << "File monitoring only supported on macOS" << std::endl;
        return false;
#endif
    }
    
    bool start() {
        if (!esClient) return false;
        isActive = true;
        return true;
    }
    
    void stop() {
        isActive = false;
#ifdef __APPLE__
        if (esClient) {
            es_delete_client(esClient);
            esClient = nullptr;
        }
#endif
    }
    
    bool isRunning() const {
        return isActive;
    }
    
    void setEventCallback(FileEventCallback cb) {
        callback = cb;
    }
    
    void addWatchPath(const std::string& path) {
        watchPaths.insert(path);
    }
    
    void removeWatchPath(const std::string& path) {
        watchPaths.erase(path);
    }
    
private:
#ifdef __APPLE__
    es_client_t* esClient;
    dispatch_queue_t monitorQueue;
#endif
    std::atomic<bool> isActive;
    FileEventCallback callback;
    std::set<std::string> watchPaths;
    
    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }
    
#ifdef __APPLE__
    ProcessInfo getProcessInfo(pid_t pid) {
        ProcessInfo info = {};
        info.pid = pid;
        
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
            info.path = std::string(pathbuf);
            
            size_t lastSlash = info.path.find_last_of('/');
            if (lastSlash != std::string::npos) {
                info.name = info.path.substr(lastSlash + 1);
            } else {
                info.name = info.path;
            }
        }
        
        struct proc_bsdinfo procInfo;
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) > 0) {
            info.uid = procInfo.pbi_uid;
            info.gid = procInfo.pbi_gid;
            if (info.name.empty()) {
                info.name = std::string(procInfo.pbi_comm);
            }
        }
        
        return info;
    }
    
    bool shouldMonitorPath(const std::string& path) {
        if (watchPaths.empty()) return true; // Monitor all if no specific paths set
        
        for (const auto& watchPath : watchPaths) {
            if (path.find(watchPath) == 0) {
                return true;
            }
        }
        return false;
    }
    
    void handleEvent(const es_message_t* message) {
        if (!message || !callback) return;
        
        FileEvent event;
        event.timestamp = getCurrentTimestamp();
        
        pid_t pid = audit_token_to_pid(message->process->audit_token);
        event.process = getProcessInfo(pid);
        
        // Skip events from our own monitoring process
        if (event.process.name.find("enhanced") != std::string::npos || 
            event.process.name.find("monitor") != std::string::npos ||
            event.process.path.find("/tmp/") != std::string::npos) {
            return;
        }
        
        switch (message->event_type) {
            case ES_EVENT_TYPE_NOTIFY_OPEN:
                event.type = FileEvent::OPEN;
                if (message->event.open.file && message->event.open.file->path.data) {
                    event.filePath = std::string(message->event.open.file->path.data, 
                                                message->event.open.file->path.length);
                    event.details = "flags:" + std::to_string(message->event.open.fflag);
                }
                break;
                
            case ES_EVENT_TYPE_NOTIFY_CLOSE:
                event.type = FileEvent::CLOSE;
                if (message->event.close.target && message->event.close.target->path.data) {
                    event.filePath = std::string(message->event.close.target->path.data, 
                                                message->event.close.target->path.length);
                    event.details = "modified:" + std::to_string(message->event.close.modified);
                }
                break;
                
            case ES_EVENT_TYPE_NOTIFY_WRITE:
                event.type = FileEvent::WRITE;
                if (message->event.write.target && message->event.write.target->path.data) {
                    event.filePath = std::string(message->event.write.target->path.data, 
                                                message->event.write.target->path.length);
                }
                break;
                
            case ES_EVENT_TYPE_NOTIFY_CREATE:
                event.type = FileEvent::CREATE;
                if (message->event.create.destination.existing_file && 
                    message->event.create.destination.existing_file->path.data) {
                    event.filePath = std::string(message->event.create.destination.existing_file->path.data, 
                                                message->event.create.destination.existing_file->path.length);
                }
                break;
                
            case ES_EVENT_TYPE_NOTIFY_UNLINK:
                event.type = FileEvent::DELETE;
                if (message->event.unlink.target && message->event.unlink.target->path.data) {
                    event.filePath = std::string(message->event.unlink.target->path.data, 
                                                message->event.unlink.target->path.length);
                }
                break;
                
            case ES_EVENT_TYPE_NOTIFY_RENAME:
                event.type = FileEvent::RENAME;
                if (message->event.rename.source && message->event.rename.source->path.data) {
                    event.filePath = std::string(message->event.rename.source->path.data,
                                                message->event.rename.source->path.length);
                    if (message->event.rename.destination.existing_file &&
                        message->event.rename.destination.existing_file->path.data) {
                        event.details = "new_path:" + std::string(
                            message->event.rename.destination.existing_file->path.data,
                            message->event.rename.destination.existing_file->path.length);
                    }
                }
                break;
                
            default:
                return;
        }
        
        if (!shouldMonitorPath(event.filePath)) return;
        
        callback(event);
    }
#endif
};

FileMonitorEngine::FileMonitorEngine() : pImpl(std::make_unique<Impl>()) {}
FileMonitorEngine::~FileMonitorEngine() = default;

bool FileMonitorEngine::initialize() { return pImpl->initialize(); }
bool FileMonitorEngine::start() { return pImpl->start(); }
void FileMonitorEngine::stop() { pImpl->stop(); }
bool FileMonitorEngine::isRunning() const { return pImpl->isRunning(); }
void FileMonitorEngine::setEventCallback(FileEventCallback callback) { pImpl->setEventCallback(callback); }
void FileMonitorEngine::addWatchPath(const std::string& path) { pImpl->addWatchPath(path); }
void FileMonitorEngine::removeWatchPath(const std::string& path) { pImpl->removeWatchPath(path); }

// C API implementation
extern "C" {
    void* file_monitor_create() {
        return new FileMonitorEngine();
    }
    
    void file_monitor_destroy(void* monitor) {
        delete static_cast<FileMonitorEngine*>(monitor);
    }
    
    bool file_monitor_initialize(void* monitor) {
        return static_cast<FileMonitorEngine*>(monitor)->initialize();
    }
    
    bool file_monitor_start(void* monitor) {
        return static_cast<FileMonitorEngine*>(monitor)->start();
    }
    
    void file_monitor_stop(void* monitor) {
        static_cast<FileMonitorEngine*>(monitor)->stop();
    }
    
    void file_monitor_set_callback(void* monitor, file_event_callback_t callback) {
        static_cast<FileMonitorEngine*>(monitor)->setEventCallback([callback](const FileEvent& event) {
            callback(&event);
        });
    }
    
    void file_monitor_add_watch_path(void* monitor, const char* path) {
        static_cast<FileMonitorEngine*>(monitor)->addWatchPath(std::string(path));
    }
    
    void file_monitor_remove_watch_path(void* monitor, const char* path) {
        static_cast<FileMonitorEngine*>(monitor)->removeWatchPath(std::string(path));
    }
}

} // namespace FileMonitor
