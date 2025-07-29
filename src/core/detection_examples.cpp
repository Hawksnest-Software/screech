// Examples of how malware might detect monitoring tools
// These are for educational/defensive purposes only

#include <iostream>
#include <string>
#include <fstream>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

// Check if specific processes are running
bool isProcessRunning(const std::string& processName) {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return false;
    
    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
            std::string cmdline_path = "/proc/" + std::string(entry->d_name) + "/cmdline";
            std::ifstream cmdline_file(cmdline_path);
            std::string cmdline;
            if (getline(cmdline_file, cmdline)) {
                if (cmdline.find(processName) != std::string::npos) {
                    closedir(proc_dir);
                    return true;
                }
            }
        }
    }
    closedir(proc_dir);
    return false;
}

// Check for libpcap usage by examining open file descriptors
bool detectLibpcapUsage() {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return false;
    
    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
            std::string fd_path = "/proc/" + std::string(entry->d_name) + "/fd";
            DIR* fd_dir = opendir(fd_path.c_str());
            if (!fd_dir) continue;
            
            struct dirent* fd_entry;
            while ((fd_entry = readdir(fd_dir)) != nullptr) {
                if (fd_entry->d_type == DT_LNK) {
                    char link_target[256];
                    std::string link_path = fd_path + "/" + fd_entry->d_name;
                    ssize_t len = readlink(link_path.c_str(), link_target, sizeof(link_target) - 1);
                    if (len > 0) {
                        link_target[len] = '\0';
                        std::string target(link_target);
                        // Look for packet sockets or network interfaces
                        if (target.find("packet:") != std::string::npos ||
                            target.find("socket:") != std::string::npos) {
                            closedir(fd_dir);
                            closedir(proc_dir);
                            return true;
                        }
                    }
                }
            }
            closedir(fd_dir);
        }
    }
    closedir(proc_dir);
    return false;
}

// Monitor system call frequency to detect analysis tools
class SystemCallMonitor {
private:
    int lsof_calls = 0;
    int ps_calls = 0;
    time_t last_check = 0;
    
public:
    bool suspiciousActivity() {
        time_t now = time(nullptr);
        if (now - last_check > 60) { // Reset counters every minute
            lsof_calls = 0;
            ps_calls = 0;
            last_check = now;
        }
        
        // Check for frequent lsof/ps execution patterns
        // This would require hooking system calls or monitoring /proc
        return (lsof_calls > 10 || ps_calls > 20); // Arbitrary thresholds
    }
};

// Check system load patterns
bool highSystemActivity() {
    std::ifstream loadavg("/proc/loadavg");
    double load1, load5, load15;
    if (loadavg >> load1 >> load5 >> load15) {
        // High load might indicate active analysis
        return (load1 > 2.0 || load5 > 1.5);
    }
    return false;
}

// Anti-debugging techniques
bool debuggerDetected() {
    // Check if being traced
    std::ifstream status("/proc/self/status");
    std::string line;
    while (getline(status, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            std::string tracer_pid = line.substr(line.find(":") + 1);
            if (std::stoi(tracer_pid) != 0) {
                return true; // Being debugged/traced
            }
        }
    }
    return false;
}

int main() {
    std::cout << "Detection Examples (Educational Only):\n";
    
    // Examples of what malware might check for:
    if (isProcessRunning("tcpdump")) {
        std::cout << "- tcpdump detected\n";
    }
    if (isProcessRunning("wireshark")) {
        std::cout << "- Wireshark detected\n";
    }
    if (isProcessRunning("screech")) {
        std::cout << "- screech monitoring detected\n";
    }
    
    if (detectLibpcapUsage()) {
        std::cout << "- Packet capture activity detected\n";
    }
    
    if (debuggerDetected()) {
        std::cout << "- Debugger/tracer detected\n";
    }
    
    if (highSystemActivity()) {
        std::cout << "- High system activity (possible analysis)\n";
    }
    
    return 0;
}
