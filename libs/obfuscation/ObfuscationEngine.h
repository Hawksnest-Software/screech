//
// ObfuscationEngine.h - Obfuscation and Anti-Analysis Library
// Provides anti-debugging, anti-analysis, and integrity monitoring
//

#ifndef OBFUSCATION_ENGINE_H
#define OBFUSCATION_ENGINE_H

#include <string>
#include <functional>
#include <memory>

namespace ObfuscationEngine {

struct ThreatInfo {
    enum Type {
        DEBUGGER_DETECTED,
        VM_DETECTED,
        INTEGRITY_VIOLATION,
        HOOK_DETECTED,
        ANALYSIS_TOOL_DETECTED
    } type;
    
    std::string timestamp;
    std::string details;
    int severityLevel; // 1-10
};

using ThreatCallback = std::function<void(const ThreatInfo&)>;

class SecurityEngine {
public:
    SecurityEngine();
    ~SecurityEngine();
    
    bool initialize();
    bool start();
    void stop();
    bool isRunning() const;
    
    void setThreatCallback(ThreatCallback callback);
    
    // Anti-analysis methods
    bool detectDebugger();
    bool detectVirtualMachine();
    bool validateCodeIntegrity();
    
    // Anti-hooking methods
    bool detectFunctionHooks(void* functionPtr);
    bool isDylibHooked(const std::string& dylibPath);
    void obfuscateFunctionPointers();
    
    // Syscall obfuscation
    long obfuscatedSyscall(int syscallNumber, void* args, int argCount);
    void randomizeSyscallOrder();
    
    // Memory protection
    void protectCriticalMemoryRegions();
    void scrambleMemoryLayout();
    
    // Polymorphic execution
    void performPolymorphicExecution(std::function<void()> block);
    void insertAntiDisassemblyBarrier();
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// C API for compatibility with existing code
extern "C" {
    void screech_init_obfuscation(void);
    void screech_cleanup_obfuscation(void);
    int screech_obfuscated_syscall(int syscall_num, ...);
    void screech_anti_disasm_barrier(void);
    bool screech_detect_hooks(void* func_ptr);
    bool screech_detect_debugger(void);
    bool screech_detect_vm(void);
    bool screech_validate_integrity(void);
    void screech_start_monitoring(void);
    void screech_stop_monitoring(void);
}

} // namespace ObfuscationEngine

#endif // OBFUSCATION_ENGINE_H
