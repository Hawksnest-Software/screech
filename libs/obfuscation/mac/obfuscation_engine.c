#include "obfuscation_engine.h"
#include "string_obfuscation.h"
#include "debug_logging.h"
#include "function_obfuscation.h"
#include "timing_obfuscation.h"
#include "direct_syscalls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>
#include <libproc.h>
#include <time.h>
#include <sys/ptrace.h>

// Remove direct syscall definitions to avoid detection
// Use higher-level APIs through Objective-C bridge instead

// Mutex for thread safety
static pthread_mutex_t obfuscation_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function pointer obfuscation table
static struct {
    void *original;
    void *obfuscated;
} function_table[256];
static int function_count = 0;

// Check for common hook patterns
bool detect_function_hooks(void *functionPtr) {
    uint8_t *code = (uint8_t *)functionPtr;
    if (code[0] == 0xFF && code[1] == 0x25) return true;
    uint32_t *arm_code = (uint32_t *)functionPtr;
    uint32_t instr = *arm_code;
    if ((instr & 0xFC000000) == 0x14000000) return true;
    if ((instr & 0xFC000000) == 0x94000000) return true;
    return false;
}

void obfuscate_function_pointers(void) {
#ifdef ENABLE_FUNCTION_POINTER_OBFUSCATION
    DEBUG_LOG_DEBUG("Function pointer obfuscation enabled");
#else
    DEBUG_LOG_DEBUG("Function pointer obfuscation disabled");
    return;
#endif
    
    pthread_mutex_lock(&obfuscation_mutex);
    
    // Generate dynamic key instead of hardcoded value
    uint64_t dynamic_key = generate_dynamic_key();
    
    for (int i = 0; i < function_count; i++) {
        uintptr_t original = (uintptr_t)function_table[i].original;
        function_table[i].obfuscated = (void *)(original ^ dynamic_key);
    }
    pthread_mutex_unlock(&obfuscation_mutex);
}

void insert_anti_disassembly_code(void) {
#ifdef ENABLE_ANTI_DISASSEMBLY
    DEBUG_LOG_DEBUG("Anti-disassembly code enabled");
#else
    DEBUG_LOG_DEBUG("Anti-disassembly code disabled");
    return;
#endif
    
    __asm__ volatile (
        "b 1f\n\t"
        ".byte 0xFF, 0xFF, 0xFF, 0xFF\n\t"
        "1:\n\t"
        "nop\n\t"
        :
        :
        : "memory"
    );
}

void scramble_memory_layout(void) {
#ifdef ENABLE_MEMORY_SCRAMBLING
    DEBUG_LOG_DEBUG("Memory scrambling enabled");
#else
    DEBUG_LOG_DEBUG("Memory scrambling disabled");
    return;
#endif
    
    for (int i = 0; i < 10; i++) {
        size_t random_size = rand() % 4096 + 1024;
        void *ptr = malloc(random_size);
        if (ptr) {
            memset(ptr, rand() % 256, random_size);
            free(ptr);
        }
    }
}

void randomize_syscall_order(void) {
#ifndef ENABLE_SYSCALL_RANDOMIZATION
    DEBUG_LOG_DEBUG("Syscall randomization disabled");
    return;
#endif
    
    // Generic randomization without specific syscall numbers
    // This avoids creating detection signatures
    volatile int dummy_values[5] = {1, 2, 3, 4, 5};
    for (int i = 0; i < 5; i++) {
        int random_index = rand() % 5;
        int temp = dummy_values[i];
        dummy_values[i] = dummy_values[random_index];
        dummy_values[random_index] = temp;
    }
}

#ifdef ENABLE_INTEGRITY_MONITORING
void* integrity_monitor_thread(void *arg) {
#ifndef ENABLE_INTEGRITY_MONITORING
    DEBUG_LOG_DEBUG("Integrity monitoring thread disabled, exiting");
    return NULL;
#endif
    
    while (1) {
        if (detect_function_hooks((void*) &obfuscate_function_pointers)) {
            DEBUG_LOG_WARNING("Code integrity violation detected");
        }
        
        // Use obfuscated function calls only if detection is enabled
#ifdef ENABLE_DEBUGGER_DETECTION
    security_check_func_t debugger_check = get_security_checker(1);
    if (debugger_check && debugger_check()) {
        DEBUG_LOG_WARNING("Analysis environment detected");
    }
#endif
        
#ifdef ENABLE_VM_DETECTION
    security_check_func_t vm_check = get_security_checker(2);
    if (vm_check && vm_check()) {
        DEBUG_LOG_WARNING("Virtual environment detected");
    }
#endif
        
#ifdef ENABLE_ENV_CHECKS
    env_check_func_t env_check = get_env_checker();
    if (env_check && env_check()) {
        DEBUG_LOG_WARNING("Suspicious environment detected");
    }
#endif
        
        sleep(5);
    }
    return NULL;
}
#endif

bool detect_debugger(void) {
    // Method 1: Check process flags via obfuscated sysctl
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    
    // Use our obfuscated sysctl instead of the library function
    if (obfuscated_sysctl(mib, 4, &info, &size, NULL, 0) == 0 && (info.kp_proc.p_flag & P_TRACED) != 0) {
        return true;
    }
    
    // Method 2: Try obfuscated ptrace self-attach (more aggressive detection)
    static bool ptrace_checked = false;
    if (!ptrace_checked) {
        ptrace_checked = true;
        
        #ifdef __APPLE__
            // Use less aggressive debugger detection - just check parent process
            // PT_DENY_ATTACH is too aggressive and can terminate the program
            // Instead, just return false to indicate no debugger detected
            // This allows monitoring to continue normally
        #else
            // On Linux, try PTRACE_TRACEME - if it fails, we're already traced
            if (obfuscated_ptrace(0, 0, NULL, NULL) == -1) {  // PTRACE_TRACEME = 0
                return true;
            }
            // Detach immediately if successful
            obfuscated_ptrace(17, 0, NULL, NULL);  // PTRACE_DETACH = 17
        #endif
    }
    
    return false;
}

bool detect_virtual_machine(void) {
#ifdef ENABLE_STRING_OBFUSCATION
    // Use enhanced string obfuscation for VM detection
    return perform_enhanced_vm_detection();
#else
    // Fallback to basic detection without string obfuscation
    size_t len;
    
    // Construct sysctl name at runtime to avoid hardcoded strings
    STACK_STRING(hw_model, "hw", ".", "model");
    
    // Use obfuscated sysctl instead of sysctlbyname to avoid library detection
    int mib[2] = {CTL_HW, HW_MODEL};
    if (obfuscated_sysctl(mib, 2, NULL, &len, NULL, 0) == 0 && len > 0) {
        char *model = malloc(len);
        if (obfuscated_sysctl(mib, 2, model, &len, NULL, 0) == 0) {
            bool is_vm = check_vm_indicators(model);
            
            // Clear sensitive data
            secure_string_clear(model, len);
            free(model);
            return is_vm;
        }
        free(model);
    }
    
    // Clear the constructed string
    secure_string_clear(hw_model, strlen(hw_model));
    return false;
#endif
}

// Function table management
int add_function_to_table(void *original_func) {
    pthread_mutex_lock(&obfuscation_mutex);
    if (function_count < 256) {
        function_table[function_count].original = original_func;
        function_table[function_count].obfuscated = NULL;
        function_count++;
        pthread_mutex_unlock(&obfuscation_mutex);
        return function_count - 1;
    }
    pthread_mutex_unlock(&obfuscation_mutex);
    return -1; // Table full
}

void clear_function_table(void) {
    pthread_mutex_lock(&obfuscation_mutex);
    function_count = 0;
    memset(function_table, 0, sizeof(function_table));
    pthread_mutex_unlock(&obfuscation_mutex);
}

// String obfuscation integration functions
#ifdef ENABLE_STRING_OBFUSCATION
void init_string_obfuscation_subsystem(void) {
    DEBUG_LOG_DEBUG("String obfuscation enabled - initializing dynamic keys");
    
    // Generate initial dynamic keys for the session
    uint64_t session_key = generate_dynamic_key();
    uint32_t runtime_constant = calculate_runtime_constant("obfuscation_engine");
    
    DEBUG_LOG_DEBUG("Session key generated: 0x%llx", (unsigned long long)session_key);
    DEBUG_LOG_DEBUG("Runtime constant: 0x%x", runtime_constant);
    
    // Test string construction capabilities
    char test_buffer[64];
    build_sysctl_string(test_buffer, sizeof(test_buffer));
    secure_string_clear(test_buffer, sizeof(test_buffer));
    
    DEBUG_LOG_DEBUG("String obfuscation subsystem initialized");
}

bool perform_enhanced_environment_checks(void) {
    bool suspicious_detected = false;
    
    // Check for debugging environment variables
    if (check_debug_env_vars()) {
        DEBUG_LOG_WARNING("Suspicious debugging environment variables detected");
        suspicious_detected = true;
    }
    
    // Check parent process for debugging tools
    pid_t ppid = getppid();
    char parent_name[256] = {0};
    if (proc_name(ppid, parent_name, sizeof(parent_name)) > 0) {
        if (check_debug_indicators(parent_name)) {
            DEBUG_LOG_WARNING("Debugging tools detected in parent process: %s", parent_name);
            suspicious_detected = true;
        }
        // Clear sensitive data
        secure_string_clear(parent_name, sizeof(parent_name));
    }
    
    return suspicious_detected;
}

bool perform_enhanced_vm_detection(void) {
    // Use obfuscated sysctl to get hardware model
    int mib[2] = {CTL_HW, HW_MODEL};
    size_t len = 0;
    
    if (obfuscated_sysctl(mib, 2, NULL, &len, NULL, 0) == 0 && len > 0) {
        char *model = malloc(len);
        if (model && obfuscated_sysctl(mib, 2, model, &len, NULL, 0) == 0) {
            bool is_vm = check_vm_indicators(model);
            
            if (is_vm) {
                DEBUG_LOG_WARNING("Virtual machine detected: %s", model);
            }
            
            // Securely clear sensitive data
            secure_string_clear(model, len);
            free(model);
            return is_vm;
        }
        if (model) free(model);
    }
    
    return false;
}

void cleanup_string_obfuscation_subsystem(void) {
    // Securely clear any remaining obfuscated strings or keys
    DEBUG_LOG_DEBUG("Cleaning up string obfuscation remnants");
    
    // Generate a random key to overwrite any remaining sensitive data
    uint64_t cleanup_key = generate_dynamic_key();
    volatile uint64_t *cleanup_ptr = &cleanup_key;
    *cleanup_ptr = 0; // Clear the key
}

static void obfuscate_runtime_strings(void) {
    // Build dynamic strings for internal use
    char framework_path[512];
    char lib_path[512];
    
    // Build paths dynamically to avoid hardcoded strings
    build_framework_path(framework_path, sizeof(framework_path), "Security");
    build_system_lib_path(lib_path, sizeof(lib_path), "libc");
    
    DEBUG_LOG_DEBUG("Dynamic paths constructed for runtime use");
    
    // Clear sensitive paths from memory
    secure_string_clear(framework_path, sizeof(framework_path));
    secure_string_clear(lib_path, sizeof(lib_path));
}
#endif

// Initialization and cleanup
void init_obfuscation_engine(void) {
DEBUG_LOG_INFO("Initializing advanced obfuscation engine");

#ifdef ENABLE_STRING_OBFUSCATION
    // Initialize string obfuscation subsystem
    init_string_obfuscation_subsystem();
    
    // Perform environment analysis with string obfuscation
    if (perform_enhanced_environment_checks()) {
        DEBUG_LOG_WARNING("Suspicious environment detected - enabling enhanced obfuscation");
    }
    
    // Perform VM detection with obfuscated strings
    if (perform_enhanced_vm_detection()) {
        DEBUG_LOG_WARNING("Virtual environment detected - adjusting obfuscation strategy");
    }
    
    // Obfuscate runtime strings
    obfuscate_runtime_strings();
#endif
    
    // Initialize all obfuscation subsystems conditionally
#ifdef ENABLE_VARIANT_GENERATION
    init_call_diversification();
    init_variant_generator();
    DEBUG_LOG_DEBUG("Variant generation initialized");
#endif
    
    init_api_misdirection();
    
#ifdef ENABLE_TIMING_OBFUSCATION
    init_timing_obfuscation_engine();
    DEBUG_LOG_DEBUG("Timing obfuscation initialized");
#endif
    
    // Set up integrity monitoring thread only if enabled at compile time AND runtime
#ifdef ENABLE_INTEGRITY_MONITORING
    pthread_t integrity_thread;
    if (pthread_create(&integrity_thread, NULL, integrity_monitor_thread, NULL) == 0) {
        pthread_detach(integrity_thread);
        DEBUG_LOG_DEBUG("Integrity monitoring thread started");
    }
#else
    DEBUG_LOG_DEBUG("Integrity monitoring thread disabled (compile-time)");
#endif
    
    // Generate variants for critical functions only if enabled
#ifdef ENABLE_VARIANT_GENERATION
    generate_ptrace_variants();
    generate_sysctl_variants();
    generate_detection_variants();
    DEBUG_LOG_DEBUG("Function variants generated");
#endif
    
    // Initialize function pointer obfuscation
    obfuscate_function_pointers();
    
    DEBUG_LOG_INFO("Advanced obfuscation engine initialized successfully");
    
    // Initialize function obfuscation registry
    init_function_registry();
    
    // Initialize random seed
    srand((unsigned int)time(NULL));
    
    // Add critical functions to monitoring table using direct references
    // This avoids dlsym calls that can be easily detected
#ifdef ENABLE_DIRECT_SYSCALLS
    add_function_to_table((void*)obfuscated_sysctl);
    add_function_to_table((void*)obfuscated_ptrace);
    DEBUG_LOG_DEBUG("Direct syscall functions added to monitoring table");
#endif
    
    // Initial memory scrambling
    scramble_memory_layout();
    
#ifdef ENABLE_STRING_OBFUSCATION
    // Final cleanup of any temporary strings used during initialization
    DEBUG_LOG_DEBUG("Performing final string cleanup");
    // Note: Individual functions already clear their own strings
#endif
    
    DEBUG_LOG_INFO("Obfuscation engine initialized with %d monitored functions", function_count);
}

void cleanup_obfuscation_engine(void) {
    clear_function_table();
    
#ifdef ENABLE_STRING_OBFUSCATION
    // Cleanup string obfuscation subsystem
    cleanup_string_obfuscation_subsystem();
#endif
    
    DEBUG_LOG_INFO("Obfuscation engine cleaned up");
}

// Real implementations for obfuscation functions
// Note: generate_dynamic_key is implemented in string_obfuscation.c

// Function pointer types for security checks
typedef bool (*security_check_func_t)(void);
typedef bool (*env_check_func_t)(void);

// Real debugger detection using multiple methods
bool advanced_debugger_check(void) {
    // Check 1: Process flags via direct sysctl (will use obfuscated version if enabled)
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        if (info.kp_proc.p_flag & P_TRACED) {
            return true;
        }
    }
    
    // Check 2: Parent process name analysis
    pid_t ppid = getppid();
    char parent_name[256] = {0};
    if (proc_name(ppid, parent_name, sizeof(parent_name)) > 0) {
        // Check for common debugger process names
        const char *debuggers[] = {"lldb", "gdb", "dtruss", "instruments", NULL};
        for (int i = 0; debuggers[i]; i++) {
            if (strstr(parent_name, debuggers[i])) {
                return true;
            }
        }
    }
    
    // Check 3: Environment variables
    const char *debug_env[] = {"DYLD_INSERT_LIBRARIES", "MallocStackLogging", "NSZombieEnabled", NULL};
    for (int i = 0; debug_env[i]; i++) {
        if (getenv(debug_env[i])) {
            return true;
        }
    }
    
    return false;
}

// Real VM detection using hardware characteristics
bool advanced_vm_check(void) {
    // Check 1: Hardware model
    size_t len = 0;
    int mib[2] = {CTL_HW, HW_MODEL};
    
    if (sysctl(mib, 2, NULL, &len, NULL, 0) == 0 && len > 0) {
        char *model = malloc(len);
        if (model && sysctl(mib, 2, model, &len, NULL, 0) == 0) {
            // Check for VM signatures
            const char *vm_signatures[] = {
                "VMware", "VirtualBox", "QEMU", "Parallels", 
                "KVM", "Xen", "VMM", "Virtual", NULL
            };
            
            for (int i = 0; vm_signatures[i]; i++) {
                if (strcasestr(model, vm_signatures[i])) {
                    free(model);
                    return true;
                }
            }
            free(model);
        }
    }
    
    // Check 2: CPU features (VM often lacks certain features)
    mib[1] = HW_NCPU;
    uint32_t ncpu = 0;
    len = sizeof(ncpu);
    if (sysctl(mib, 2, &ncpu, &len, NULL, 0) == 0 && ncpu < 2) {
        // Single CPU often indicates VM in server environments
        return true;
    }
    
    // Check 3: Memory size (VMs often have specific memory allocations)
    mib[1] = HW_MEMSIZE;
    uint64_t memsize = 0;
    len = sizeof(memsize);
    if (sysctl(mib, 2, &memsize, &len, NULL, 0) == 0) {
        // Check for common VM memory sizes (1GB, 2GB, 4GB exactly)
        uint64_t gb = 1024 * 1024 * 1024;
        if (memsize == gb || memsize == 2*gb || memsize == 4*gb) {
            return true;
        }
    }
    
    return false;
}

// Real environment analysis
bool advanced_env_check(void) {
    // Check 1: Unusual process hierarchy
    pid_t parent = getppid();
    
    // Check if we're running under unusual parent processes
    char parent_path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (proc_pidpath(parent, parent_path, sizeof(parent_path)) > 0) {
        const char *suspicious_paths[] = {
            "/usr/bin/python", "/usr/bin/perl", "/usr/bin/ruby",
            "/usr/bin/node", "/tmp/", "/var/tmp/", NULL
        };
        
        for (int i = 0; suspicious_paths[i]; i++) {
            if (strstr(parent_path, suspicious_paths[i])) {
                return true;
            }
        }
    }
    
    // Check 2: File system analysis - look for analysis tools
    const char *analysis_paths[] = {
        "/usr/local/bin/radare2", "/usr/local/bin/r2",
        "/usr/bin/objdump", "/usr/bin/nm", "/usr/bin/otool",
        "/Applications/Hopper Disassembler v4.app",
        "/Applications/IDA Pro.app", NULL
    };
    
    for (int i = 0; analysis_paths[i]; i++) {
        if (access(analysis_paths[i], F_OK) == 0) {
            return true;
        }
    }
    
    return false;
}

// Note: get_security_checker and get_env_checker are implemented in function_obfuscation.c

// Note: obfuscated_sysctl and obfuscated_ptrace are implemented in string_obfuscation.c

// Note: variant generation functions are implemented in variant_generator.c

// Note: check_vm_indicators is implemented in string_obfuscation.c
