#include "obfuscation_engine.h"
#include "string_obfuscation.h"
#include "stealth_logging.h"
#include "function_obfuscation.h"
#include "timing_obfuscation.h"
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

void obfuscate_function_pointers() {
    pthread_mutex_lock(&obfuscation_mutex);
    
    // Generate dynamic key instead of hardcoded value
    uint64_t dynamic_key = generate_dynamic_key();
    
    for (int i = 0; i < function_count; i++) {
        uintptr_t original = (uintptr_t)function_table[i].original;
        function_table[i].obfuscated = (void *)(original ^ dynamic_key);
    }
    pthread_mutex_unlock(&obfuscation_mutex);
}

void insert_anti_disassembly_code() {
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

void scramble_memory_layout() {
    for (int i = 0; i < 10; i++) {
        size_t random_size = rand() % 4096 + 1024;
        void *ptr = malloc(random_size);
        if (ptr) {
            memset(ptr, rand() % 256, random_size);
            free(ptr);
        }
    }
}

void randomize_syscall_order() {
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

void* integrity_monitor_thread(void *arg) {
    while (1) {
        if (!detect_function_hooks((void*) &obfuscate_function_pointers)) {
            STEALTH_LOG_WARNING("Code integrity violation detected");
        }
        
        // Use obfuscated function calls
        security_check_func_t debugger_check = get_security_checker(1);
        if (debugger_check && debugger_check()) {
            STEALTH_LOG_WARNING("Analysis environment detected");
        }
        
        security_check_func_t vm_check = get_security_checker(2);
        if (vm_check && vm_check()) {
            STEALTH_LOG_WARNING("Virtual environment detected");
        }
        
        env_check_func_t env_check = get_env_checker();
        if (env_check && env_check()) {
            STEALTH_LOG_WARNING("Suspicious environment detected");
        }
        
        sleep(5);
    }
    return NULL;
}

bool detect_debugger() {
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
            // PT_DENY_ATTACH on macOS - will terminate if debugger attached
            if (obfuscated_ptrace(31, 0, NULL, NULL) == -1) {  // PT_DENY_ATTACH = 31
                return true; // Debugger likely present
            }
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

bool detect_virtual_machine() {
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

// Initialization and cleanup
void init_obfuscation_engine(void) {
    // Initialize stealth logging system
    stealth_log_init();
    
    // Initialize all obfuscation subsystems
    init_call_diversification();
    init_variant_generator();
    init_api_misdirection();
    init_timing_obfuscation_engine();
    
    STEALTH_LOG_INFO("Initializing advanced obfuscation engine");
    
    // Set up integrity monitoring thread
    pthread_t integrity_thread;
    if (pthread_create(&integrity_thread, NULL, integrity_monitor_thread, NULL) == 0) {
        pthread_detach(integrity_thread);
        STEALTH_LOG_DEBUG("Integrity monitoring thread started");
    }
    
    // Generate variants for critical functions
    generate_ptrace_variants();
    generate_sysctl_variants();
    generate_detection_variants();
    
    STEALTH_LOG_DEBUG("Function variants generated");
    
    // Initialize function pointer obfuscation
    obfuscate_function_pointers();
    
    STEALTH_LOG_INFO("Advanced obfuscation engine initialized successfully");
    stealth_log_init();
    
    // Initialize function obfuscation registry
    init_function_registry();
    
    // Initialize random seed
    srand((unsigned int)time(NULL));
    
    // Add critical functions to monitoring table using direct references
    // This avoids dlsym calls that can be easily detected
    add_function_to_table((void*)obfuscated_sysctl);
    add_function_to_table((void*)obfuscated_ptrace);
    
    // Initial memory scrambling
    scramble_memory_layout();
    
    STEALTH_LOG_INFO("Obfuscation engine initialized with %d monitored functions", function_count);
}

void cleanup_obfuscation_engine(void) {
    clear_function_table();
    STEALTH_LOG_INFO("Obfuscation engine cleaned up");
}
