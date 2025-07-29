//
// obfuscation_config.c - Runtime configuration for obfuscation features
//

#include "obfuscation_config.h"
#include "debug_logging.h"
#include <string.h>
#include <stdlib.h>

// Global configuration instance
obfuscation_config_t g_obfuscation_config;

// Minimal configuration - safest, least likely to cause issues
const obfuscation_config_t OBFUSCATION_CONFIG_MINIMAL = {
    .enable_function_pointer_obfuscation = false,
    .enable_anti_disassembly = false,
    .enable_memory_scrambling = true,       // Usually safe
    .enable_syscall_randomization = false,
    
    .enable_debugger_detection = false,     // Disable aggressive detection
    .enable_vm_detection = false,
    .enable_env_checks = false,
    
    .enable_integrity_monitoring = false,   // Only enabled via compile flag
    .enable_variant_generation = false,
    .enable_string_obfuscation = true,      // Usually safe
    .enable_timing_obfuscation = false,
    
    .enable_direct_syscalls = false,        // Most likely to cause issues
    .enable_ptrace_protection = false,
    .enable_anti_debug_ptrace = false
};

// Moderate configuration - balance between protection and stability
const obfuscation_config_t OBFUSCATION_CONFIG_MODERATE = {
    .enable_function_pointer_obfuscation = true,
    .enable_anti_disassembly = true,
    .enable_memory_scrambling = true,
    .enable_syscall_randomization = true,
    
    .enable_debugger_detection = true,
    .enable_vm_detection = true,
    .enable_env_checks = true,
    
    .enable_integrity_monitoring = false,   // Only enabled via compile flag
    .enable_variant_generation = true,
    .enable_string_obfuscation = true,
    .enable_timing_obfuscation = true,
    
    .enable_direct_syscalls = false,        // Still risky
    .enable_ptrace_protection = false,
    .enable_anti_debug_ptrace = false
};

// Full configuration - maximum protection, highest risk
const obfuscation_config_t OBFUSCATION_CONFIG_FULL = {
    .enable_function_pointer_obfuscation = true,
    .enable_anti_disassembly = true,
    .enable_memory_scrambling = true,
    .enable_syscall_randomization = true,
    
    .enable_debugger_detection = true,
    .enable_vm_detection = true,
    .enable_env_checks = true,
    
    .enable_integrity_monitoring = false,   // Only enabled via compile flag
    .enable_variant_generation = true,
    .enable_string_obfuscation = true,
    .enable_timing_obfuscation = true,
    
    .enable_direct_syscalls = true,
    .enable_ptrace_protection = true,
    .enable_anti_debug_ptrace = true
};

void obfuscation_config_init_minimal(void) {
    g_obfuscation_config = OBFUSCATION_CONFIG_MINIMAL;
    DEBUG_LOG_INFO("Obfuscation initialized with MINIMAL configuration");
}

void obfuscation_config_init_moderate(void) {
    g_obfuscation_config = OBFUSCATION_CONFIG_MODERATE;
    DEBUG_LOG_INFO("Obfuscation initialized with MODERATE configuration");
}

void obfuscation_config_init_full(void) {
    g_obfuscation_config = OBFUSCATION_CONFIG_FULL;
    DEBUG_LOG_INFO("Obfuscation initialized with FULL configuration");
}

void obfuscation_config_set_custom(const obfuscation_config_t* config) {
    if (config) {
        g_obfuscation_config = *config;
        DEBUG_LOG_INFO("Obfuscation initialized with CUSTOM configuration");
    }
}

bool obfuscation_is_enabled(const char* feature_name) {
    if (!feature_name) return false;
    
    if (strcmp(feature_name, "function_pointer_obfuscation") == 0) {
        return g_obfuscation_config.enable_function_pointer_obfuscation;
    } else if (strcmp(feature_name, "anti_disassembly") == 0) {
        return g_obfuscation_config.enable_anti_disassembly;
    } else if (strcmp(feature_name, "memory_scrambling") == 0) {
        return g_obfuscation_config.enable_memory_scrambling;
    } else if (strcmp(feature_name, "syscall_randomization") == 0) {
        return g_obfuscation_config.enable_syscall_randomization;
    } else if (strcmp(feature_name, "debugger_detection") == 0) {
        return g_obfuscation_config.enable_debugger_detection;
    } else if (strcmp(feature_name, "vm_detection") == 0) {
        return g_obfuscation_config.enable_vm_detection;
    } else if (strcmp(feature_name, "env_checks") == 0) {
        return g_obfuscation_config.enable_env_checks;
    } else if (strcmp(feature_name, "integrity_monitoring") == 0) {
        return g_obfuscation_config.enable_integrity_monitoring;
    } else if (strcmp(feature_name, "variant_generation") == 0) {
        return g_obfuscation_config.enable_variant_generation;
    } else if (strcmp(feature_name, "string_obfuscation") == 0) {
        return g_obfuscation_config.enable_string_obfuscation;
    } else if (strcmp(feature_name, "timing_obfuscation") == 0) {
        return g_obfuscation_config.enable_timing_obfuscation;
    } else if (strcmp(feature_name, "direct_syscalls") == 0) {
        return g_obfuscation_config.enable_direct_syscalls;
    } else if (strcmp(feature_name, "ptrace_protection") == 0) {
        return g_obfuscation_config.enable_ptrace_protection;
    } else if (strcmp(feature_name, "anti_debug_ptrace") == 0) {
        return g_obfuscation_config.enable_anti_debug_ptrace;
    }
    
    return false;
}

void obfuscation_config_print(void) {
    DEBUG_LOG_INFO("=== Obfuscation Configuration ===");
    DEBUG_LOG_INFO("Function Pointer Obfuscation: %s", g_obfuscation_config.enable_function_pointer_obfuscation ? "ON" : "OFF");
    DEBUG_LOG_INFO("Anti-Disassembly: %s", g_obfuscation_config.enable_anti_disassembly ? "ON" : "OFF");
    DEBUG_LOG_INFO("Memory Scrambling: %s", g_obfuscation_config.enable_memory_scrambling ? "ON" : "OFF");
    DEBUG_LOG_INFO("Syscall Randomization: %s", g_obfuscation_config.enable_syscall_randomization ? "ON" : "OFF");
    DEBUG_LOG_INFO("Debugger Detection: %s", g_obfuscation_config.enable_debugger_detection ? "ON" : "OFF");
    DEBUG_LOG_INFO("VM Detection: %s", g_obfuscation_config.enable_vm_detection ? "ON" : "OFF");
    DEBUG_LOG_INFO("Environment Checks: %s", g_obfuscation_config.enable_env_checks ? "ON" : "OFF");
    DEBUG_LOG_INFO("Integrity Monitoring: %s", g_obfuscation_config.enable_integrity_monitoring ? "ON" : "OFF");
    DEBUG_LOG_INFO("Variant Generation: %s", g_obfuscation_config.enable_variant_generation ? "ON" : "OFF");
    DEBUG_LOG_INFO("String Obfuscation: %s", g_obfuscation_config.enable_string_obfuscation ? "ON" : "OFF");
    DEBUG_LOG_INFO("Timing Obfuscation: %s", g_obfuscation_config.enable_timing_obfuscation ? "ON" : "OFF");
    DEBUG_LOG_INFO("Direct Syscalls: %s", g_obfuscation_config.enable_direct_syscalls ? "ON" : "OFF");
    DEBUG_LOG_INFO("Ptrace Protection: %s", g_obfuscation_config.enable_ptrace_protection ? "ON" : "OFF");
    DEBUG_LOG_INFO("Anti-Debug Ptrace: %s", g_obfuscation_config.enable_anti_debug_ptrace ? "ON" : "OFF");
    DEBUG_LOG_INFO("===============================");
}
