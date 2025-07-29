//
// obfuscation_config.h - Runtime configuration for obfuscation features
//

#ifndef OBFUSCATION_CONFIG_H
#define OBFUSCATION_CONFIG_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // Core obfuscation features
    bool enable_function_pointer_obfuscation;
    bool enable_anti_disassembly;
    bool enable_memory_scrambling;
    bool enable_syscall_randomization;
    
    // Security checks
    bool enable_debugger_detection;
    bool enable_vm_detection;
    bool enable_env_checks;
    
    // Advanced features
    bool enable_integrity_monitoring;
    bool enable_variant_generation;
    bool enable_string_obfuscation;
    bool enable_timing_obfuscation;
    
    // Aggressive features (most likely to cause issues)
    bool enable_direct_syscalls;
    bool enable_ptrace_protection;
    bool enable_anti_debug_ptrace;
} obfuscation_config_t;

// Default configurations
extern const obfuscation_config_t OBFUSCATION_CONFIG_MINIMAL;
extern const obfuscation_config_t OBFUSCATION_CONFIG_MODERATE;  
extern const obfuscation_config_t OBFUSCATION_CONFIG_FULL;

// Global configuration
extern obfuscation_config_t g_obfuscation_config;

// Configuration functions
void obfuscation_config_init_minimal(void);
void obfuscation_config_init_moderate(void);
void obfuscation_config_init_full(void);
void obfuscation_config_set_custom(const obfuscation_config_t* config);

// Runtime feature checks
bool obfuscation_is_enabled(const char* feature_name);
void obfuscation_config_print(void);

#ifdef __cplusplus
}
#endif

#endif // OBFUSCATION_CONFIG_H
