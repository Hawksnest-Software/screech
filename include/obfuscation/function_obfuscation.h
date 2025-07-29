//
// function_obfuscation.h - Function name obfuscation and dynamic calling
// Provides runtime function resolution to avoid obvious function names
//

#ifndef FUNCTION_OBFUSCATION_H
#define FUNCTION_OBFUSCATION_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Function pointer types for obfuscated calls
typedef bool (*security_check_func_t)(void);
typedef bool (*env_check_func_t)(void);
typedef void (*protection_func_t)(void);
typedef void (*monitoring_func_t)(void);

// Dynamic function resolution
typedef struct {
    const char* obfuscated_name;
    void* function_ptr;
    uint32_t name_hash;
} function_registry_entry_t;

// Function registry management
void init_function_registry(void);
void register_obfuscated_function(const char* obfuscated_name, void* func_ptr);
void* resolve_obfuscated_function(const char* obfuscated_name);
uint32_t hash_function_name(const char* name);

// Obfuscated function name macros - these create runtime-constructed names
#define OBFUSCATED_FUNC(base, suffix) resolve_obfuscated_function(construct_func_name(base, suffix))

// Dynamic function calling wrappers
security_check_func_t get_security_checker(uint32_t type);
env_check_func_t get_env_checker(void);
protection_func_t get_memory_protector(void);
monitoring_func_t get_monitor_starter(void);

// Helper functions for dynamic name construction
char* construct_func_name(const char* base, const char* suffix);
void scramble_function_names(void);
void restore_function_names(void);

#ifdef __cplusplus
}
#endif

#endif // FUNCTION_OBFUSCATION_H
