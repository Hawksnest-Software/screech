//
// function_obfuscation.c - Function name obfuscation implementation
//

#include "function_obfuscation.h"
#include "string_obfuscation.h"
#include "obfuscation_engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_FUNCTIONS 64
#define MAX_NAME_LEN 128

static function_registry_entry_t function_registry[MAX_FUNCTIONS];
static size_t registry_count = 0;
static bool registry_initialized = false;

// Initialize the function registry
void init_function_registry(void) {
    if (registry_initialized) return;
    
    memset(function_registry, 0, sizeof(function_registry));
    registry_count = 0;
    
    // Register core functions with obfuscated names
    // Instead of "detect_debugger", use runtime-constructed names
    char dbg_name[MAX_NAME_LEN];
    construct_stack_string(dbg_name, sizeof(dbg_name), "sec", "_", "chk", "_", "001", NULL);
    register_obfuscated_function(dbg_name, (void*)detect_debugger);
    secure_string_clear(dbg_name, strlen(dbg_name));
    
    char vm_name[MAX_NAME_LEN];
    construct_stack_string(vm_name, sizeof(vm_name), "env", "_", "val", "_", "002", NULL);
    register_obfuscated_function(vm_name, (void*)detect_virtual_machine);
    secure_string_clear(vm_name, strlen(vm_name));
    
    char env_name[MAX_NAME_LEN];
    construct_stack_string(env_name, sizeof(env_name), "cfg", "_", "chk", "_", "003", NULL);
    register_obfuscated_function(env_name, (void*)check_debug_env_vars);
    secure_string_clear(env_name, strlen(env_name));
    
    registry_initialized = true;
}

// Register a function with an obfuscated name
void register_obfuscated_function(const char* obfuscated_name, void* func_ptr) {
    if (registry_count >= MAX_FUNCTIONS) return;
    
    function_registry_entry_t* entry = &function_registry[registry_count];
    
    // Store a copy of the name (will be cleared later)
    static char name_storage[MAX_FUNCTIONS][MAX_NAME_LEN];
    strncpy(name_storage[registry_count], obfuscated_name, MAX_NAME_LEN - 1);
    name_storage[registry_count][MAX_NAME_LEN - 1] = '\0';
    
    entry->obfuscated_name = name_storage[registry_count];
    entry->function_ptr = func_ptr;
    entry->name_hash = hash_function_name(obfuscated_name);
    
    registry_count++;
}

// Resolve an obfuscated function by name
void* resolve_obfuscated_function(const char* obfuscated_name) {
    if (!registry_initialized) {
        init_function_registry();
    }
    
    uint32_t target_hash = hash_function_name(obfuscated_name);
    
    for (size_t i = 0; i < registry_count; i++) {
        if (function_registry[i].name_hash == target_hash) {
            // Additional string comparison to avoid hash collisions
            if (strcmp(function_registry[i].obfuscated_name, obfuscated_name) == 0) {
                return function_registry[i].function_ptr;
            }
        }
    }
    
    return NULL;
}

// Hash function names for fast lookup
uint32_t hash_function_name(const char* name) {
    uint32_t hash = 5381;
    for (const char* p = name; *p; p++) {
        hash = ((hash << 5) + hash) + *p;
    }
    return hash;
}

// Get security checker function by type
security_check_func_t get_security_checker(uint32_t type) {
    char func_name[MAX_NAME_LEN];
    
    switch (type) {
        case 1: // Debugger detection
            construct_stack_string(func_name, sizeof(func_name), "sec", "_", "chk", "_", "001", NULL);
            break;
        case 2: // VM detection  
            construct_stack_string(func_name, sizeof(func_name), "env", "_", "val", "_", "002", NULL);
            break;
        default:
            return NULL;
    }
    
    security_check_func_t func = (security_check_func_t)resolve_obfuscated_function(func_name);
    secure_string_clear(func_name, strlen(func_name));
    
    return func;
}

// Get environment checker function
env_check_func_t get_env_checker(void) {
    char func_name[MAX_NAME_LEN];
    construct_stack_string(func_name, sizeof(func_name), "cfg", "_", "chk", "_", "003", NULL);
    
    env_check_func_t func = (env_check_func_t)resolve_obfuscated_function(func_name);
    secure_string_clear(func_name, strlen(func_name));
    
    return func;
}

// Get memory protector function
protection_func_t get_memory_protector(void) {
    // For now, return a placeholder - could be expanded
    return NULL;
}

// Get monitor starter function
monitoring_func_t get_monitor_starter(void) {
    // For now, return a placeholder - could be expanded
    return NULL;
}

// Construct function names dynamically
char* construct_func_name(const char* base, const char* suffix) {
    static char name_buffer[MAX_NAME_LEN];
    
    // Clear previous content
    secure_string_clear(name_buffer, sizeof(name_buffer));
    
    // Construct name from parts
    construct_stack_string(name_buffer, sizeof(name_buffer), base, "_", suffix, NULL);
    
    return name_buffer;
}

// Scramble function names in registry (for anti-analysis)
void scramble_function_names(void) {
    if (!registry_initialized) return;
    
    // Generate a pseudo-random scrambling key
    uint32_t scramble_key = calculate_runtime_constant("scramble");
    
    for (size_t i = 0; i < registry_count; i++) {
        // Modify the hash to scramble lookups
        function_registry[i].name_hash ^= scramble_key;
    }
}

// Restore function names (reverse scrambling)
void restore_function_names(void) {
    if (!registry_initialized) return;
    
    // Use same key to restore
    uint32_t scramble_key = calculate_runtime_constant("scramble");
    
    for (size_t i = 0; i < registry_count; i++) {
        // Restore original hash
        function_registry[i].name_hash ^= scramble_key;
    }
}
