//
// obfuscation_engine.h - Pure C Obfuscation Engine
// Core obfuscation functionality that doesn't require Objective-C
//

#ifndef OBFUSCATION_ENGINE_H
#define OBFUSCATION_ENGINE_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// Core obfuscation functions
bool detect_function_hooks(void *functionPtr);
void obfuscate_function_pointers(void);
void insert_anti_disassembly_code(void);
void scramble_memory_layout(void);
void randomize_syscall_order(void);

// Detection functions
bool detect_debugger(void);
bool detect_virtual_machine(void);

// Threading functions
void* integrity_monitor_thread(void *arg);

// Function table management
int add_function_to_table(void *original_func);
void clear_function_table(void);

// Advanced obfuscation subsystem initialization
void init_call_diversification(void);
void init_variant_generator(void);
void init_api_misdirection(void);
void init_timing_obfuscation_engine(void);
void generate_ptrace_variants(void);
void generate_sysctl_variants(void);
void generate_detection_variants(void);

// Dynamic key generation
uint64_t generate_dynamic_key(void);

// Security check function types
typedef bool (*security_check_func_t)(void);
typedef bool (*env_check_func_t)(void);

// Security checker functions
security_check_func_t get_security_checker(uint32_t type);
env_check_func_t get_env_checker(void);

// Obfuscated system calls
long obfuscated_sysctl(int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen);
long obfuscated_ptrace(int request, int pid, void* addr, void* data);

// VM detection helpers
bool check_vm_indicators(const char* model);

// Function registry
void init_function_registry(void);

// Initialization
void init_obfuscation_engine(void);
void cleanup_obfuscation_engine(void);

#ifdef __cplusplus
}
#endif

#endif // OBFUSCATION_ENGINE_H
