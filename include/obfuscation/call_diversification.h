//
// call_diversification.h - API misdirection and diversified call paths
// Provides automated function diversification and decoy API functions
//

#ifndef CALL_DIVERSIFICATION_H
#define CALL_DIVERSIFICATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Function pointer types for diversified calls
typedef long (*syscall_variant_func_t)(int, int, void*, void*);
typedef int (*detection_variant_func_t)(void);
typedef bool (*check_variant_func_t)(const char*);

// Diversification configuration
#define MAX_CALL_VARIANTS 8
#define MAX_DECOY_FUNCTIONS 16

// Function variant selector - changes behavior based on runtime state
typedef struct {
    uint32_t seed;
    uint8_t variant_count;
    uint8_t active_variant;
    uint64_t last_switch_time;
    syscall_variant_func_t variants[MAX_CALL_VARIANTS];
} call_diversifier_t;

// Decoy function registry
typedef struct {
    void (*decoy_funcs[MAX_DECOY_FUNCTIONS])(void);
    uint8_t decoy_count;
    bool active;
} decoy_registry_t;

// API misdirection macros - automatically diversify function calls
#define DIVERSIFIED_PTRACE(req, pid, addr, data) \
    diversified_ptrace_call(req, pid, addr, data)

#define DIVERSIFIED_SYSCTL(name, namelen, oldp, oldlenp, newp, newlen) \
    diversified_sysctl_call(name, namelen, oldp, oldlenp, newp, newlen)

#define DIVERSIFIED_DETECT() \
    diversified_detection_check()

// Automated variant generation macros
#define DECLARE_VARIANT_FUNC(base_name, variant_id) \
    static long base_name##_variant_##variant_id(int req, int pid, void* addr, void* data)

#define IMPLEMENT_VARIANT_FUNC(base_name, variant_id, implementation) \
    static long base_name##_variant_##variant_id(int req, int pid, void* addr, void* data) { \
        implementation \
    }

// Core diversification functions
void init_call_diversification(void);
void update_call_variants(void);
uint8_t select_call_variant(const char* func_name);

// Diversified API entry points
long diversified_ptrace_call(int request, int pid, void* addr, void* data);
long diversified_sysctl_call(int* name, unsigned int namelen, void* oldp, 
                           size_t* oldlenp, void* newp, size_t newlen);
int diversified_detection_check(void);
bool diversified_process_check(const char* process_name);

// Decoy API functions (misdirection)
void init_decoy_functions(void);
void activate_random_decoys(void);
void deactivate_decoys(void);

// Decoy function declarations (appear in symbol table)
void decoy_network_init(void);
void decoy_file_monitor(void);
void decoy_process_scan(void);
void decoy_memory_check(void);
void decoy_registry_access(void);
void decoy_service_enum(void);
void decoy_driver_load(void);
void decoy_thread_monitor(void);

// Automated variant management
void register_function_variants(void);
void rotate_active_variants(void);
bool should_switch_variant(void);

// Runtime polymorphism support
void generate_runtime_variants(void);
void obfuscate_call_sequence(void);

#ifdef __cplusplus
}
#endif

#endif // CALL_DIVERSIFICATION_H
