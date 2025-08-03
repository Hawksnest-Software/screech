// call_diversification.c - API misdirection and diversified call paths implementation
#include "call_diversification.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>

// Global call diversifier configuration
static call_diversifier_t ptrace_diversifier;
static call_diversifier_t sysctl_diversifier;
static decoy_registry_t decoy_registry;

void init_call_diversification(void) {
    srand(time(NULL));

    ptrace_diversifier.variant_count = MAX_CALL_VARIANTS;
    for (int i = 0; i < ptrace_diversifier.variant_count; i++) {
        ptrace_diversifier.variants[i] = sysctl_diversifier.variants[i] = NULL;  // Placeholder for variant functions
    }
    ptrace_diversifier.active_variant = rand() % ptrace_diversifier.variant_count;

    sysctl_diversifier.variant_count = MAX_CALL_VARIANTS;
    sysctl_diversifier.active_variant = rand() % sysctl_diversifier.variant_count;

    init_decoy_functions();
}

void update_call_variants(void) {
    if (should_switch_variant()) {
        ptrace_diversifier.active_variant = rand() % ptrace_diversifier.variant_count;
        sysctl_diversifier.active_variant = rand() % sysctl_diversifier.variant_count;
        printf("Variants updated: ptrace -> %d, sysctl -> %d\n", 
               ptrace_diversifier.active_variant, sysctl_diversifier.active_variant);
    }
}

uint8_t select_call_variant(const char* func_name) {
    // Select variant based on function name hash
    if (!func_name) return 0;
    
    uint32_t hash = 0;
    for (const char* p = func_name; *p; p++) {
        hash = hash * 31 + (uint32_t)*p;
    }
    
    return (uint8_t)(hash % MAX_CALL_VARIANTS);
}

bool should_switch_variant(void) {
    return (rand() % 100) < 10;  // 10% chance of switching
}

long diversified_ptrace_call(int request, int pid, void* addr, void* data) {
    update_call_variants();
    syscall_variant_func_t func = ptrace_diversifier.variants[ptrace_diversifier.active_variant];
    if (func != NULL) return func(request, pid, addr, data);
    return -1;  // Default fail
}

long diversified_sysctl_call(int* name, unsigned int namelen, void* oldp, 
                             size_t* oldlenp, void* newp, size_t newlen) {
    update_call_variants();
    
    // Validate parameters before proceeding
    if (!name || namelen == 0) {
        return -1;
    }
    
    // Add some obfuscation delay based on the call type
    if (name[0] > 0) {
        usleep(rand() % 1000); // Random delay up to 1ms
    }
    
    // For now, simulate a successful sysctl call based on the parameters
    if (oldp && oldlenp) {
        // Simulate reading system information
        *oldlenp = (*oldlenp > sizeof(int)) ? sizeof(int) : *oldlenp;
        if (*oldlenp > 0) {
            *(int*)oldp = rand(); // Return random data as placeholder
        }
        return 0;
    }
    
    if (newp && newlen > 0) {
        // Simulate setting system information (but don't actually change anything)
        return 0;
    }
    
    return -1;
}

// Placeholder for decoy functions
void decoy_network_init(void) { printf("Decoy network init\n"); }
void decoy_file_monitor(void) { printf("Decoy file monitor\n"); }
void decoy_process_scan(void) { printf("Decoy process scan\n"); }
void decoy_memory_check(void) { printf("Decoy memory check\n"); }
void decoy_registry_access(void) { printf("Decoy registry access\n"); }
void decoy_service_enum(void) { printf("Decoy service enum\n"); }
void decoy_driver_load(void) { printf("Decoy driver load\n"); }
void decoy_thread_monitor(void) { printf("Decoy thread monitor\n"); }

void init_decoy_functions(void) {
    decoy_registry.decoy_funcs[0] = decoy_network_init;
    decoy_registry.decoy_funcs[1] = decoy_file_monitor;
    decoy_registry.decoy_funcs[2] = decoy_process_scan;
    decoy_registry.decoy_funcs[3] = decoy_memory_check;
    decoy_registry.decoy_funcs[4] = decoy_registry_access;
    decoy_registry.decoy_funcs[5] = decoy_service_enum;
    decoy_registry.decoy_funcs[6] = decoy_driver_load;
    decoy_registry.decoy_funcs[7] = decoy_thread_monitor;
    decoy_registry.decoy_count = 8;

    decoy_registry.active = false;
}

void activate_random_decoys(void) {
    if (!decoy_registry.active) {
        for (int i = 0; i < decoy_registry.decoy_count; i++) {
            if (rand() % 2) {  // 50% chance to activate
                decoy_registry.decoy_funcs[i]();
            }
        }
        decoy_registry.active = true;
    }
}

void deactivate_decoys(void) {
    decoy_registry.active = false;
}
