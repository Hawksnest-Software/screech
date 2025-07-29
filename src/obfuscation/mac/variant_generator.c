//
// variant_generator.c - Automated function variant generation implementation
//

#include "variant_generator.h"
#include "string_obfuscation.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

// Global variant state
static uint32_t runtime_seed = 0;
static uint64_t variant_switch_counter = 0;
static bool generator_initialized = false;

// Hash table for function variant tracking
#define VARIANT_HASH_SIZE 64
static function_variant_t variant_registry[VARIANT_HASH_SIZE][MAX_VARIANTS];
static uint8_t registry_counts[VARIANT_HASH_SIZE] = {0};

// Hash function for function names
static uint32_t hash_function_name(const char* name) {
    uint32_t hash = 5381;
    for (const char* p = name; *p; p++) {
        hash = ((hash << 5) + hash) + *p;
    }
    return hash % VARIANT_HASH_SIZE;
}

void init_variant_generator(void) {
    if (generator_initialized) return;
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    runtime_seed = (uint32_t)(tv.tv_sec ^ tv.tv_usec ^ getpid());
    
    // Initialize variant registry
    memset(variant_registry, 0, sizeof(variant_registry));
    memset(registry_counts, 0, sizeof(registry_counts));
    
    generator_initialized = true;
    
    // Generate variants for critical functions
    generate_ptrace_variants();
    generate_sysctl_variants();
    generate_detection_variants();
}

uint32_t get_runtime_seed(void) {
    // Update seed periodically to add entropy
    variant_switch_counter++;
    if (variant_switch_counter % 100 == 0) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        runtime_seed ^= (uint32_t)tv.tv_usec;
    }
    return runtime_seed;
}

uint64_t calculate_noise_value(void) {
    uint64_t noise = get_runtime_seed();
    noise = (noise << 16) ^ (noise >> 16);
    noise ^= (uint64_t)&noise; // Add stack address entropy
    return noise;
}

uint8_t select_runtime_variant(const char* func_name) {
    if (!generator_initialized) {
        init_variant_generator();
    }
    
    uint32_t hash = hash_function_name(func_name);
    uint32_t seed = get_runtime_seed();
    
    // Use function name hash and runtime seed to select variant
    uint8_t variant = (hash ^ seed ^ variant_switch_counter) % MAX_VARIANTS;
    return variant;
}

void register_function_variants(const char* func_name, void** variants, uint8_t count) {
    uint32_t hash = hash_function_name(func_name);
    
    for (uint8_t i = 0; i < count && i < MAX_VARIANTS; i++) {
        variant_registry[hash][i].function_ptr = variants[i];
        variant_registry[hash][i].info.id = i;
        variant_registry[hash][i].info.type = i % VARIANT_TYPE_COUNT;
        variant_registry[hash][i].info.complexity_level = (i * 2) % 10;
        variant_registry[hash][i].is_active = true;
        
        // Generate random seed for this variant
        for (int j = 0; j < VARIANT_SEED_SIZE; j++) {
            variant_registry[hash][i].info.seed[j] = (get_runtime_seed() >> (j % 4)) & 0xFF;
        }
    }
    
    registry_counts[hash] = count;
}

void update_variant_selection(void) {
    variant_switch_counter++;
    
    // Periodically update runtime seed
    if (variant_switch_counter % 50 == 0) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        runtime_seed = (runtime_seed << 1) ^ (uint32_t)tv.tv_usec;
    }
}

// Critical function variant generation

// Forward declarations for base functions
static long obfuscated_ptrace_base(int request, int pid, void* addr, void* data);
static long obfuscated_sysctl_base(int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen);
static int detect_debugger_base(void);

// Generate ptrace variants using the macro system
VARIANT_0_IMPL(obfuscated_ptrace, long, (int request, int pid, void* addr, void* data), {
    return obfuscated_ptrace_base(request, pid, addr, data);
})

VARIANT_1_IMPL(obfuscated_ptrace, long, (int request, int pid, void* addr, void* data), {
    return obfuscated_ptrace_base(request, pid, addr, data);
})

VARIANT_2_IMPL(obfuscated_ptrace, long, (int request, int pid, void* addr, void* data), {
    return obfuscated_ptrace_base(request, pid, addr, data);
})

VARIANT_3_IMPL(obfuscated_ptrace, long, (int request, int pid, void* addr, void* data), {
    return obfuscated_ptrace_base(request, pid, addr, data);
})

VARIANT_4_IMPL(obfuscated_ptrace, long, (int request, int pid, void* addr, void* data), {
    return obfuscated_ptrace_base(request, pid, addr, data);
})

VARIANT_5_IMPL(obfuscated_ptrace, long, (int request, int pid, void* addr, void* data), {
    return obfuscated_ptrace_base(request, pid, addr, data);
})

VARIANT_6_IMPL(obfuscated_ptrace, long, (int request, int pid, void* addr, void* data), {
    return obfuscated_ptrace_base(request, pid, addr, data);
})

VARIANT_7_IMPL(obfuscated_ptrace, long, (int request, int pid, void* addr, void* data), {
    return obfuscated_ptrace_base(request, pid, addr, data);
})

// Base ptrace implementation (from string_obfuscation.c)
static long obfuscated_ptrace_base(int request, int pid, void* addr, void* data) {
    // This would call the actual obfuscated_ptrace implementation
    // For now, return a placeholder
    return -1;
}

// Generate variant table for ptrace
DECLARE_VARIANT_TABLE(obfuscated_ptrace, long, (int, int, void*, void*))

void generate_ptrace_variants(void) {
    void* variants[MAX_VARIANTS] = {
        (void*)obfuscated_ptrace_variant_0,
        (void*)obfuscated_ptrace_variant_1,
        (void*)obfuscated_ptrace_variant_2,
        (void*)obfuscated_ptrace_variant_3,
        (void*)obfuscated_ptrace_variant_4,
        (void*)obfuscated_ptrace_variant_5,
        (void*)obfuscated_ptrace_variant_6,
        (void*)obfuscated_ptrace_variant_7
    };
    
    register_function_variants("obfuscated_ptrace", variants, MAX_VARIANTS);
}

// Generate sysctl variants
VARIANT_0_IMPL(obfuscated_sysctl, long, (int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen), {
    return obfuscated_sysctl_base(name, namelen, oldp, oldlenp, newp, newlen);
})

VARIANT_1_IMPL(obfuscated_sysctl, long, (int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen), {
    return obfuscated_sysctl_base(name, namelen, oldp, oldlenp, newp, newlen);
})

VARIANT_2_IMPL(obfuscated_sysctl, long, (int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen), {
    return obfuscated_sysctl_base(name, namelen, oldp, oldlenp, newp, newlen);
})

VARIANT_3_IMPL(obfuscated_sysctl, long, (int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen), {
    return obfuscated_sysctl_base(name, namelen, oldp, oldlenp, newp, newlen);
})

VARIANT_4_IMPL(obfuscated_sysctl, long, (int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen), {
    return obfuscated_sysctl_base(name, namelen, oldp, oldlenp, newp, newlen);
})

VARIANT_5_IMPL(obfuscated_sysctl, long, (int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen), {
    return obfuscated_sysctl_base(name, namelen, oldp, oldlenp, newp, newlen);
})

VARIANT_6_IMPL(obfuscated_sysctl, long, (int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen), {
    return obfuscated_sysctl_base(name, namelen, oldp, oldlenp, newp, newlen);
})

VARIANT_7_IMPL(obfuscated_sysctl, long, (int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen), {
    return obfuscated_sysctl_base(name, namelen, oldp, oldlenp, newp, newlen);
})

// Base sysctl implementation
static long obfuscated_sysctl_base(int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    // This would call the actual obfuscated_sysctl implementation
    return -1;
}

// Generate variant table for sysctl
DECLARE_VARIANT_TABLE(obfuscated_sysctl, long, (int*, unsigned int, void*, size_t*, void*, size_t))

void generate_sysctl_variants(void) {
    void* variants[MAX_VARIANTS] = {
        (void*)obfuscated_sysctl_variant_0,
        (void*)obfuscated_sysctl_variant_1,
        (void*)obfuscated_sysctl_variant_2,
        (void*)obfuscated_sysctl_variant_3,
        (void*)obfuscated_sysctl_variant_4,
        (void*)obfuscated_sysctl_variant_5,
        (void*)obfuscated_sysctl_variant_6,
        (void*)obfuscated_sysctl_variant_7
    };
    
    register_function_variants("obfuscated_sysctl", variants, MAX_VARIANTS);
}

// Generate detection variants
VARIANT_0_IMPL(detect_debugger, int, (void), {
    return detect_debugger_base();
})

VARIANT_1_IMPL(detect_debugger, int, (void), {
    return detect_debugger_base();
})

VARIANT_2_IMPL(detect_debugger, int, (void), {
    return detect_debugger_base();
})

VARIANT_3_IMPL(detect_debugger, int, (void), {
    return detect_debugger_base();
})

VARIANT_4_IMPL(detect_debugger, int, (void), {
    return detect_debugger_base();
})

VARIANT_5_IMPL(detect_debugger, int, (void), {
    return detect_debugger_base();
})

VARIANT_6_IMPL(detect_debugger, int, (void), {
    return detect_debugger_base();
})

VARIANT_7_IMPL(detect_debugger, int, (void), {
    return detect_debugger_base();
})

// Base detection implementation
static int detect_debugger_base(void) {
    // This would call the actual detection implementation
    return 0;
}

// Generate variant table for detection
DECLARE_VARIANT_TABLE(detect_debugger, int, (void))

void generate_detection_variants(void) {
    void* variants[MAX_VARIANTS] = {
        (void*)detect_debugger_variant_0,
        (void*)detect_debugger_variant_1,
        (void*)detect_debugger_variant_2,
        (void*)detect_debugger_variant_3,
        (void*)detect_debugger_variant_4,
        (void*)detect_debugger_variant_5,
        (void*)detect_debugger_variant_6,
        (void*)detect_debugger_variant_7
    };
    
    register_function_variants("detect_debugger", variants, MAX_VARIANTS);
}

// Variant metadata management
variant_info_t* get_variant_info(const char* func_name, uint8_t variant_id) {
    uint32_t hash = hash_function_name(func_name);
    if (variant_id < MAX_VARIANTS && variant_id < registry_counts[hash]) {
        return &variant_registry[hash][variant_id].info;
    }
    return NULL;
}

void set_variant_active(const char* func_name, uint8_t variant_id, bool active) {
    uint32_t hash = hash_function_name(func_name);
    if (variant_id < MAX_VARIANTS && variant_id < registry_counts[hash]) {
        variant_registry[hash][variant_id].is_active = active;
    }
}

bool is_variant_active(const char* func_name, uint8_t variant_id) {
    uint32_t hash = hash_function_name(func_name);
    if (variant_id < MAX_VARIANTS && variant_id < registry_counts[hash]) {
        return variant_registry[hash][variant_id].is_active;
    }
    return false;
}
