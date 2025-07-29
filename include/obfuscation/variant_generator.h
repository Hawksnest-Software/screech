//
// variant_generator.h - Automated function variant generation system
// Creates multiple implementations of critical functions at compile time
//

#ifndef VARIANT_GENERATOR_H
#define VARIANT_GENERATOR_H

#include <stdint.h>
#include <stdbool.h>

// Architecture-specific assembly macros
#if defined(__x86_64__)
#define ARCH_NOP_PADDING() __asm__ volatile ("nop; nop; nop;")
#define ARCH_REG_SHUFFLE(dummy_reg) __asm__ volatile ("mov %0, %%eax; xor %%eax, %%eax" : : "r"(dummy_reg) : "eax")
#define ARCH_STACK_OPS() __asm__ volatile ("pushf; popf;")
#elif defined(__aarch64__)
#define ARCH_NOP_PADDING() __asm__ volatile ("nop; nop; nop;")
#define ARCH_REG_SHUFFLE(dummy_reg) __asm__ volatile ("mov w8, %w0; eor w8, w8, w8" : : "r"(dummy_reg) : "w8")
#define ARCH_STACK_OPS() __asm__ volatile ("stp x29, x30, [sp, #-16]!; ldp x29, x30, [sp], #16")
#else
#define ARCH_NOP_PADDING() ((void)0)
#define ARCH_REG_SHUFFLE(dummy_reg) ((void)0)
#define ARCH_STACK_OPS() ((void)0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Variant generation configuration
#define MAX_VARIANTS 8
#define VARIANT_SEED_SIZE 16

// Variant types
typedef enum {
    VARIANT_TYPE_NOOP_PADDING,
    VARIANT_TYPE_REGISTER_SHUFFLE,
    VARIANT_TYPE_INSTRUCTION_REORDER,
    VARIANT_TYPE_DUMMY_COMPUTATION,
    VARIANT_TYPE_CONTROL_FLOW_OBFUSCATION,
    VARIANT_TYPE_COUNT
} variant_type_t;

// Variant metadata
typedef struct {
    uint32_t id;
    variant_type_t type;
    uint8_t complexity_level;
    uint8_t seed[VARIANT_SEED_SIZE];
    const char* description;
} variant_info_t;

// Function variant registry
typedef struct {
    void* function_ptr;
    variant_info_t info;
    bool is_active;
} function_variant_t;

// Automated variant generation macros
#define GENERATE_VARIANTS(func_name, base_impl) \
    VARIANT_0_##func_name(base_impl) \
    VARIANT_1_##func_name(base_impl) \
    VARIANT_2_##func_name(base_impl) \
    VARIANT_3_##func_name(base_impl) \
    VARIANT_4_##func_name(base_impl) \
    VARIANT_5_##func_name(base_impl) \
    VARIANT_6_##func_name(base_impl) \
    VARIANT_7_##func_name(base_impl)

// Variant implementation macros with different obfuscation techniques
#define VARIANT_0_IMPL(func_name, return_type, params, base_impl) \
    static return_type func_name##_variant_0 params { \
        /* No padding variant */ \
        base_impl \
    }

#define VARIANT_1_IMPL(func_name, return_type, params, base_impl) \
    static return_type func_name##_variant_1 params { \
        /* NOP padding variant */ \
        ARCH_NOP_PADDING(); \
        base_impl \
        ARCH_NOP_PADDING(); \
    }

#define VARIANT_2_IMPL(func_name, return_type, params, base_impl) \
    static return_type func_name##_variant_2 params { \
        /* Register shuffle variant */ \
        volatile int dummy_reg = 0x12345678; \
        ARCH_REG_SHUFFLE(dummy_reg); \
        base_impl \
    }

#define VARIANT_3_IMPL(func_name, return_type, params, base_impl) \
    static return_type func_name##_variant_3 params { \
        /* Dummy computation variant */ \
        volatile uint32_t dummy = get_runtime_seed() ^ 0xDEADBEEF; \
        dummy = (dummy << 3) ^ (dummy >> 5); \
        base_impl \
    }

#define VARIANT_4_IMPL(func_name, return_type, params, base_impl) \
    static return_type func_name##_variant_4 params { \
        /* Control flow obfuscation variant */ \
        if (get_runtime_seed() & 1) { \
            if (!(get_runtime_seed() & 2)) { \
                base_impl \
            } else { \
                base_impl \
            } \
        } else { \
            base_impl \
        } \
    }

#define VARIANT_5_IMPL(func_name, return_type, params, base_impl) \
    static return_type func_name##_variant_5 params { \
        /* Stack manipulation variant */ \
        volatile char stack_noise[64]; \
        for(int i = 0; i < 64; i++) stack_noise[i] = i ^ 0xAA; \
        base_impl \
        for(int i = 0; i < 64; i++) stack_noise[i] = 0; \
    }

#define VARIANT_6_IMPL(func_name, return_type, params, base_impl) \
    static return_type func_name##_variant_6 params { \
        /* Instruction reordering variant */ \
        volatile uint32_t temp1 = get_runtime_seed(); \
        volatile uint32_t temp2 = temp1 ^ 0x55555555; \
        base_impl \
        temp1 = temp2 = 0; \
    }

#define VARIANT_7_IMPL(func_name, return_type, params, base_impl) \
    static return_type func_name##_variant_7 params { \
        /* Complex obfuscation variant */ \
        ARCH_STACK_OPS(); \
        volatile uint64_t noise = calculate_noise_value(); \
        if (noise & 0x1) { ARCH_NOP_PADDING(); } \
        base_impl \
        ARCH_STACK_OPS(); \
    }

// Variant selector macro
#define SELECT_VARIANT(func_name, variant_id) func_name##_variant_##variant_id

// Automated variant table generation
#define DECLARE_VARIANT_TABLE(func_name, return_type, params) \
    typedef return_type (*func_name##_variant_func_t) params; \
    static func_name##_variant_func_t func_name##_variants[MAX_VARIANTS] = { \
        func_name##_variant_0, \
        func_name##_variant_1, \
        func_name##_variant_2, \
        func_name##_variant_3, \
        func_name##_variant_4, \
        func_name##_variant_5, \
        func_name##_variant_6, \
        func_name##_variant_7  \
    };

// Runtime variant selection
#define CALL_VARIANT(func_name, ...) \
    func_name##_variants[select_runtime_variant(#func_name)](__VA_ARGS__)

// Core variant generation functions
void init_variant_generator(void);
uint32_t get_runtime_seed(void);
uint64_t calculate_noise_value(void);
uint8_t select_runtime_variant(const char* func_name);
void register_function_variants(const char* func_name, void** variants, uint8_t count);
void update_variant_selection(void);

// Variant metadata management
variant_info_t* get_variant_info(const char* func_name, uint8_t variant_id);
void set_variant_active(const char* func_name, uint8_t variant_id, bool active);
bool is_variant_active(const char* func_name, uint8_t variant_id);

// Automated variant generation for critical functions
void generate_ptrace_variants(void);
void generate_sysctl_variants(void);
void generate_detection_variants(void);

// Compile-time variant configuration
#ifdef ENABLE_VARIANT_GENERATION
#define VARIANT_ENABLED 1
#else
#define VARIANT_ENABLED 0
#endif

#if VARIANT_ENABLED
#define VARIANT_CALL(func, ...) CALL_VARIANT(func, __VA_ARGS__)
#else
#define VARIANT_CALL(func, ...) func(__VA_ARGS__)
#endif

#ifdef __cplusplus
}
#endif

#endif // VARIANT_GENERATOR_H
