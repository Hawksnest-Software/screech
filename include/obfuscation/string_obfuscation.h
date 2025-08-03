//
// string_obfuscation.h - String obfuscation utilities
// Provides runtime string decryption and construction
//

#ifndef STRING_OBFUSCATION_H
#define STRING_OBFUSCATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

// String obfuscation macros
#define OBFUSCATED_STRING(str) obfuscated_string_decrypt(__builtin_strlen(str), str)
#define STACK_STRING(var, ...) char var[256]; construct_stack_string(var, sizeof(var), __VA_ARGS__, NULL)

// Dynamic string construction
char* obfuscated_string_decrypt(size_t len, const char* encrypted);
void construct_stack_string(char* buffer, size_t buffer_size, ...);
void secure_string_clear(char* str, size_t len);

// Dynamic constant generation  
uint64_t generate_dynamic_key(void);
uint32_t calculate_runtime_constant(const char* seed);
void* derive_pointer_from_context(void* base);

// String comparison without hardcoded strings
bool secure_string_contains(const char* haystack, const char* needle_parts[], size_t count);
bool check_vm_indicators(const char* model_string);
bool check_debug_indicators(const char* process_name);
bool check_debug_env_vars(void);

// Obfuscated string construction helpers
void build_dyld_string(char* buffer, size_t size);
void build_ptrace_string(char* buffer, size_t size);
void build_sysctl_string(char* buffer, size_t size);
void build_system_lib_path(char* buffer, size_t size, const char* lib_name);
void build_framework_path(char* buffer, size_t size, const char* framework_name);

// Note: obfuscated syscall wrappers are declared in direct_syscalls.h

#ifdef __cplusplus
}
#endif

#endif // STRING_OBFUSCATION_H
