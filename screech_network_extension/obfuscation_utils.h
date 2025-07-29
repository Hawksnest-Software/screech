#ifndef OBFUSCATION_UTILS_H
#define OBFUSCATION_UTILS_H

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <dlfcn.h>

// String obfuscation macros for compile-time protection
#define OBFUSCATED_STRING(s) obfuscate_string(@s, __LINE__)
#define ROT13_STRING(s) rot13_transform(@s)

// Dynamic loading obfuscation
#define LOAD_FUNCTION(lib, func) dlsym(dlopen(lib, RTLD_LAZY), func)

// Memory pattern obfuscation
#define XOR_MEMORY(ptr, size, key) xor_memory_block(ptr, size, key)

// Function pointer obfuscation
typedef void* (*GenericFunctionPtr)(void*, ...);
#define CALL_OBFUSCATED(func, ...) ((GenericFunctionPtr)func)(__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

// String obfuscation functions
NSString* obfuscate_string(NSString* input, int seed);
NSString* rot13_transform(NSString* input);
NSString* base64_encode_string(NSString* input);
NSString* base64_decode_string(NSString* input);

// Memory obfuscation functions
void xor_memory_block(void* memory, size_t size, uint8_t key);
void encrypt_memory_aes(void* memory, size_t size, const char* key);
void decrypt_memory_aes(void* memory, size_t size, const char* key);

// Dynamic loading helpers
void* load_framework_symbol(const char* framework, const char* symbol);
void* load_library_function(const char* library, const char* function);

// Anti-debugging functions
BOOL is_debugger_present(void);
BOOL is_being_traced(void);
void anti_debug_checks(void);

// Process name obfuscation
NSString* obfuscate_process_name(NSString* realName);
NSString* generate_fake_process_name(void);

// Bundle identifier obfuscation
NSString* generate_dynamic_bundle_id(NSString* prefix);
NSString* obfuscate_bundle_identifier(NSString* realId);

// System call obfuscation
int obfuscated_syscall(int number, ...);
void hide_syscall_traces(void);

// Network address obfuscation
NSString* obfuscate_ip_address(NSString* realIP);
uint16_t obfuscate_port_number(uint16_t realPort);

// File path obfuscation
NSString* obfuscate_file_path(NSString* realPath);
NSString* generate_temp_filename(void);

// Timing obfuscation
void random_delay(void);
void anti_timing_analysis(void);

// Code flow obfuscation
void dummy_operations(void);
void insert_junk_code(void);

#ifdef __cplusplus
}
#endif

// Compile-time constants obfuscation
static const char kObfuscatedKey[] = {0x73, 0x79, 0x73, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x74, 0x69, 0x63, 0x73, 0x00}; // "sys_analytics"
static const int kObfuscationSeed = 0xDEADBEEF ^ __LINE__;

// Macro for obfuscated function calls
#define OBFUSCATED_CALL(func, ...) do { \
    dummy_operations(); \
    random_delay(); \
    func(__VA_ARGS__); \
    insert_junk_code(); \
} while(0)

// Macro for obfuscated string literals
#define OBFS(str) obfuscate_string(@str, kObfuscationSeed)

#endif /* OBFUSCATION_UTILS_H */
