//
// string_obfuscation.c - String obfuscation implementation
//

#include "string_obfuscation.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#include <sys/ptrace.h>
#elif __linux__
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#endif

// Simple XOR-based string decryption (can be enhanced)
char* obfuscated_string_decrypt(size_t len, const char* encrypted) {
    static char buffer[512];
    if (len >= sizeof(buffer)) return NULL;
    
    // Use time-based key for basic obfuscation
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint8_t key = (uint8_t)(tv.tv_usec & 0xFF) ^ 0xAA;
    
    for (size_t i = 0; i < len; i++) {
        buffer[i] = encrypted[i] ^ key ^ (uint8_t)i;
    }
    buffer[len] = '\0';
    return buffer;
}

// Construct strings at runtime from parts
void construct_stack_string(char* buffer, size_t buffer_size, ...) {
    va_list args;
    va_start(args, buffer_size);
    
    buffer[0] = '\0';
    size_t current_len = 0;
    
    const char* part;
    while ((part = va_arg(args, const char*)) != NULL) {
        size_t part_len = strlen(part);
        if (current_len + part_len + 1 < buffer_size) {
            strcat(buffer, part);
            current_len += part_len;
        }
    }
    
    va_end(args);
}

// Securely clear string from memory
void secure_string_clear(char* str, size_t len) {
    volatile char* p = str;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
}

// Generate dynamic key based on runtime state
uint64_t generate_dynamic_key(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    // Combine various runtime values
    uint64_t key = (uint64_t)tv.tv_sec << 32 | tv.tv_usec;
    key ^= (uint64_t)getpid() << 16;
    key ^= (uint64_t)&key;  // Stack address
    
    return key;
}

// Calculate constants at runtime
uint32_t calculate_runtime_constant(const char* seed) {
    uint32_t hash = 5381;
    
    if (seed) {
        for (const char* p = seed; *p; p++) {
            hash = ((hash << 5) + hash) + *p;
        }
    }
    
    // Mix with runtime values
    struct timeval tv;
    gettimeofday(&tv, NULL);
    hash ^= (uint32_t)tv.tv_usec;
    
    return hash;
}

// Derive pointers from context to avoid fixed addresses
void* derive_pointer_from_context(void* base) {
    uintptr_t addr = (uintptr_t)base;
    
    // Apply some transformation
    addr ^= generate_dynamic_key() & 0xFFFF;
    addr += calculate_runtime_constant("context") & 0xFF;
    
    return (void*)addr;
}

// Check for VM indicators without hardcoded strings
bool check_vm_indicators(const char* model_string) {
    if (!model_string) return false;
    
    // Construct VM vendor names at runtime
    STACK_STRING(vmware, "VM", "ware");
    STACK_STRING(vbox, "Virtual", "Box");  
    STACK_STRING(parallels, "Para", "llels");
    STACK_STRING(qemu, "QE", "MU");
    
    // Case-insensitive substring search
    char model_lower[256];
    strncpy(model_lower, model_string, sizeof(model_lower) - 1);
    model_lower[sizeof(model_lower) - 1] = '\0';
    
    // Convert to lowercase
    for (char* p = model_lower; *p; p++) {
        if (*p >= 'A' && *p <= 'Z') {
            *p = *p - 'A' + 'a';
        }
    }
    
    bool is_vm = (strstr(model_lower, vmware) != NULL) ||
                 (strstr(model_lower, vbox) != NULL) ||
                 (strstr(model_lower, parallels) != NULL) ||
                 (strstr(model_lower, qemu) != NULL);
    
    // Clear sensitive strings from stack
    secure_string_clear(vmware, strlen(vmware));
    secure_string_clear(vbox, strlen(vbox));
    secure_string_clear(parallels, strlen(parallels));
    secure_string_clear(qemu, strlen(qemu));
    secure_string_clear(model_lower, sizeof(model_lower));
    
    return is_vm;
}

// Check for debugging tools without hardcoded strings
bool check_debug_indicators(const char* process_name) {
    if (!process_name) return false;
    
    // Construct debugger names at runtime
    STACK_STRING(lldb, "ll", "db");
    STACK_STRING(gdb, "g", "db");
    STACK_STRING(xcode, "xco", "de");
    STACK_STRING(instruments, "instru", "ments");
    STACK_STRING(dtrace, "dtr", "ace");
    
    // Convert process name to lowercase for comparison
    char name_lower[256];
    strncpy(name_lower, process_name, sizeof(name_lower) - 1);
    name_lower[sizeof(name_lower) - 1] = '\0';
    
    for (char* p = name_lower; *p; p++) {
        if (*p >= 'A' && *p <= 'Z') {
            *p = *p - 'A' + 'a';
        }
    }
    
    bool is_debugger = (strstr(name_lower, lldb) != NULL) ||
                       (strstr(name_lower, gdb) != NULL) ||
                       (strstr(name_lower, xcode) != NULL) ||
                       (strstr(name_lower, instruments) != NULL) ||
                       (strstr(name_lower, dtrace) != NULL);
    
    // Clear sensitive strings
    secure_string_clear(lldb, strlen(lldb));
    secure_string_clear(gdb, strlen(gdb));
    secure_string_clear(xcode, strlen(xcode));
    secure_string_clear(instruments, strlen(instruments));
    secure_string_clear(dtrace, strlen(dtrace));
    secure_string_clear(name_lower, sizeof(name_lower));
    
    return is_debugger;
}

// Check for suspicious environment variables
bool check_debug_env_vars(void) {
    // Construct env var names at runtime
    STACK_STRING(dyld_insert, "DY", "LD_", "INSERT_", "LIBRARIES");
    STACK_STRING(dyld_flat, "DY", "LD_", "FORCE_", "FLAT_", "NAMESPACE");
    STACK_STRING(dyld_print, "DY", "LD_", "PRINT_", "LIBRARIES");
    
    bool suspicious = (getenv(dyld_insert) != NULL) ||
                     (getenv(dyld_flat) != NULL) ||
                     (getenv(dyld_print) != NULL);
    
    // Clear sensitive strings
    secure_string_clear(dyld_insert, strlen(dyld_insert));
    secure_string_clear(dyld_flat, strlen(dyld_flat));
    secure_string_clear(dyld_print, strlen(dyld_print));
    
    return suspicious;
}

// Build system call names at runtime
void build_dyld_string(char* buffer, size_t size) {
    STACK_STRING(dyld, "DY", "LD_", "INSERT_", "LIBRARIES");
    strncpy(buffer, dyld, size - 1);
    buffer[size - 1] = '\0';
    secure_string_clear(dyld, strlen(dyld));
}

void build_ptrace_string(char* buffer, size_t size) {
    STACK_STRING(ptrace_str, "ptr", "ace");
    strncpy(buffer, ptrace_str, size - 1);
    buffer[size - 1] = '\0';
    secure_string_clear(ptrace_str, strlen(ptrace_str));
}

void build_sysctl_string(char* buffer, size_t size) {
    STACK_STRING(sysctl_str, "sys", "ctl");
    strncpy(buffer, sysctl_str, size - 1);
    buffer[size - 1] = '\0';
    secure_string_clear(sysctl_str, strlen(sysctl_str));
}

// Build system library paths at runtime
void build_system_lib_path(char* buffer, size_t size, const char* lib_name) {
    STACK_STRING(usr_path, "/", "usr", "/", "lib", "/", "system", "/");
    STACK_STRING(dylib_ext, ".", "dylib");
    
    // Clear buffer first
    memset(buffer, 0, size);
    
    // Construct full path
    size_t usr_len = strlen(usr_path);
    size_t lib_len = strlen(lib_name);
    size_t ext_len = strlen(dylib_ext);
    
    if (usr_len + lib_len + ext_len + 1 < size) {
        strcpy(buffer, usr_path);
        strcat(buffer, lib_name);
        strcat(buffer, dylib_ext);
    }
    
    // Clear intermediate strings
    secure_string_clear(usr_path, strlen(usr_path));
    secure_string_clear(dylib_ext, strlen(dylib_ext));
}

// Build framework paths at runtime
void build_framework_path(char* buffer, size_t size, const char* framework_name) {
    STACK_STRING(sys_path, "/", "System", "/", "Library", "/", "Frameworks", "/");
    STACK_STRING(fw_ext, ".", "framework");
    
    // Clear buffer first
    memset(buffer, 0, size);
    
    // Construct full path
    size_t sys_len = strlen(sys_path);
    size_t fw_len = strlen(framework_name);
    size_t ext_len = strlen(fw_ext);
    
    if (sys_len + fw_len + ext_len + 1 < size) {
        strcpy(buffer, sys_path);
        strcat(buffer, framework_name);
        strcat(buffer, fw_ext);
    }
    
    // Clear intermediate strings
    secure_string_clear(sys_path, strlen(sys_path));
    secure_string_clear(fw_ext, strlen(fw_ext));
}

// Direct syscall implementations to avoid library function detection
// These bypass ptrace() and sysctl() in libc

// Runtime syscall number deobfuscation - common for both platforms
static inline int deobfuscate_syscall_number(int base_num) {
    // Multiple layers of obfuscation
    volatile int obfuscated = base_num;
    
#ifdef __APPLE__
    // macOS obfuscation constants
    #define SYSCALL_XOR_KEY 0x5A
    #define SYSCALL_ADD_KEY 0x3C
#else
    // Linux obfuscation constants
    #define SYSCALL_XOR_KEY 0x7F
    #define SYSCALL_ADD_KEY 0x29
#endif
    
    // Layer 1: XOR with runtime key
    uint32_t runtime_key = calculate_runtime_constant("syscall") & 0xFF;
    obfuscated = (obfuscated ^ SYSCALL_XOR_KEY) ^ runtime_key;
    
    // Layer 2: Arithmetic obfuscation
    obfuscated = (obfuscated - SYSCALL_ADD_KEY) & 0xFFFF;
    
    // Layer 3: Conditional transformation
    if (obfuscated > 300) {
        obfuscated = base_num; // Fallback to original
    }
    
    return obfuscated;
}

#ifdef __APPLE__
// macOS syscall numbers - obfuscated at compile time
#define SYS_ptrace_base  26
#define SYS_sysctl_base  202
#define PT_DENY_ATTACH_OBF 31

// Store syscall numbers in obfuscated form at compile time
static const int ptrace_obfuscated = (SYS_ptrace_base + SYSCALL_ADD_KEY) ^ SYSCALL_XOR_KEY;
static const int sysctl_obfuscated = (SYS_sysctl_base + SYSCALL_ADD_KEY) ^ SYSCALL_XOR_KEY;

long obfuscated_ptrace(int request, int pid, void* addr, void* data) {
    // Deobfuscate syscall number at runtime
    volatile int syscall_num = deobfuscate_syscall_number(ptrace_obfuscated);
    
    long result;
#if defined(__x86_64__)
    __asm__ volatile (
        "mov %1, %%rax\n\t"    // syscall number
        "mov %2, %%rdi\n\t"    // request
        "mov %3, %%rsi\n\t"    // pid
        "mov %4, %%rdx\n\t"    // addr
        "mov %5, %%r10\n\t"    // data
        "syscall\n\t"
        "mov %%rax, %0\n\t"    // result
        : "=m" (result)
        : "r" ((long)syscall_num), "r" ((long)request), "r" ((long)pid), 
          "r" ((long)addr), "r" ((long)data)
        : "rax", "rdi", "rsi", "rdx", "r10", "memory"
    );
#elif defined(__aarch64__)
    __asm__ volatile (
        "mov x8, %1\n\t"       // syscall number
        "mov x0, %2\n\t"       // request
        "mov x1, %3\n\t"       // pid
        "mov x2, %4\n\t"       // addr
        "mov x3, %5\n\t"       // data
        "svc #0x80\n\t"        // system call
        "mov %0, x0\n\t"       // result
        : "=r" (result)
        : "r" ((long)syscall_num), "r" ((long)request), "r" ((long)pid), 
          "r" ((long)addr), "r" ((long)data)
        : "x0", "x1", "x2", "x3", "x8", "memory"
    );
#else
    // Fallback for unsupported architectures
    result = ptrace(request, pid, addr, data);
#endif
    return result;
}

long obfuscated_sysctl(int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    // Deobfuscate syscall number at runtime
    volatile int syscall_num = deobfuscate_syscall_number(sysctl_obfuscated);
    
    long result;
#if defined(__x86_64__)
    __asm__ volatile (
        "mov %1, %%rax\n\t"    // syscall number
        "mov %2, %%rdi\n\t"    // name
        "mov %3, %%rsi\n\t"    // namelen
        "mov %4, %%rdx\n\t"    // oldp
        "mov %5, %%r10\n\t"    // oldlenp
        "mov %6, %%r8\n\t"     // newp
        "mov %7, %%r9\n\t"     // newlen
        "syscall\n\t"
        "mov %%rax, %0\n\t"    // result
        : "=m" (result)
        : "r" ((long)syscall_num), "r" ((long)name), "r" ((long)namelen),
          "r" ((long)oldp), "r" ((long)oldlenp), "r" ((long)newp), "r" ((long)newlen)
        : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory"
    );
#elif defined(__aarch64__)
    __asm__ volatile (
        "mov x8, %1\n\t"       // syscall number
        "mov x0, %2\n\t"       // name
        "mov x1, %3\n\t"       // namelen
        "mov x2, %4\n\t"       // oldp
        "mov x3, %5\n\t"       // oldlenp
        "mov x4, %6\n\t"       // newp
        "mov x5, %7\n\t"       // newlen
        "svc #0x80\n\t"        // system call
        "mov %0, x0\n\t"       // result
        : "=r" (result)
        : "r" ((long)syscall_num), "r" ((long)name), "r" ((long)namelen),
          "r" ((long)oldp), "r" ((long)oldlenp), "r" ((long)newp), "r" ((long)newlen)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x8", "memory"
    );
#else
    // Fallback for unsupported architectures
    result = sysctl(name, namelen, oldp, oldlenp, newp, newlen);
#endif
    return result;
}

#else
// Linux syscall numbers - obfuscated at compile time
#define SYS_ptrace_base  101
#define SYS_sysctl_base  149
#define PTRACE_TRACEME_OBF 0
#define PTRACE_DETACH_OBF  17

// Different obfuscation keys for Linux
#define SYSCALL_XOR_KEY 0x7F
#define SYSCALL_ADD_KEY 0x29

// Store obfuscated syscall numbers for Linux
static const int ptrace_obfuscated_linux = (SYS_ptrace_base + SYSCALL_ADD_KEY) ^ SYSCALL_XOR_KEY;
static const int sysctl_obfuscated_linux = (SYS_sysctl_base + SYSCALL_ADD_KEY) ^ SYSCALL_XOR_KEY;

long obfuscated_ptrace(int request, int pid, void* addr, void* data) {
    // Deobfuscate syscall number at runtime
    volatile int syscall_num = deobfuscate_syscall_number(ptrace_obfuscated_linux);
    
    long result;
    __asm__ volatile (
        "mov %1, %%rax\n\t"    // syscall number
        "mov %2, %%rdi\n\t"    // request
        "mov %3, %%rsi\n\t"    // pid
        "mov %4, %%rdx\n\t"    // addr
        "mov %5, %%r10\n\t"    // data
        "syscall\n\t"
        "mov %%rax, %0\n\t"    // result
        : "=m" (result)
        : "r" ((long)syscall_num), "r" ((long)request), "r" ((long)pid),
          "r" ((long)addr), "r" ((long)data)
        : "rax", "rdi", "rsi", "rdx", "r10", "memory"
    );
    return result;
}

long obfuscated_sysctl(int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    // Deobfuscate syscall number at runtime
    volatile int syscall_num = deobfuscate_syscall_number(sysctl_obfuscated_linux);
    
    long result;
    __asm__ volatile (
        "mov %1, %%rax\n\t"    // syscall number
        "mov %2, %%rdi\n\t"    // name
        "mov %3, %%rsi\n\t"    // namelen
        "mov %4, %%rdx\n\t"    // oldp
        "mov %5, %%r10\n\t"    // oldlenp
        "mov %6, %%r8\n\t"     // newp
        "mov %7, %%r9\n\t"     // newlen
        "syscall\n\t"
        "mov %%rax, %0\n\t"    // result
        : "=m" (result)
        : "r" ((long)syscall_num), "r" ((long)name), "r" ((long)namelen),
          "r" ((long)oldp), "r" ((long)oldlenp), "r" ((long)newp), "r" ((long)newlen)
        : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory"
    );
    return result;
}

#endif
