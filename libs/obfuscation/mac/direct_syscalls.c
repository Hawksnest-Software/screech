#include "direct_syscalls.h"
#include "string_obfuscation.h"  // for calculate_runtime_constant
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <stdint.h>

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
