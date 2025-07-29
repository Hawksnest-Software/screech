# System Call Obfuscation Techniques

## Overview

System call obfuscation is designed to bypass API hooking by avoiding the standard library functions that malware analysis tools commonly monitor. Here's how it works:

## 1. Normal vs Obfuscated System Calls

### Normal System Call Flow:
```
Application → libc function → syscall wrapper → kernel
    ↓
[Easily hooked at libc level]
```

### Obfuscated System Call Flow:
```
Application → Direct assembly → kernel (bypasses libc entirely)
    ↓
[Difficult to hook without kernel-level access]
```

## 2. Direct System Call Implementation

### Standard libc Call:
```c
// This can be easily hooked
int fd = open("/path/to/file", O_RDONLY);
```

### Direct Assembly Call:
```c
// This bypasses all userspace hooks
static inline int direct_open(const char* path, int flags) {
    int result;
    __asm__ volatile (
        "movq $2, %%rax\n\t"        // SYS_open = 2
        "movq %1, %%rdi\n\t"        // path argument
        "movq %2, %%rsi\n\t"        // flags argument  
        "syscall\n\t"               // direct kernel call
        "movq %%rax, %0\n\t"        // store result
        : "=m" (result)             // output
        : "m" (path), "m" (flags)   // inputs
        : "rax", "rdi", "rsi", "rcx", "r11"  // clobbered registers
    );
    return result;
}
```

## 3. Function Pointer Obfuscation

### The Problem:
Storing function pointers in plain memory makes them easy to detect and hook.

### The Solution:
```c
// Instead of storing: void* original_function = dlsym(handle, "function");
// We store an obfuscated version:

uintptr_t obfuscate_pointer(void* ptr, uintptr_t key) {
    uintptr_t addr = (uintptr_t)ptr;
    
    // XOR with key
    addr ^= key;
    
    // Bit rotation
    addr = (addr << 13) | (addr >> (64 - 13));
    
    // Additional XOR layer
    addr ^= 0xDEADBEEFCAFEBABE;
    
    return addr;
}

uintptr_t deobfuscate_pointer(uintptr_t obfuscated, uintptr_t key) {
    // Reverse the obfuscation process
    obfuscated ^= 0xDEADBEEFCAFEBABE;
    obfuscated = (obfuscated >> 13) | (obfuscated << (64 - 13));
    obfuscated ^= key;
    
    return obfuscated;
}
```

## 4. Dynamic Key Generation

Keys change at runtime to prevent static analysis:

```c
uintptr_t generate_runtime_key(void) {
    uintptr_t key = 0;
    
    // Use runtime values that change between executions
    key ^= (uintptr_t)mach_task_self();    // Process-specific
    key ^= (uintptr_t)pthread_self();      // Thread-specific  
    key ^= (uintptr_t)time(NULL);          // Time-based
    key ^= (uintptr_t)&key;                // Stack address (ASLR)
    
    return key;
}
```

## 5. Syscall Number Obfuscation

### Problem:
Using hardcoded syscall numbers is detectable.

### Solution:
```c
// Instead of: syscall(SYS_open, path, flags);
// Use obfuscated numbers:

int obfuscated_syscall_numbers[] = {
    SYS_open ^ 0xABCD,
    SYS_read ^ 0xABCD, 
    SYS_write ^ 0xABCD,
    // ... more syscalls
};

int get_real_syscall_number(int index) {
    return obfuscated_syscall_numbers[index] ^ 0xABCD;
}

// Usage:
int real_open_num = get_real_syscall_number(0);
int fd = direct_syscall_2(real_open_num, (long)path, (long)flags);
```

## 6. Anti-Hook Detection

Before making syscalls, verify they haven't been hooked:

```c
BOOL is_syscall_hooked(int syscall_num) {
    // Get syscall table address (simplified)
    void* syscall_addr = get_syscall_address(syscall_num);
    
    if (!syscall_addr) return YES; // Assume hooked if can't verify
    
    // Read first few bytes
    uint8_t bytes[8];
    if (read_memory(syscall_addr, bytes, 8) != 0) {
        return YES; // Can't read = likely hooked
    }
    
    // Check for hook signatures
    if (bytes[0] == 0xE9 ||  // JMP rel32
        bytes[0] == 0xE8 ||  // CALL rel32
        bytes[0] == 0xFF) {  // JMP/CALL indirect
        return YES; // Likely hooked
    }
    
    return NO; // Appears clean
}
```

## 7. Polymorphic Execution

Change how syscalls are made to avoid pattern detection:

```c
typedef enum {
    SYSCALL_METHOD_DIRECT,
    SYSCALL_METHOD_INDIRECT,  
    SYSCALL_METHOD_DELAYED,
    SYSCALL_METHOD_SPLIT
} syscall_method_t;

int polymorphic_syscall(int num, long arg1, long arg2) {
    static syscall_method_t method = SYSCALL_METHOD_DIRECT;
    
    // Rotate method to avoid patterns
    method = (method + 1) % 4;
    
    switch (method) {
        case SYSCALL_METHOD_DIRECT:
            return direct_syscall_2(num, arg1, arg2);
            
        case SYSCALL_METHOD_INDIRECT: {
            // Call through function pointer
            int (*syscall_func)(int, long, long) = &direct_syscall_2;
            return syscall_func(num, arg1, arg2);
        }
        
        case SYSCALL_METHOD_DELAYED:
            // Add random delay to break timing analysis
            usleep(arc4random_uniform(100));
            return direct_syscall_2(num, arg1, arg2);
            
        case SYSCALL_METHOD_SPLIT:
            // Split arguments across multiple operations
            volatile long temp_arg1 = arg1;
            volatile long temp_arg2 = arg2;
            return direct_syscall_2(num, temp_arg1, temp_arg2);
    }
    
    return -1;
}
```

## 8. Memory Protection

Protect our own code from being hooked:

```c
void protect_anti_hook_code(void) {
    // Get address range of our functions
    void* start = (void*)&direct_syscall_0;
    void* end = (void*)&protect_anti_hook_code;
    size_t size = (char*)end - (char*)start;
    
    // Make the memory read-only and executable
    mprotect(start, size, PROT_READ | PROT_EXEC);
    
    // Or use mach_vm_protect for more control
    vm_protect(mach_task_self(), 
               (vm_address_t)start, 
               size, 
               NO, 
               VM_PROT_READ | VM_PROT_EXECUTE);
}
```

## 9. Runtime Integrity Checking

Continuously verify our functions haven't been modified:

```c
typedef struct {
    void* function_addr;
    uint32_t original_checksum;
} function_integrity_t;

uint32_t calculate_checksum(void* addr, size_t size) {
    uint32_t checksum = 0;
    uint8_t* bytes = (uint8_t*)addr;
    
    for (size_t i = 0; i < size; i++) {
        checksum = (checksum << 1) ^ bytes[i];
    }
    
    return checksum;
}

BOOL verify_function_integrity(function_integrity_t* func) {
    uint32_t current_checksum = calculate_checksum(func->function_addr, 64);
    return (current_checksum == func->original_checksum);
}
```

## 10. Complete Example Usage

```c
// Initialize anti-hooking system
void init_obfuscated_syscalls(void) {
    // Generate runtime key
    g_obfuscation_key = generate_runtime_key();
    
    // Store original function pointers (obfuscated)
    void* libc = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_LAZY);
    void* original_open = dlsym(libc, "open");
    g_obfuscated_open = obfuscate_pointer(original_open, g_obfuscation_key);
    
    // Protect our code
    protect_anti_hook_code();
}

// Safe file opening that evades hooks
int safe_open_file(const char* path, int flags) {
    // Check if standard open() is hooked
    void* open_func = deobfuscate_pointer(g_obfuscated_open, g_obfuscation_key);
    if (is_function_hooked(open_func)) {
        // Use direct syscall instead
        return polymorphic_syscall(SYS_open, (long)path, (long)flags);
    } else {
        // Safe to use standard function
        return ((int(*)(const char*, int))open_func)(path, flags);
    }
}
```

## Key Benefits:

1. **Bypasses userspace hooks** - Direct syscalls can't be hooked without kernel access
2. **Dynamic obfuscation** - Keys and methods change at runtime
3. **Multiple evasion layers** - Function pointer obfuscation, polymorphic execution, integrity checking
4. **Self-protection** - Code protects itself from modification
5. **Adaptive behavior** - Falls back to direct syscalls when hooks are detected

This approach makes it extremely difficult for malware analysis tools to intercept and monitor system calls without kernel-level access or hypervisor-based solutions.
