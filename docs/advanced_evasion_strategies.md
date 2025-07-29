# Advanced Evasion Strategies for Anti-Debugging & Analysis

## Current Detection Vectors

Even with our obfuscated direct syscalls (`ptrace`, `sysctl`), sophisticated analysis tools can still detect our anti-debugging measures through several methods:

### 1. System Call Tracing (strace/dtrace)
```bash
# This will still show our syscalls:
strace -e trace=ptrace,sysctl ./screech
# Output: ptrace(PTRACE_TRACEME, 0, NULL, NULL) = 0
```
**Why**: The kernel still sees the syscall numbers (26, 202) regardless of how we invoke them.

### 2. eBPF/Kernel Tracing
```c
// Security tools can hook syscall entry points in kernel
int trace_sys_ptrace(struct pt_regs *ctx) {
    // This catches ALL ptrace calls, including our obfuscated ones
    bpf_trace_printk("ptrace detected from PID %d", bpf_get_current_pid_tgid());
}
```

### 3. Static Analysis of Assembly
Our inline assembly is still visible in disassembly:
```asm
mov $0x1a, %rax    ; 26 = ptrace syscall number  
mov $0x1f, %rdi    ; 31 = PT_DENY_ATTACH
syscall            ; Obviously a direct syscall
```

### 4. Behavioral Analysis
- **Timing patterns**: ptrace calls have characteristic timing
- **Return values**: PT_DENY_ATTACH has predictable failure modes
- **Side effects**: Process termination patterns when debuggers are present

### 5. Hardware Breakpoints
```c
// Hardware can trap on specific instruction patterns
// Intel CET (Control-flow Enforcement Technology) can detect syscall patterns
```

### 6. Hypervisor Detection
In VMs, the hypervisor can intercept and log all syscalls regardless of how they're made.

---

## Advanced Evasion Strategies

### Strategy 1: Syscall Number Obfuscation & Indirection

Instead of using ptrace/sysctl directly, use alternative syscalls that provide similar information:

```c
// Instead of ptrace(PTRACE_TRACEME), use:
// 1. Check /proc/self/status for TracerPid field
// 2. Use process_vm_readv to detect memory protection changes
// 3. Monitor timing of memory operations

bool detect_debugger_indirect() {
    // Method 1: Parse /proc/self/status
    FILE* status = fopen("/proc/self/status", "r");
    if (status) {
        char line[256];
        while (fgets(line, sizeof(line), status)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int tracer_pid = atoi(line + 10);
                fclose(status);
                return tracer_pid != 0;
            }
        }
        fclose(status);
    }
    
    // Method 2: Memory timing analysis
    return detect_via_timing();
}
```

### Strategy 2: Timing-Based Detection

Debugged processes exhibit different timing characteristics:

```c
bool detect_via_timing() {
    struct timespec start, end;
    volatile int dummy = 0;
    
    // Measure time for simple operations
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < 1000; i++) {
        dummy += i * i;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    long duration = (end.tv_sec - start.tv_sec) * 1000000000L + 
                   (end.tv_nsec - start.tv_nsec);
    
    // If operations take too long, might be debugged
    return duration > EXPECTED_THRESHOLD;
}
```

### Strategy 3: Environment Inference

Check side effects rather than direct debugging state:

```c
bool detect_via_environment() {
    // Check for suspicious memory mappings
    FILE* maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            // Look for debugger-specific libraries
            if (strstr(line, "libpython") || 
                strstr(line, "gdb") ||
                strstr(line, "lldb")) {
                fclose(maps);
                return true;
            }
        }
        fclose(maps);
    }
    
    // Check file descriptor count (debuggers open many FDs)
    DIR* fd_dir = opendir("/proc/self/fd");
    if (fd_dir) {
        int fd_count = 0;
        struct dirent* entry;
        while ((entry = readdir(fd_dir)) != NULL) {
            if (entry->d_name[0] != '.') fd_count++;
        }
        closedir(fd_dir);
        
        // Normal processes have few FDs, debuggers have many
        return fd_count > NORMAL_FD_THRESHOLD;
    }
    
    return false;
}
```

### Strategy 4: Polymorphic Detection Methods

Change detection methods at runtime to avoid signatures:

```c
typedef enum {
    DETECT_METHOD_TIMING,
    DETECT_METHOD_PROC_STATUS,
    DETECT_METHOD_MEMORY_LAYOUT,
    DETECT_METHOD_FD_COUNT,
    DETECT_METHOD_SYSCALL,
    DETECT_METHOD_COUNT
} detection_method_t;

bool polymorphic_detection() {
    static int method_index = 0;
    static bool methods_shuffled = false;
    
    // Shuffle methods on first call
    if (!methods_shuffled) {
        // Use runtime-generated random order
        method_index = generate_dynamic_key() % DETECT_METHOD_COUNT;
        methods_shuffled = true;
    }
    
    switch (method_index % DETECT_METHOD_COUNT) {
        case DETECT_METHOD_TIMING:
            return detect_via_timing();
        case DETECT_METHOD_PROC_STATUS:
            return detect_debugger_indirect();
        case DETECT_METHOD_MEMORY_LAYOUT:
            return detect_via_environment();
        case DETECT_METHOD_FD_COUNT:
            return detect_via_fd_analysis();
        case DETECT_METHOD_SYSCALL:
            // Only occasionally use direct syscalls
            if ((generate_dynamic_key() % 10) == 0) {
                return detect_debugger_direct(); // Our current method
            }
            return false;
        default:
            return false;
    }
}
```

### Strategy 5: Decoy Operations

Add false positives to confuse analysis:

```c
void add_decoy_operations() {
    // Perform legitimate operations that look suspicious
    
    // 1. Open and close many files (mimic malware behavior)
    for (int i = 0; i < 10; i++) {
        char filename[64];
        snprintf(filename, sizeof(filename), "/tmp/decoy_%d", i);
        int fd = open(filename, O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) {
            write(fd, "decoy", 5);
            close(fd);
            unlink(filename);
        }
    }
    
    // 2. Perform memory operations that trigger analysis tools
    void* decoy_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, 
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (decoy_mem != MAP_FAILED) {
        memset(decoy_mem, 0xCC, 4096); // INT3 breakpoint instruction
        munmap(decoy_mem, 4096);
    }
    
    // 3. Make legitimate syscalls that analysts expect to see
    getpid();
    getppid();
    gettimeofday(NULL, NULL);
}
```

### Strategy 6: Code Morphing & Self-Modification

Generate syscall code at runtime:

```c
typedef struct {
    uint8_t code[64];
    size_t size;
} dynamic_syscall_t;

dynamic_syscall_t* generate_ptrace_call(int request, int pid) {
    dynamic_syscall_t* syscall_code = malloc(sizeof(dynamic_syscall_t));
    
    // Generate x86_64 syscall code at runtime
    uint8_t template[] = {
        0x48, 0xc7, 0xc0, 0x1a, 0x00, 0x00, 0x00,  // mov rax, 26 (ptrace)
        0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, request (placeholder)
        0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00,  // mov rsi, pid (placeholder)
        0x48, 0x31, 0xd2,                          // xor rdx, rdx
        0x4d, 0x31, 0xc0,                          // xor r8, r8
        0x0f, 0x05,                                // syscall
        0xc3                                       // ret
    };
    
    memcpy(syscall_code->code, template, sizeof(template));
    
    // Patch in the actual values
    *(uint32_t*)(syscall_code->code + 10) = request;
    *(uint32_t*)(syscall_code->code + 17) = pid;
    
    syscall_code->size = sizeof(template);
    
    // Make code executable
    if (mprotect(syscall_code, sizeof(dynamic_syscall_t), 
                PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        free(syscall_code);
        return NULL;
    }
    
    return syscall_code;
}

long execute_dynamic_syscall(dynamic_syscall_t* syscall_code) {
    // Cast to function pointer and execute
    long (*func)() = (long (*)())syscall_code->code;
    return func();
}
```

### Strategy 7: Multi-Vector Probabilistic Detection

Combine multiple weak signals instead of relying on strong ones:

```c
typedef struct {
    float weight;
    bool (*detect_func)(void);
    const char* name;
} detection_vector_t;

float calculate_debug_probability() {
    detection_vector_t vectors[] = {
        {0.3f, detect_via_timing, "timing"},
        {0.2f, detect_via_environment, "environment"}, 
        {0.15f, check_debug_env_vars, "env_vars"},
        {0.1f, detect_via_fd_analysis, "fd_count"},
        {0.1f, check_memory_anomalies, "memory"},
        {0.15f, detect_suspicious_processes, "processes"}
    };
    
    float debug_score = 0.0f;
    int vector_count = sizeof(vectors) / sizeof(vectors[0]);
    
    for (int i = 0; i < vector_count; i++) {
        if (vectors[i].detect_func()) {
            debug_score += vectors[i].weight;
            STEALTH_LOG_DEBUG("Detection vector '%s' triggered", vectors[i].name);
        }
    }
    
    return debug_score;
}

bool is_being_debugged() {
    float probability = calculate_debug_probability();
    
    // Use probabilistic threshold instead of binary detection
    // This makes it harder to identify exactly what triggered detection
    return probability > DEBUG_THRESHOLD; // e.g., 0.4
}
```

---

## Implementation Priority

1. **High Priority**: Implement timing-based and environment inference methods
2. **Medium Priority**: Add polymorphic detection and decoy operations  
3. **Low Priority**: Implement code morphing (complex but very effective)

## Key Principles

- **Defense in Depth**: Use multiple weak signals instead of strong obvious ones
- **Probabilistic Detection**: Make it hard to know exactly what triggered detection
- **Behavioral Mimicry**: Make the program look like legitimate software
- **Runtime Adaptation**: Change behavior based on detected environment

---

## Future Enhancements

- **Machine Learning**: Train models to detect analysis environments
- **Network-Based Detection**: Check for analysis tools via network behavior
- **Hardware Fingerprinting**: Use CPU/GPU characteristics to detect VMs
- **Social Engineering**: Present fake error messages to discourage analysis
