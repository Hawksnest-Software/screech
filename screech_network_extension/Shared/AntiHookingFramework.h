#ifndef AntiHookingFramework_h
#define AntiHookingFramework_h

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif

// Function pointer types for dynamic loading
typedef int (*syscall_ptr)(int, ...);
typedef void* (*dlsym_ptr)(void*, const char*);
typedef void* (*dlopen_ptr)(const char*, int);
typedef kern_return_t (*mach_vm_read_ptr)(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_offset_t*, mach_msg_type_number_t*);

// API call obfuscation macros
#define OBFUSCATED_SYSCALL(num, ...) obfuscated_syscall_wrapper(num, ##__VA_ARGS__)
#define SAFE_DLSYM(handle, symbol) safe_dlsym_wrapper(handle, symbol)
#define PROTECTED_API_CALL(api, ...) protected_api_call((void*)api, ##__VA_ARGS__)

// Hook detection result types
typedef NS_ENUM(NSInteger, HookDetectionResult) {
    HookDetectionResultClean = 0,
    HookDetectionResultSuspicious = 1,
    HookDetectionResultHooked = 2,
    HookDetectionResultUnknown = 3
};

// Anti-hooking service
@interface AntiHookingService : NSObject

+ (instancetype)sharedService;

// Hook detection methods
- (HookDetectionResult)detectAPIHooks;
- (BOOL)isSystemCallHooked:(int)syscallNumber;
- (BOOL)isFunctionHooked:(void*)functionAddress;
- (BOOL)isDylibHooked:(const char*)dylibPath;

// Memory protection methods
- (void)protectCriticalMemoryRegions;
- (BOOL)validateCodeIntegrity;
- (void)detectMemoryPatching;

// Dynamic loading obfuscation
- (void*)safeGetProcAddress:(const char*)library function:(const char*)function;
- (void*)obfuscatedDlopen:(const char*)path flags:(int)flags;
- (void*)obfuscatedDlsym:(void*)handle symbol:(const char*)symbol;

// System call obfuscation
- (int)obfuscatedSyscall:(int)number args:(va_list)args;
- (void)rotateSyscallMethods;

// Function call indirection
- (void*)createFunctionTrampoline:(void*)originalFunction;
- (void)callThroughTrampoline:(void*)trampoline args:(void*)args;

// Runtime evasion
- (void)polymorphicCodeExecution;
- (void)antiDebuggingChecks;
- (void)junkCodeInjection;

@end

// Direct system call interface (bypassing libc)
@interface DirectSyscallInterface : NSObject

+ (int)directSyscall:(int)number arg1:(long)arg1 arg2:(long)arg2 arg3:(long)arg3 arg4:(long)arg4;
+ (void)initializeDirectSyscalls;
+ (BOOL)validateSyscallTable;

@end

// Function pointer obfuscation
@interface FunctionPointerObfuscator : NSObject

+ (void*)obfuscatePointer:(void*)pointer key:(uintptr_t)key;
+ (void*)deobfuscatePointer:(void*)obfuscatedPointer key:(uintptr_t)key;
+ (uintptr_t)generateObfuscationKey;

@end

// Inline assembly wrappers for critical operations
static inline int direct_syscall_0(int syscall_num) {
    int result;
    __asm__ volatile (
        "mov w16, %w1\n\t"
        "svc 0\n\t"
        "mov %w0, w0\n\t"
        : "=r" (result)
        : "r" (syscall_num)
        : "x16", "x0"
    );
    return result;
}

static inline int direct_syscall_1(int syscall_num, long arg1) {
    int result;
    __asm__ volatile (
        "mov w16, %w1\n\t"
        "mov x0, %2\n\t"
        "svc 0\n\t"
        "mov %w0, w0\n\t"
        : "=r" (result)
        : "r" (syscall_num), "r" (arg1)
        : "x16", "x0"
    );
    return result;
}

static inline int direct_syscall_3(int syscall_num, long arg1, long arg2, long arg3) {
    int result;
    __asm__ volatile (
        "mov w16, %w1\n\t"
        "mov x0, %2\n\t"
        "mov x1, %3\n\t"
        "mov x2, %4\n\t"
        "svc 0\n\t"
        "mov %w0, w0\n\t"
        : "=r" (result)
        : "r" (syscall_num), "r" (arg1), "r" (arg2), "r" (arg3)
        : "x16", "x0", "x1", "x2"
    );
    return result;
}

// Dynamic API resolution
typedef struct {
    const char* library_name;
    const char* function_name;
    void** function_pointer;
    BOOL is_resolved;
    uint32_t checksum;
} dynamic_api_entry_t;

// Function integrity verification
typedef struct {
    void* function_address;
    size_t function_size;
    uint32_t original_checksum;
    BOOL is_hooked;
} function_integrity_t;

// Memory region protection
typedef struct {
    void* start_address;
    size_t size;
    vm_prot_t original_protection;
    vm_prot_t current_protection;
} protected_region_t;

// API call wrapper functions (declarations)
int obfuscated_syscall_wrapper(int syscall_num, ...);
void* safe_dlsym_wrapper(void* handle, const char* symbol);
void* protected_api_call(void* function_ptr, ...);

// Hook detection utilities
BOOL detect_inline_hook(void* function_address);
BOOL detect_iat_hook(const char* module_name, const char* function_name);
BOOL detect_trampoline_hook(void* function_address);
BOOL detect_vtable_hook(void* object, int method_index);

// Anti-analysis techniques
// Note: insert_anti_disassembly_code is provided by the main obfuscation framework
extern void insert_anti_disassembly_code(void); // From obfuscation engine
void create_fake_control_flow(void);
void obfuscate_string_references(void);
void randomize_execution_timing(void);

// Code morphing capabilities
void* generate_polymorphic_stub(void* original_function);
void rotate_encryption_keys(void);
void modify_code_checksums(void);

// Environment validation
BOOL validate_execution_environment(void);
BOOL detect_virtualized_environment(void);
BOOL detect_debugging_tools(void);
BOOL detect_code_injection(void);

#ifdef __cplusplus
}
#endif

#endif /* AntiHookingFramework_h */
