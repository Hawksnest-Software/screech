//
//  ScreechObfuscation.h
//  Screech Obfuscation Library
//
//  Created by Screech Framework
//

#ifndef ScreechObfuscation_h
#define ScreechObfuscation_h

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach/mach_vm.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// Core obfuscation interface
@interface ScreechObfuscationEngine : NSObject

// Anti-hooking methods
+ (BOOL)detectFunctionHooks:(void *)functionPtr;
+ (BOOL)validateCodeIntegrity;
+ (void)obfuscateFunctionPointers;
+ (BOOL)isDylibHooked:(NSString *)dylibPath;

// Syscall obfuscation
+ (long)obfuscatedSyscall:(int)syscallNumber withArgs:(void *)args argCount:(int)count;
+ (void)randomizeSyscallOrder;

// Anti-analysis
+ (void)insertAntiDisassemblyCode;
+ (void)performPolymorphicExecution:(void(^)(void))block;
+ (BOOL)detectDebugger;
+ (BOOL)detectVirtualMachine;

// Memory protection
+ (void)protectCriticalMemoryRegions;
+ (void)scrambleMemoryLayout;

// Integrity monitoring
+ (void)startIntegrityMonitoring;
+ (void)stopIntegrityMonitoring;

@end

// C API for performance-critical operations
void screech_init_obfuscation(void);
void screech_cleanup_obfuscation(void);
int screech_obfuscated_syscall(int syscall_num, ...);
void screech_anti_disasm_barrier(void);
bool screech_detect_hooks(void *func_ptr);

// Additional C wrapper functions
bool screech_detect_debugger(void);
bool screech_detect_vm(void);
bool screech_validate_integrity(void);
void screech_start_monitoring(void);
void screech_stop_monitoring(void);

#ifdef __cplusplus
}
#endif

#endif /* ScreechObfuscation_h */
