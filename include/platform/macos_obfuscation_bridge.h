//
// macos_obfuscation_bridge.h - Objective-C Bridge for macOS-specific features
// Features that require Objective-C or macOS frameworks
//

#ifndef MACOS_OBFUSCATION_BRIDGE_H
#define MACOS_OBFUSCATION_BRIDGE_H

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#endif

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>

#ifdef __cplusplus
extern "C" {
#endif

// macOS-specific memory protection using Mach kernel
void protect_critical_memory_regions(void);

// Advanced syscall obfuscation with ARM64 assembly
long obfuscated_syscall(int syscall_number, void *args, int arg_count);

// Dynamic library integrity checking
bool is_dylib_hooked(const char *dylib_path);

// Polymorphic execution with Objective-C blocks
typedef void (^PolymorphicBlock)(void);
void perform_polymorphic_execution(PolymorphicBlock block);

// Objective-C runtime manipulation for additional obfuscation
void obfuscate_objc_runtime(void);
void restore_objc_runtime(void);

// Enhanced random number generation using macOS APIs
uint32_t secure_random_uniform(uint32_t upper_bound);

// Threading with integrity monitoring
void start_integrity_monitoring_with_objc(void);
void stop_integrity_monitoring_with_objc(void);

// Stealthy anti-debugging using high-level macOS APIs (no ptrace)
void apply_stealth_anti_debugging(void);

#ifdef __cplusplus
}
#endif

#endif // MACOS_OBFUSCATION_BRIDGE_H
