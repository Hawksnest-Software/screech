//
// direct_syscalls.h - Direct syscall implementations to bypass libc
// These functions call system calls directly to avoid library detection
//

#ifndef DIRECT_SYSCALLS_H
#define DIRECT_SYSCALLS_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Direct syscall implementations that bypass libc
// Only available when ENABLE_DIRECT_SYSCALLS is defined at compile time

#ifdef ENABLE_DIRECT_SYSCALLS

/**
 * Direct ptrace syscall - bypasses libc ptrace()
 * @param request ptrace request type  
 * @param pid target process ID
 * @param addr memory address for some requests
 * @param data data pointer for some requests
 * @return syscall result (varies by request)
 */
long obfuscated_ptrace(int request, int pid, void* addr, void* data);

/**
 * Direct sysctl syscall - bypasses libc sysctl()
 * @param name MIB array specifying the sysctl
 * @param namelen length of the MIB array
 * @param oldp buffer to receive current value
 * @param oldlenp size of oldp buffer
 * @param newp buffer containing new value (or NULL)
 * @param newlen size of newp buffer
 * @return 0 on success, -1 on error
 */
long obfuscated_sysctl(int* name, unsigned int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen);

#else

// When direct syscalls are disabled, these functions are implemented in obfuscation_engine.c
// (declarations are in obfuscation_engine.h)

#endif

#ifdef __cplusplus
}
#endif

#endif // DIRECT_SYSCALLS_H
