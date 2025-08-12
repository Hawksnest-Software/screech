#ifndef __VMLINUX_H__
#define __VMLINUX_H__

// Standard C types
typedef unsigned long size_t;

// Basic kernel types
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;

typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

// Network byte order types
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

// BPF map types
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2

// BPF update flags
#define BPF_ANY 0

// Socket address families
#define AF_INET 2
#define AF_INET6 10

// Socket types
#define SOCK_STREAM 1
#define SOCK_DGRAM 2

// Protocols
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Forward declarations to avoid circular dependencies
struct trace_entry;

// Complete user_pt_regs structure for ARM64 (expected by libbpf)
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};
#endif

// Complete pt_regs structure - architecture specific
#ifdef __aarch64__
struct pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};
#else
// x86_64 pt_regs
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};
#endif

// File system structures
struct qstr {
    unsigned int len;
    const char *name;
};

struct path {
    struct dentry *dentry;
};

struct dentry {
    struct qstr d_name;
};

struct file {
    struct path f_path;
};

struct mm_struct {
    struct file *exe_file;
};

// Process structures
struct task_struct {
    int pid;
    int tgid;
    char comm[16];
    struct mm_struct *mm;
};

// Network structures
struct sock {
    unsigned short sk_family;
    unsigned short sk_type;
    unsigned short sk_protocol;
};

struct inet_sock {
    struct sock sk;
    __u32 inet_saddr;
    __u16 inet_sport;
    __u16 inet_dport;
    __u32 inet_daddr;
};

struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct {
        __u32 s_addr;
    } sin_addr;
    char sin_zero[8];
};

struct iovec {
    void *iov_base;
    size_t iov_len;
};

struct msghdr {
    void *msg_name;
    int msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    unsigned int msg_flags;
};

// Tracepoint structures
struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
};

#endif /* __VMLINUX_H__ */
