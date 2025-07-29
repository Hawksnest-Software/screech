#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Include guards for older kernel compatibility
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define MAX_CONNECTIONS 10000
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Connection info structure shared between kernel and userspace
struct connection_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;  // IPPROTO_TCP or IPPROTO_UDP
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    __u64 timestamp;
    __u8 event_type; // 0=socket_create, 1=connect, 2=sendto
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} connection_events SEC(".maps");

// Hash map to track seen connections (avoid duplicates)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, __u64);  // connection key (src_ip:src_port -> dst_ip:dst_port)
    __type(value, __u8); // just a flag
} seen_connections SEC(".maps");

// Helper function to create connection key
static __always_inline __u64 make_connection_key(__u32 src_ip, __u16 src_port, __u32 dst_ip, __u16 dst_port) {
    return ((__u64)src_ip << 32) | ((__u64)src_port << 16) | dst_port;
}

// Helper to check if IP is external (not private)
static __always_inline int is_external_ip(__u32 ip) {
    __u8 first_octet = (ip >> 24) & 0xFF;
    __u8 second_octet = (ip >> 16) & 0xFF;
    
    // 10.0.0.0/8
    if (first_octet == 10) return 0;
    
    // 172.16.0.0/12
    if (first_octet == 172 && (second_octet >= 16 && second_octet <= 31)) return 0;
    
    // 192.168.0.0/16
    if (first_octet == 192 && second_octet == 168) return 0;
    
    // 127.0.0.0/8 (loopback)
    if (first_octet == 127) return 0;
    
    return 1;
}

// Helper to get process executable path - compatible with older kernels
static __always_inline void get_process_path(struct connection_event *event) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        event->filename[0] = '\0';
        return;
    }
    
    struct mm_struct *mm;
    if (bpf_core_read(&mm, sizeof(mm), &task->mm) != 0 || !mm) {
        event->filename[0] = '\0';
        return;
    }
    
    struct file *exe_file;
    if (bpf_core_read(&exe_file, sizeof(exe_file), &mm->exe_file) != 0 || !exe_file) {
        event->filename[0] = '\0';
        return;
    }
    
    struct dentry *dentry;
    if (bpf_core_read(&dentry, sizeof(dentry), &exe_file->f_path.dentry) != 0 || !dentry) {
        event->filename[0] = '\0';
        return;
    }
    
    struct qstr d_name;
    if (bpf_core_read(&d_name, sizeof(d_name), &dentry->d_name) != 0) {
        event->filename[0] = '\0';
        return;
    }
    
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), d_name.name);
}

// Helper to fill common event fields
static __always_inline void fill_event_common(struct connection_event *event, __u8 event_type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    event->pid = pid_tgid >> 32;
    event->uid = uid_gid & 0xFFFFFFFF;
    event->gid = uid_gid >> 32;
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = event_type;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_process_path(event);
}

// Track TCP connect attempts
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sockaddr *uaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    
    if (!sk || !uaddr) 
        return 0;
    
    // Reserve space in ring buffer
    struct connection_event *event = bpf_ringbuf_reserve(&connection_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Fill common fields
    fill_event_common(event, 1); // event_type = connect
    event->protocol = IPPROTO_TCP;
    
    // Get source information from socket - with error checking
    struct inet_sock *inet = (struct inet_sock *)sk;
    if (inet) {
        __u32 saddr;
        __u16 sport;
        if (bpf_core_read(&saddr, sizeof(saddr), &inet->inet_saddr) == 0) {
            event->src_ip = saddr;
        }
        if (bpf_core_read(&sport, sizeof(sport), &inet->inet_sport) == 0) {
            event->src_port = __builtin_bswap16(sport);
        }
    }
    
    // Extract destination from sockaddr
    if (uaddr->sa_family == AF_INET) {
        struct sockaddr_in addr_in;
        bpf_probe_read_kernel(&addr_in, sizeof(addr_in), uaddr);
        event->dst_ip = addr_in.sin_addr.s_addr;
        event->dst_port = __builtin_bswap16(addr_in.sin_port);
    }
    
    // Check if we've seen this connection before
    __u64 conn_key = make_connection_key(event->src_ip, event->src_port, event->dst_ip, event->dst_port);
    if (bpf_map_lookup_elem(&seen_connections, &conn_key)) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Mark as seen
    __u8 flag = 1;
    bpf_map_update_elem(&seen_connections, &conn_key, &flag, BPF_ANY);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Track UDP sendmsg calls
SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    
    if (!sk || !msg)
        return 0;
    
    // Reserve space in ring buffer
    struct connection_event *event = bpf_ringbuf_reserve(&connection_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Fill common fields
    fill_event_common(event, 2); // event_type = sendto
    event->protocol = IPPROTO_UDP;
    
    // Get source information from socket - with error checking
    struct inet_sock *inet = (struct inet_sock *)sk;
    if (inet) {
        __u32 saddr;
        __u16 sport;
        if (bpf_core_read(&saddr, sizeof(saddr), &inet->inet_saddr) == 0) {
            event->src_ip = saddr;
        }
        if (bpf_core_read(&sport, sizeof(sport), &inet->inet_sport) == 0) {
            event->src_port = __builtin_bswap16(sport);
        }
    }
    
    // Get destination from msghdr - with error checking
    struct sockaddr *addr;
    __u32 addr_len;
    if (bpf_core_read(&addr, sizeof(addr), &msg->msg_name) != 0) {
        addr = NULL;
    }
    if (bpf_core_read(&addr_len, sizeof(addr_len), &msg->msg_namelen) != 0) {
        addr_len = 0;
    }
    
    if (addr && addr_len >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in addr_in;
        bpf_probe_read_kernel(&addr_in, sizeof(addr_in), addr);
        
        if (addr_in.sin_family == AF_INET) {
            event->dst_ip = addr_in.sin_addr.s_addr;
            event->dst_port = __builtin_bswap16(addr_in.sin_port);
        }
    }
    
    // Check if we've seen this connection before
    __u64 conn_key = make_connection_key(event->src_ip, event->src_port, event->dst_ip, event->dst_port);
    if (bpf_map_lookup_elem(&seen_connections, &conn_key)) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Mark as seen
    __u8 flag = 1;
    bpf_map_update_elem(&seen_connections, &conn_key, &flag, BPF_ANY);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Track socket creation for additional context
SEC("kprobe/__sys_socket")
int trace_socket_create(struct pt_regs *ctx) {
    int family = (int)PT_REGS_PARM1(ctx);
    int type = (int)PT_REGS_PARM2(ctx);
    int protocol = (int)PT_REGS_PARM3(ctx);
    
    // Only track inet sockets
    if (family != AF_INET && family != AF_INET6)
        return 0;
    
    // Reserve space in ring buffer
    struct connection_event *event = bpf_ringbuf_reserve(&connection_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Fill common fields
    fill_event_common(event, 0); // event_type = socket_create
    
    // Determine protocol
    if (type == SOCK_STREAM) {
        event->protocol = IPPROTO_TCP;
    } else if (type == SOCK_DGRAM) {
        event->protocol = IPPROTO_UDP;
    } else {
        event->protocol = 0; // Other
    }
    
    // No specific connection details yet
    event->src_ip = 0;
    event->dst_ip = 0;
    event->src_port = 0;
    event->dst_port = 0;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Track network namespace changes (for container monitoring)
SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx) {
    // This can be used to track network namespace changes
    // Useful for container network monitoring
    return 0;
}

// Track process execution for better process tracking
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    // This can be used to track process creation
    // and maintain a process tree
    return 0;
}

char _license[] SEC("license") = "GPL";
