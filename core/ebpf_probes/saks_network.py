#!/usr/bin/env python3
from bcc import BPF
import time

# eBPF C program to intercept outbound TCP connections
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Hash map to store the socket pointer by PID
BPF_HASH(currsock, u32, struct sock *);

// Hook the entry of tcp_v4_connect
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    currsock.update(&pid, &sk);
    return 0;
}

// Hook the return of tcp_v4_connect to get the destination IP and Port
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock **skpp = currsock.lookup(&pid);
    
    if (skpp == 0) return 0; // Missed entry
    
    struct sock *skp = *skpp;
    u32 daddr = skp->__sk_common.skc_daddr;
    u16 dport = skp->__sk_common.skc_dport;
    
    // Print the destination IP (IPv4) and Port to the kernel trace buffer
    bpf_trace_printk("NETWORK_ALERT | PID: %d | Outbound IP: %pI4 | Port: %d\\n", pid, &daddr, ntohs(dport));
    
    currsock.delete(&pid);
    return 0;
}
"""

print("SAKS Network eBPF Tracer initializing... hooking tcp_v4_connect")
b = BPF(text=bpf_text)

# Read from the kernel trace buffer
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        decoded_msg = msg.decode('utf-8', 'replace')
        if "NETWORK_ALERT" in decoded_msg:
            print(f"[SAKS KERNEL ALERT] {decoded_msg}")
    except KeyboardInterrupt:
        exit()
