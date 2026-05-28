#!/usr/bin/env python3
from bcc import BPF
import time

# eBPF C program to hook into process creation
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

// Hook into the sys_execve system call (process execution)
int syscall__execve(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

print("SAKS eBPF Tracer initializing... hooking sys_execve")
b = BPF(text=bpf_text)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"[SAKS KERNEL ALERT] Process Execution Detected - PID: {event.pid}, Command: {event.comm.decode('utf-8', 'replace')}")

b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
