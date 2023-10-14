#!/usr/bin/python3

from bcc import BPF

# eBPF program code
ebpf_text = """
#include <linux/ptrace.h>

int trace_fork(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();

    // return value of the fork system call
    int rv = PT_REGS_RC(ctx);

    // Print the return value
    bpf_trace_printk("parent %d - fork return value: %d\\n", pid, rv);

    return 0;
}
"""

# Load the eBPF program
b = BPF(text=ebpf_text)

# Attach the program to the clone return
b.attach_kretprobe(event=b.get_syscall_fnname("clone"), fn_name="trace_fork")

while True:
    try:
        print(b.trace_readline())
    except KeyboardInterrupt:
        break
