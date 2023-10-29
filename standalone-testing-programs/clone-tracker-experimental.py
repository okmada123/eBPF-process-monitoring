#!/usr/bin/python3

# Using KRETFUNC_PROBE to catch clones seems to be more reliable thanwhat I was doing in fork-tracker.

from bcc import BPF

# eBPF program code
ebpf_text = """
#include <linux/ptrace.h>

KRETFUNC_PROBE(kernel_clone, void* args, int rv) {
    u32 pid = bpf_get_current_pid_tgid();
   
    bpf_trace_printk("fork parent: %d, child: %d \\n", pid, rv);

    return 0;
}

"""

# Load the eBPF program
b = BPF(text=ebpf_text)

while True:
    try:
        print(b.trace_readline())
    except KeyboardInterrupt:
        break
