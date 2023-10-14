#!/usr/bin/python3

from bcc import BPF
import sys

# eBPF program code
ebpf_text = """
#include <linux/ptrace.h>

BPF_HASH(tracked_pids, u32, char);

static void remember_fork(u32 parent_pid, u32 child_pid, char val)
{
    // remember child value in the map so that we can track it
    tracked_pids.insert(&child_pid, &val);

    // Print info
    bpf_trace_printk("parent %d - fork return value: %d\\n", parent_pid, child_pid);
}

int trace_fork(struct pt_regs *ctx)
{
    char _TRUE = 1, _FALSE = 0;
    u32 parent_pid = bpf_get_current_pid_tgid();

    // return value of the fork system call
    u32 child_pid = PT_REGS_RC(ctx);

    if (parent_pid == #DEFAULT_PID#)
    {
        remember_fork(parent_pid, child_pid, _TRUE);
    }
    else
    {
        char* map_value = tracked_pids.lookup(&parent_pid);
        if (map_value == NULL || *map_value == _FALSE)
            return 0; // we don't track this PID so we don't care about it forking a process
        
        // we do track it
        remember_fork(parent_pid, child_pid, _TRUE);
    }

    return 0;
}
"""

if (len(sys.argv) != 2):
    print("Usage: ./fork-tracker.py <DEFAULT-PID>")
    exit(1)

try:
    default_pid = int(sys.argv[1])
    if default_pid <= 0: raise Exception
except:
    print("<DEFAULT-PID> has to be a valid PID (positive integer)")
    exit(1)

ebpf_text = ebpf_text.replace("#DEFAULT_PID#", str(default_pid))

# Load the eBPF program
b = BPF(text=ebpf_text)

# Attach the program to the clone return
b.attach_kretprobe(event=b.get_syscall_fnname("clone"), fn_name="trace_fork")

while True:
    try:
        print(b.trace_readline())
    except KeyboardInterrupt:
        break
