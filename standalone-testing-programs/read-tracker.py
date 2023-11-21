# This doesn't work very well, because I can't figure out how to get full path from file descriptor

#!/usr/bin/python3

from bcc import BPF
import sys

# eBPF program code
ebpf_text = """
#include <linux/ptrace.h>
#define _TRUE 1
#define _FALSE 2 // static helper functions apparently cannot return 0

BPF_HASH(tracked_pids, u32, char);

static int is_tracked_pid(u32 pid)
{
    if (pid == #DEFAULT_PID#) return _TRUE;
    
    char* map_value = tracked_pids.lookup(&pid);
    if (map_value == NULL || *map_value == _FALSE)
    {
        return _FALSE;
    }

    return _TRUE;
}

static void remember_fork(u32 parent_pid, u32 child_pid, char val)
{
    // remember child value in the map so that we can track it
    tracked_pids.insert(&child_pid, &val);
}

KRETFUNC_PROBE(kernel_clone, void* args, int child_pid)
{
    u32 parent_pid = bpf_get_current_pid_tgid();
    if (is_tracked_pid(parent_pid) != _TRUE) return 0;
    else
    {
        remember_fork(parent_pid, child_pid, _TRUE);
        // Print info
        bpf_trace_printk("parent %d - fork return value: %d\\n", parent_pid, child_pid);
        return 0;
    }
}

// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/read_write.c
KFUNC_PROBE(ksys_read, int fd)
{
    if (fd == 0) return 0; // don't track stdin 
    u32 pid = bpf_get_current_pid_tgid();
    if (is_tracked_pid(pid) != _TRUE) return 0;
    else
    {
        bpf_trace_printk("read %d FD: %d\\n", pid, fd);
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

while True:
    try:
        print(b.trace_readline())
    except KeyboardInterrupt:
        break

