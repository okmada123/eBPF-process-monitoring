#!/usr/bin/python3

from bcc import BPF
import sys

ebpf_text = """
#include <linux/ptrace.h>
#include <uapi/linux/ptrace.h>
#include <asm/fcntl.h>

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

int syscall__execve(struct pt_regs *ctx, const char *filename)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (is_tracked_pid(pid) != _TRUE) return 0;

    char buff[256];
    if (bpf_probe_read_user(buff, sizeof(buff), filename) == 0)
    {
        bpf_trace_printk("execve: %s\\n", buff);
    }
    else
    {
        bpf_trace_printk("execve, but user space read failed\\n");
    }

    return 0;
}

KRETFUNC_PROBE(do_sys_openat2, int dirfd, const char *pathname)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (is_tracked_pid(pid) != _TRUE) return 0;

    char buff[256];
    if (bpf_probe_read_user(buff, sizeof(buff), pathname) == 0) {
        if (buff[0] == '/')
            bpf_trace_printk("absolute path file open: %s\\n", buff);
        else {
            if (dirfd == AT_FDCWD)
                bpf_trace_printk("relative path file open: %s, at current working directory (%d)\\n", buff, dirfd); // TODO - can we find the path of the current working directory?
            else
                bpf_trace_printk("relative path file open: %s, NOT the current working directory... (%d)\\n", buff, dirfd);
        }
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
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")

while True:
    try:
        print(b.trace_readline())
    except KeyboardInterrupt:
        break
