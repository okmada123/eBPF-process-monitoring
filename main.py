#!/usr/bin/python3

from bcc import BPF
import sys

EVENT_VALUES = [
    ("FORK", "#EVENT_FORK_VALUE#", 1),
    ("EXEC", "#EVENT_EXEC_VALUE#", 2),
    ("OPEN", "#EVENT_OPEN_VALUE#", 3)
]

ebpf_text = """
#include <linux/ptrace.h>
#include <uapi/linux/ptrace.h>
#include <asm/fcntl.h>

#define _TRUE 1
#define _FALSE 2 // static helper functions apparently cannot return 0
#define BUFSIZE 256

#define _EVENT_FORK #EVENT_FORK_VALUE#
#define _EVENT_EXEC #EVENT_EXEC_VALUE#
#define _EVENT_OPEN #EVENT_OPEN_VALUE#

struct output_data {
    u8 event_type;
    u32 pid;
    char path[BUFSIZE];
    u32 output_int_1;
    u32 output_int_2;
};
BPF_PERF_OUTPUT(events);

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

/* remember child value in the map so that we can track it */
static void remember_fork(u32 parent_pid, u32 child_pid, char val)
{
    tracked_pids.insert(&child_pid, &val);
}

KRETFUNC_PROBE(kernel_clone, void* args, int child_pid)
{
    u32 parent_pid = bpf_get_current_pid_tgid();
    if (is_tracked_pid(parent_pid) != _TRUE) return 0;
    else
    {
        remember_fork(parent_pid, child_pid, _TRUE);
        
        struct output_data data = {};
        data.event_type = _EVENT_FORK;
        data.pid = parent_pid;
        data.output_int_1 = child_pid;
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
}

int syscall__execve(struct pt_regs *ctx, const char *filename)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (is_tracked_pid(pid) != _TRUE) return 0;

    struct output_data data = {};
    if (bpf_probe_read_user(&data.path, sizeof(data.path), filename) == 0)
    {
        data.event_type = _EVENT_EXEC;
        data.pid = pid;
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
    else // bpf_probe_read_user failed
    {
        return 1;
    }
}

KRETFUNC_PROBE(do_sys_openat2, int dirfd, const char *pathname)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (is_tracked_pid(pid) != _TRUE) return 0;

    struct output_data data = {};
    if (bpf_probe_read_user(&data.path, sizeof(data.path), pathname) == 0) {
        data.pid = pid;
        data.event_type = _EVENT_OPEN;
        if (data.path[0] == '/')
            data.output_int_1 = _TRUE; // is absolute path
        else {
            if (dirfd == AT_FDCWD)
                data.output_int_1 = _FALSE; // is relative path at CWD
            // else // is relative path not at CWD - don't know if this could even happen
                // bpf_trace_printk("relative path file open: %s, NOT the current working directory... (%d)\\n", buff, dirfd);
        }
        events.perf_submit(ctx, &data, sizeof(data));
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
for event in EVENT_VALUES:
    ebpf_text = ebpf_text.replace(event[1], str(event[2]))

# Load the eBPF program
b = BPF(text=ebpf_text)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")

# while True:
#     try:
#         print(b.trace_readline())
#     except KeyboardInterrupt:
#         break

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID: {event.pid}, EVENT TYPE: {event.event_type}, PATH: {event.path} INT1: {event.output_int_1}")

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()