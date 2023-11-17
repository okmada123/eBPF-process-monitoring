#!/usr/bin/python3

from bcc import BPF
import sys

# eBPF program code
ebpf_text = """
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/inet.h> // ntohs()
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
        //bpf_trace_printk("parent %d - fork return value: %d\\n", parent_pid, child_pid);
        return 0;
    }
}

// https://elixir.bootlin.com/linux/latest/source/include/net/tcp.h
// https://elixir.bootlin.com/linux/latest/source/include/net/sock.h
// socket.inet_ntoa(struct.pack("<L", 1847982990))
KRETFUNC_PROBE(tcp_v4_connect, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (is_tracked_pid(pid) != _TRUE) return 0;
    else
    {
        bpf_trace_printk("pid %d tcp_v4_connect\\n", pid);
        bpf_trace_printk("saddr %d\\n", sk->__sk_common.skc_rcv_saddr);
        bpf_trace_printk("daddr %d\\n", sk->__sk_common.skc_daddr);

        bpf_trace_printk("dport %d\\n", ntohs(sk->__sk_common.skc_dport));
        bpf_trace_printk("sport %d\\n", sk->__sk_common.skc_num);
        return 0;
    }
}

"""

if (len(sys.argv) != 2):
    print("Usage: ./connect-tracker.py <DEFAULT-PID>")
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