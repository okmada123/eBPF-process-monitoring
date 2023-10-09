#!/usr/bin/python3

from bcc import BPF

b = BPF(text="""
#include <uapi/linux/ptrace.h>

int syscall__execve(struct pt_regs *ctx, const char *filename)
{
    char buff[256];
    int rv = bpf_probe_read_user(buff, sizeof(buff), filename);
    bpf_trace_printk("rv: %d, buffer: %s\\n", rv, buff);

    return 0;
}
""")
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
b.trace_print()
