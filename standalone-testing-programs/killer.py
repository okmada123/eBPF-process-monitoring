#!/usr/bin/python3

from bcc import BPF

b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/signal.h>

int syscall__execve(struct pt_regs *ctx, const char *filename)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (pid >= 6000 & pid <= 10000)
    {
        long rv = bpf_send_signal(SIGKILL);
        bpf_trace_printk("exec killed ? rv: %d\\n", rv);
        return 0;
    }
    else
    {
        char buff[256];
        int rv = bpf_probe_read_user(buff, sizeof(buff), filename);
        bpf_trace_printk("pid: %d, buffer: %s\\n", pid, buff);

        return 0;
    }
}
""")
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
b.trace_print()
