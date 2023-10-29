#!/usr/bin/python3

from bcc import BPF

ebpf_text = """
#include <linux/ptrace.h>
#include <linux/limits.h> // PATH_MAX
#include <asm/fcntl.h>

// Find the correct function name here https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/open.c and here https://filippo.io/linux-syscall-table/
KRETFUNC_PROBE(do_sys_openat2, int dirfd, const char *pathname)
{
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

# Load the eBPF program
b = BPF(text=ebpf_text)

while True:
    try:
        print(b.trace_readline())
    except KeyboardInterrupt:
        break
