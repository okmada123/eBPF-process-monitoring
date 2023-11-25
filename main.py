#!/usr/bin/python3

import sys, os, requests, socket, struct, json
from bcc import BPF
from dotenv import load_dotenv
from time import time_ns

USE_BACKEND_TOGGLE = True # TODO - remove
C_CODE_PID_VARIABLE = "pid" # variable name representing the PID in the C code, preceeding #DEFAULT_PID# placeholder

load_dotenv()
API_URL = f"http://{os.getenv('API_HOST')}:{os.getenv('API_PORT')}{os.getenv('API_PROXY')}/log"

EVENT_FORK = 1
EVENT_EXEC = 2
EVENT_OPEN = 3
EVENT_CONNECT = 4
EVENT_ACCEPT = 5

EVENT_VALUES = [
    ("#EVENT_FORK_VALUE#", EVENT_FORK),
    ("#EVENT_EXEC_VALUE#", EVENT_EXEC),
    ("#EVENT_OPEN_VALUE#", EVENT_OPEN),
    ("#EVENT_CONNECT_VALUE#", EVENT_CONNECT),
    ("#EVENT_ACCEPT_VALUE#", EVENT_ACCEPT)
]

ebpf_text = """
#include <linux/ptrace.h>
#include <uapi/linux/ptrace.h>
#include <asm/fcntl.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/inet.h> // ntohs()

#define _TRUE 1
#define _FALSE 2 // static helper functions apparently cannot return 0
#define BUFSIZE 256

#define _EVENT_FORK #EVENT_FORK_VALUE#
#define _EVENT_EXEC #EVENT_EXEC_VALUE#
#define _EVENT_OPEN #EVENT_OPEN_VALUE#
#define _EVENT_CONNECT #EVENT_CONNECT_VALUE#
#define _EVENT_ACCEPT #EVENT_ACCEPT_VALUE#

struct output_data {
    u8 event_type;
    u32 pid;
    char path[BUFSIZE];
    int output_int_1;
    int output_int_2;
    int output_int_3;
    int output_int_4;
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

KRETFUNC_PROBE(do_sys_openat2, int dirfd, const char *pathname, void* openhow, int ret)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (is_tracked_pid(pid) != _TRUE) return 0;

    struct output_data data = {};
    if (bpf_probe_read_user(&data.path, sizeof(data.path), pathname) == 0) {
        data.pid = pid;
        data.event_type = _EVENT_OPEN;
        data.output_int_2 = ret;
        if (data.path[0] == '/')
            data.output_int_1 = _TRUE; // is absolute path
        else {
            if (dirfd == AT_FDCWD)
                data.output_int_1 = _FALSE; // is relative path at CWD
            // else // is relative path not at CWD - don't know if this could even happen
        }
        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// https://elixir.bootlin.com/linux/latest/source/include/net/tcp.h
// https://elixir.bootlin.com/linux/latest/source/include/net/sock.h
KRETFUNC_PROBE(tcp_v4_connect, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (is_tracked_pid(pid) != _TRUE) return 0;
    else
    {
        struct output_data data = {};
        data.event_type = _EVENT_CONNECT;
        data.pid = pid;
        data.output_int_1 = sk->__sk_common.skc_rcv_saddr; // src addr
        data.output_int_2 = sk->__sk_common.skc_num; // src port
        data.output_int_3 = sk->__sk_common.skc_daddr; // dst addr
        data.output_int_4 = ntohs(sk->__sk_common.skc_dport); // dst port
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
}

// https://elixir.bootlin.com/linux/latest/source/include/linux/socket.h#L445
// the arguments are pointers to user space memory, so we have to read it using bpf_probe_read_user()

KRETFUNC_PROBE(__sys_accept4, int sock_fd, struct sockaddr* userspace_addr, int* userspace_addrlen)
{
    u32 pid = bpf_get_current_pid_tgid();
    if (is_tracked_pid(pid) != _TRUE) return 0;

    int addrlen = 0;
    if (bpf_probe_read_user(&addrlen, sizeof(addrlen), userspace_addrlen) != 0)
    {
        return 0; // bpf_probe_read_user() failed, stop
    }

    struct sockaddr addr;
    if (sizeof(addr) < addrlen)
    {
        return 0; // addrlen should be of size sockaddr
    }

    if (bpf_probe_read_user(&addr, sizeof(addr), userspace_addr) != 0)
    {
        return 0; // bpf_probe_read_user() failed, stop
    }

    if (addr.sa_family == AF_INET) // we only care about IPv4
    {
        struct sockaddr_in* internet_socket = (struct sockaddr_in*)&addr;
        struct output_data data = {};
        data.event_type = _EVENT_ACCEPT;
        data.pid = pid;
        data.output_int_1 = internet_socket->sin_addr.s_addr; // remote addr
        data.output_int_2 = ntohs(internet_socket->sin_port); // remote port
        events.perf_submit(ctx, &data, sizeof(data));
    }
    
    return 0;
}

"""

if (len(sys.argv) < 2):
    print("Usage: ./main.py <DEFAULT-PID> [ANOTHER-PID-1] [ANOTHER-PID-2] ... ")
    exit(1)

monitored_pids = []
try:
    for i in range(1, len(sys.argv)):
        pid = int(sys.argv[i])
        if pid <= 0: raise Exception
        monitored_pids.append(pid)
except:
    print("<PID> has to be a positive integer.")
    exit(1)

monitored_pids_replace_string = str(monitored_pids[0])
if (len(monitored_pids) > 1):
    for i in range(1, len(monitored_pids)):
        monitored_pids_replace_string += f" || {C_CODE_PID_VARIABLE} == {str(monitored_pids[i])}"
ebpf_text = ebpf_text.replace("#DEFAULT_PID#", monitored_pids_replace_string)

for event in EVENT_VALUES:
    ebpf_text = ebpf_text.replace(event[0], str(event[1]))

# Load the eBPF program
b = BPF(text=ebpf_text)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")

def event_to_json(event):
    json_dict = {
        "pid": event.pid,
        "event_type": event.event_type,
        "path": event.path.decode(),
        "event_output_1": event.output_int_1,
        "event_output_2": event.output_int_2,
        "timestamp": time_ns() // 1000000,
    }
    # Create socket strings for connect
    if event.event_type == EVENT_CONNECT:
        srcaddr = socket.inet_ntoa(struct.pack("<L", event.output_int_1))
        dstaddr = socket.inet_ntoa(struct.pack("<L", event.output_int_3))
        lsocket = f"{srcaddr}:{event.output_int_2}"
        dsocket = f"{dstaddr}:{event.output_int_4}"
        json_dict["event_output_1"] = lsocket
        json_dict["event_output_2"] = dsocket
    elif event.event_type == EVENT_ACCEPT:
        remoteaddr = socket.inet_ntoa(struct.pack("<L", event.output_int_1))
        json_dict["event_output_1"] = remoteaddr
    
    return json.dumps(json_dict)

def log_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID: {event.pid}, EVENT TYPE: {event.event_type}, PATH: {event.path} INT1: {event.output_int_1}, INT2: {event.output_int_2}, INT3: {event.output_int_3}, INT4: {event.output_int_4}")
    if (not USE_BACKEND_TOGGLE): return
    try:
        res = requests.post(API_URL, event_to_json(event))
        if res.status_code != 200:
            print("Response not OK:", res.status_code)
    except Exception as e:
        print(e)
        exit(1)

print(f"Monitoring of {monitored_pids} started...")

# loop with callback to print_event
b["events"].open_perf_buffer(log_event)
while 1:
    b.perf_buffer_poll()