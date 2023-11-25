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

try:
    ebpf_text = open("source.c", "r").read()
except Exception as e:
    print("Failed to load eBPF program source code.", str(e))
    exit(1)

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
        raddr = socket.inet_ntoa(struct.pack("<L", event.output_int_1))
        rport = json_dict["event_output_2"]
        json_dict["event_output_1"] = f"{raddr}:{rport}"
        json_dict["event_output_2"] = 0
    
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
        print(str(e))
        exit(1)

print(f"Monitoring of {monitored_pids} started...")

# loop with callback to print_event
b["events"].open_perf_buffer(log_event)
while 1:
    b.perf_buffer_poll()