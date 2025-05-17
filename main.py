#!/usr/bin/env python3

import sys
import os
from bcc import BPF


# Dictionary to store chunks of data for each PID
output_buffer = {}

r = open('ebpf/trace.c').read()
r = r.replace('{{PID}}', str(os.getpid()))
bpf = BPF(text = r)

def print_open_event(cpu, data, size):
    event = bpf["open_event"].event(data)
    # print (len(event.content), event.pid, event.comm, event.len, event.chunk_len, event.content, file=sys.stdout)
    
    if len(event.content) < event.chunk_len: #sftp
        return

    if output_buffer.get(event.pid) == None:
        output_buffer[event.pid] = {}
    
    if output_buffer[event.pid].get(event.len) == None:
        output_buffer[event.pid][event.len] = {'txt': '', 'len': event.len, 'current_len': 0}

    output_buffer[event.pid][event.len]['current_len'] += event.chunk_len
    try:
        str = event.content[:event.chunk_len].decode('utf-8') # htop uses some non-utf controll symbols
        output_buffer[event.pid][event.len]['txt'] += str
    except Exception:
        return        

    if output_buffer[event.pid][event.len]['current_len'] == output_buffer[event.pid][event.len]['len']:
        print("%s (%d): %s" % (event.comm.decode("utf-8"), event.pid, output_buffer[event.pid][event.len]['txt']))
        del output_buffer[event.pid][event.len]


bpf["open_event"].open_perf_buffer(print_open_event)

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

def get_process_args(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
            argv = raw.split(b'\x00')
            argv = [arg.decode() for arg in argv if arg]
            print("    ARGV:", " ".join(argv), file=sys.stdout)
    except Exception as e:
        print(f"    Could not read cmdline: {e}", file=sys.stdout)
