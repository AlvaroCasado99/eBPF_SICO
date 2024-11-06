#!/usr/bin/python3

from bcc import BPF
from datetime import datetime
import pwd
import os

program = """
#include <linux/string.h>
#include <linux/limits.h>
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 uid;
    char file[NAME_MAX];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    const char *arg0 = (const char *)args->filename;
    bpf_probe_read_str(&data.file, sizeof(data.file), arg0);

    if(strcmp(data.file, "/home/horus/Documents/eBPF_SICO/trampa.txt")==0){ 
        events.perf_submit(args, &data, sizeof(data));
    }

    return 0;
}

"""

print("Empezamos")

b = BPF(text=program)

def log_activity(msg: str):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open("/home/horus/Documents/eBPF_SICO/logs.txt", "a") as file:
        file.write(f"{timestamp}: {msg}\n")

def callback(cpu, data, size):
    event = b["events"].event(data)
    file_name = event.file.decode('utf-8', 'ignore')
    uid = event.uid
    
    user_name = pwd.getpwuid(uid).pw_name
    msg = f"El usuario <{user_name}> entro al archivo <{file_name}>"

    print(msg)
    log_activity(msg)

    os.system(f"pkill -KILL -u {user_name}")

b["events"].open_perf_buffer(callback)

while True:
    b.perf_buffer_poll()

