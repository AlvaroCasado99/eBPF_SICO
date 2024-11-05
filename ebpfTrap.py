#!/usr/bin/python3

from bcc import BPF
import pwd

program = """
#include <linux/string.h>
#include <linux/limits.h>
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 uid;
    char filename[NAME_MAX];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    const char *route = (const char *)args->filename;
    bpf_probe_read_str(&data.filename, sizeof(data.filename), route);
    
    char target[] = "/home/horus/Documents/Master/SICO/eBPF_SICO/trampa.txt";

    if(memcmp(target, data.filename, sizeof(target))){
        bpf_trace_printk("Han entrado");
        events.perf_submit(args, &data, sizeof(data));
    }

    return 0;
}

"""


b = BPF(text=program)

def callback(cpu, data, size):
    event = b["events"].event(data)
    uid = event.uid

    user_name = pwd.getpwuid(uid).pw_name
    print(f"El usuario {user_name} accedió al archivo")

b["events"].open_perf_buffer(callback)

while True:
    b.perf_buffer_poll()

#b.trace_print()
