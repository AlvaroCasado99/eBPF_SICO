#!/usr/bin/python3

from bcc import BPF
import pwd

program = """
#include <linux/string.h>
#include <linux/limits.h>
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 uid;
    char file[100];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    const char *arg0 = (const char *)args->filename;
    bpf_probe_read_str(&data.file, sizeof(data.file), arg0);

    char target[60] = "/home/horus/Documents/Master/SICO/eBPF_SICO/trampa.txt";
    char target2[60] = "/home/horus/Documents/Master/SICO/eBPF_SICO/trampa.txt";

    int i;
    for (i = 0; i < sizeof(target); i++) {
        if (target2[i] != target[i]) {
            return 0; // Las cadenas son diferentes
        }
        if (target2[i] == '\\0') {
            break; // Termina si es el final de la cadena
        }
    }

    events.perf_submit(args, &data, sizeof(data));

    //if(memcmp(data.file, data.file, sizeof(data.file))){ 
        //events.perf_submit(args, &data, sizeof(data));
    //}

    return 0;
}

"""

b = BPF(text=program)

def callback(cpu, data, size):
    event = b["events"].event(data)
    msg = event.file.decode('utf-8', 'ignore')
    uid = event.uid
    
    user_name = pwd.getpwuid(uid).pw_name
    print(f"El usuario {user_name} ejecuto la syscall con id 59 desde: {msg}")

b["events"].open_perf_buffer(callback)

while True:
    b.perf_buffer_poll()

#b.trace_print()

