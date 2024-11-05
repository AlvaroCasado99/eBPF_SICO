#!/usr/bin/python3

from bcc import BPF

program = """
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char target[] = "/home/horus/Documents/Master/SICO/eBPF_SICO/trampa.txt";
    size_t tam = sizeof(target);
    const char* file = args->filename; 
    int equals = 1;

    for(size_t i=0; i<tam; i++){
        if(target[i]=='\\0' && file[i]!='\\0'){
            equals = 0;
            break;
        }

        if(target[i]!='\\0' && file[i]=='\\0'){
            equals = 0;
            break;
        }


        if(target[i] != file[i]){
            equals = 0;
            break;
        }
    }

    char user[] = system()

    if(equals == 1){
        bpf_trace_printk("File opened! File: %s ? %s\\n", file, target);
    }

    return 0;
}
"""


b = BPF(text=program)
b.trace_print()
