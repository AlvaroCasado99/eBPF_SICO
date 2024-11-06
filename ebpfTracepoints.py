#!/bin/bash
from bcc import BPF

program = """
    TRACEPOINT_PROBE(syscalls, sys_enter_openat){
        bpf_trace_printk("Abenrto archivo: %s\\n", args->filename);
        return 0;
    }
"""

b = BPF(text=program)
b.trace_print()
