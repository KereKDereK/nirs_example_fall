from bcc import BPF
BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Process detected!\\n"); return 0; }').trace_print()
