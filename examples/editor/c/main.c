#include "include/bpf_map.h"
#include "include/bpf.h"
#include "bpf_helpers.h"

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx)
{
    int my_constant = 0;
    LOAD_CONSTANT("my_constant_sym", my_constant);
    char fmt[] = "my_constant is: %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), my_constant);
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
