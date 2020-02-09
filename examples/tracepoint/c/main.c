#include "include/bpf_map.h"
#include "include/bpf.h"
#include "bpf_helpers.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx)
{
    char a[] = "hello!\n";
    bpf_trace_printk(a, sizeof(a));
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
