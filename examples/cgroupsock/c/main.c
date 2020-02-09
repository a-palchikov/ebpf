#include "include/bpf_map.h"
#include "include/bpf.h"
#include "bpf_helpers.h"

SEC("cgroup/sock/sock")
int cgroup_sock_func(struct bpf_sock *sk)
{
    char a[] = "cgroup/sock/sock!\n";
    bpf_trace_printk(a, sizeof(a));
    return 1;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
