#include "include/bpf_map.h"
#include "include/bpf.h"
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps/test") map_test = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 512,
    .map_flags = BPF_F_NO_PREALLOC,
    .pinning = PIN_NONE,
    .namespace = "",
};

SEC("kprobe/security_sk_classify_flow")
int kprobe__security_sk_classify_flow(void *ctx)
{
    int key = 1;
    int value = 2;
    bpf_map_update_elem(&map_test, &key, &value, BPF_ANY);
    char format[] = "map value updated!\n";
    bpf_trace_printk(format, sizeof(format));
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
