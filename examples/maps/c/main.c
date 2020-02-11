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

struct bpf_map_def SEC("maps") routing_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = 24,
    .value_size = sizeof(uint64_t),
    .max_entries = 10000,
    .map_flags = BPF_F_NO_PREALLOC,
};

SEC("kprobe/security_sk_classify_flow")
int kprobe__security_sk_classify_flow(void *ctx)
{
    uint64_t value_1 = 1;
    struct bpf_lpm_trie_key route_1 = {.data = {192, 168, 0, 0}, .prefixlen = 16};
    uint64_t value_3 = 3;
    struct bpf_lpm_trie_key route_3 = {.data = {192, 168, 1, 0}, .prefixlen = 24};

    struct bpf_lpm_trie_key key4 = {.data = {192, 168, 0, 13}, .prefixlen = 32};

    bpf_map_update_elem(&routing_map, &route_1, &value_1, BPF_ANY);
    bpf_map_update_elem(&routing_map, &route_3, &value_3, BPF_ANY);

    u64 *prefix_value = bpf_map_lookup_elem(&routing_map, &key4);
    if (prefix_value != NULL)
    {
        char fo[] = "map value: %d\n";
        bpf_trace_printk(fo, sizeof(fo), *prefix_value);
    }
    else
    {
        char fo[] = "nop\n";
        bpf_trace_printk(fo, sizeof(fo));
    }

    int key = 1;
    int value = 2;
    bpf_map_update_elem(&map_test, &key, &value, BPF_ANY);
    // char format[] = "map value updated!\n";
    // bpf_trace_printk(format, sizeof(format));
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
