// +build ignore

// TC-BPF program attached to clsact ingress+egress. Parses Eth+IPv4+{TCP,UDP},
// applies the filter spec, and copies matched frames into a ringbuf for
// userspace to forward. Returns TC_ACT_UNSPEC so packets continue through the
// kernel stack normally.
//
// We intentionally use stock Linux uapi headers (linux/*.h) + libbpf helpers
// instead of vmlinux.h. Every field we touch is in a stable skb/IP/UDP layout,
// so we don't need CO-RE. This keeps the build hermetic across kernels and
// avoids having to ship or generate a per-arch vmlinux.h.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define METADATA_IP bpf_htonl(0xa9fea9fe) // 169.254.169.254
#define DNS_PORT    bpf_htons(53)
#define VXLAN_PORT  bpf_htons(4789)
#define VXLAN_SRC   bpf_htons(16401)

#define MAX_CAPTURE 1536 // >= standard 1500-byte MTU frames

struct capture_event {
    __u32 len;
    __u32 ifindex;
    __u8  ingress;
    __u8  _pad[3];
    __u8  data[MAX_CAPTURE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 8);
} drop_counters SEC(".maps");

enum {
    DROP_NON_IPV4 = 0,
    DROP_METADATA = 1,
    DROP_NON_L4   = 2,
    DROP_DNS      = 3,
    DROP_VXLAN    = 4,
    DROP_TRUNC    = 5,
    DROP_RB_FULL  = 6,
};

static __always_inline void bump_drop(__u32 reason)
{
    __u64 *c = bpf_map_lookup_elem(&drop_counters, &reason);
    if (c)
        __sync_fetch_and_add(c, 1);
}

static __always_inline int handle(struct __sk_buff *skb, __u8 ingress)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        bump_drop(DROP_NON_IPV4);
        return TC_ACT_UNSPEC;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_UNSPEC;

    if (iph->daddr == METADATA_IP) {
        bump_drop(DROP_METADATA);
        return TC_ACT_UNSPEC;
    }

    __u32 ihl = iph->ihl * 4;
    if (ihl < sizeof(*iph))
        return TC_ACT_UNSPEC;

    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
        bump_drop(DROP_NON_L4);
        return TC_ACT_UNSPEC;
    }

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + ihl;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_UNSPEC;
        if (udp->source == DNS_PORT || udp->dest == DNS_PORT) {
            bump_drop(DROP_DNS);
            return TC_ACT_UNSPEC;
        }
        if (udp->source == VXLAN_SRC || udp->dest == VXLAN_PORT) {
            bump_drop(DROP_VXLAN);
            return TC_ACT_UNSPEC;
        }
    }

    __u32 wire_len = skb->len;
    __u32 copy_len = wire_len > MAX_CAPTURE ? MAX_CAPTURE : wire_len;

    // The verifier on kernels ≥ 6.x rejects bpf_skb_load_bytes() with a
    // len arg whose value range includes 0 (R4 invalid zero-sized read).
    // skb->len is bounded at [0, 0xffff] from the verifier's view, so we
    // must prove copy_len > 0 before the load.
    if (copy_len == 0)
        return TC_ACT_UNSPEC;

    struct capture_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump_drop(DROP_RB_FULL);
        return TC_ACT_UNSPEC;
    }
    e->len     = wire_len;
    e->ifindex = skb->ifindex;
    e->ingress = ingress;
    e->_pad[0] = e->_pad[1] = e->_pad[2] = 0;

    if (bpf_skb_load_bytes(skb, 0, e->data, copy_len) < 0) {
        bump_drop(DROP_TRUNC);
        bpf_ringbuf_discard(e, 0);
        return TC_ACT_UNSPEC;
    }
    bpf_ringbuf_submit(e, 0);
    return TC_ACT_UNSPEC;
}

SEC("tc/ingress")
int sensor_ingress(struct __sk_buff *skb) { return handle(skb, 1); }

SEC("tc/egress")
int sensor_egress(struct __sk_buff *skb)  { return handle(skb, 0); }
