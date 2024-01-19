#include "common.h"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sctp.h>

struct statskey {
    __u32 ifindex;
    __u32 protocol;
    __u32 cpu; /* Getting error when loading BPF_PERCPU_HASH which we need for atomic operations. 
    Added cpu to make the operations atomic */
    // TODO: migrate to BPF_PERCPU_HASH 
};


struct statsrec {
	__u64 rx_packets;
	__u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 rx_chunks; // For SCTP stats only
    __u64 tx_chunks;
};

BPF_PERCPU_ARRAY(counts, long, 1);
BPF_HASH(stats_map, struct statskey, struct statsrec);
// BPF_PERCPU_HASH(stats_map, struct statskey, struct statsrec, 10);

static __always_inline
__u32 record_stats(struct xdp_md *ctx, struct statskey *key, __u32 count)
{
	/* Lookup in kernel BPF-side return pointer to actual data record */
	
    struct statsrec *rec, data = {0};
    rec = stats_map.lookup(key);
	if (rec == 0) {
        data.rx_packets = 1;
        data.rx_bytes = (ctx->data_end - ctx->data);
        if (key->protocol == IPPROTO_SCTP) {
            data.rx_chunks = count;
        }
        stats_map.update(key, &data);
        return 0;
	}

	rec->rx_packets++;
	rec->rx_bytes += (ctx->data_end - ctx->data);
    if (key->protocol == IPPROTO_SCTP) {
        rec->rx_chunks += count;
    }

	return 0;
}

int xdp_prog(struct xdp_md *ctx) {
    int action = XDP_PASS;
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iphdr;
    struct ipv6hdr *ipv6hdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
    struct sctphdr *sctphdr;
    struct hdr_cursor nh = { .pos = data, .data_end = data_end };
    struct statskey skey = { .ifindex = ctx->ingress_ifindex, .protocol = 0, .cpu = bpf_get_smp_processor_id() };
    __u32 key = 0;

    eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

    if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}
    
    skey.protocol = (__u32)ip_type;
    switch(ip_type) {
        case IPPROTO_UDP:
            if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
                action = XDP_ABORTED;
                goto out;
            }
            record_stats(ctx, &skey, 1);
            break;
        case IPPROTO_TCP:
            if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
                action = XDP_ABORTED;
                goto out;
            }
            record_stats(ctx, &skey, 1);
            break;
        case IPPROTO_SCTP:
            if (parse_sctphdr(&nh, data_end, &sctphdr) < 0) {
                action = XDP_ABORTED;
                goto out;
            }
            record_stats(ctx, &skey, 1);
            // TODO: count SCTP packets and bytes

            // TODO: get more insights/stats on SCTP
            break;
        default:
            goto out;
    }

    // Access the map for storing the count
    long *value = counts.lookup(&key);
    if (value)
        *value += 1;
    bpf_trace_printk("G 7");
out:
    return action;  // Pass the packet to the network stack
}
