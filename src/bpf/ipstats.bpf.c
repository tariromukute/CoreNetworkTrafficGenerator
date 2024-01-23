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

#define GTP_PROTO_UDP_PORT 2152

static __always_inline
__u32 record_stats(struct hdr_cursor *nh, struct statskey *key, __u32 direction, __u32 count)
{
	/* Lookup in kernel BPF-side return pointer to actual data record */
    struct statsrec *rec, data = {0};
    rec = stats_map.lookup(key);
	if (rec == 0) {
        if (direction) {
            data.rx_packets = 1;
            data.rx_bytes = (nh->data_end - nh->data);
            if (key->protocol == IPPROTO_SCTP) {
                data.rx_chunks = count;
            }
        } else {
            data.tx_packets = 1;
            data.tx_bytes = (nh->data_end - nh->data);
            if (key->protocol == IPPROTO_SCTP) {
                data.tx_chunks = count;
            }
        }
        stats_map.update(key, &data);
        return 0;
	}

    if (direction) {
        rec->rx_packets++;
        rec->rx_bytes += (nh->data_end - nh->data);
        if (key->protocol == IPPROTO_SCTP) {
            rec->rx_chunks += count;
        }
    } else {
        rec->tx_packets++;
        rec->tx_bytes += (nh->data_end - nh->data);
        if (key->protocol == IPPROTO_SCTP) {
            rec->tx_chunks += count;
        }
    }

	return 0;
}

static __always_inline
__u32 parse_and_record_packet(struct hdr_cursor *nh, struct statskey *skey, int direction) {
    int ret = 0;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iphdr;
    struct ipv6hdr *ipv6hdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
    struct sctphdr *sctphdr;

    eth_type = parse_ethhdr(nh, nh->data_end, &eth);
	if (eth_type < 0) {
		goto out;
	}

    if (eth_type != bpf_htons(ETH_P_IP) && eth_type != bpf_htons(ETH_P_IPV6)) {
        // Maybe it's a tun device. Reset pointer 
        // TODO: handle other packet formats
        nh->pos = nh->data;
        eth_type = skey->protocol;
    }

    if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(nh, nh->data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(nh, nh->data_end, &ipv6hdr);
	} else {
		goto out;
	}
    
    skey->protocol = (__u32)ip_type;
    switch(ip_type) {
        case IPPROTO_UDP:
            if (parse_udphdr(nh, nh->data_end, &udphdr) < 0) {
                goto out;
            }
            // Check if it's a GTPU packet
            if (udphdr->dest == bpf_htons(GTP_PROTO_UDP_PORT))
                skey->protocol = GTP_PROTO_UDP_PORT;
            record_stats(nh, skey, direction, 1);
            break;
        case IPPROTO_TCP:
            if (parse_tcphdr(nh, nh->data_end, &tcphdr) < 0) {
                goto out;
            }
            record_stats(nh, skey, direction, 1);
            break;
        case IPPROTO_SCTP:
            if (parse_sctphdr(nh, nh->data_end, &sctphdr) < 0) {
                goto out;
            }
            record_stats(nh, skey, direction, 1);
            // TODO: count SCTP packets and bytes

            // TODO: get more insights/stats on SCTP
            break;
        default:
            goto out;
    }

out:
    return ret;
}

#define IS_INGRESS 0x1
// initial handler for each packet on an ingress tc filter
int handle_tc_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
    struct hdr_cursor nh = { .data = data, .data_end = data_end, .pos = data };
    struct statskey skey = { .ifindex = skb->ingress_ifindex, .protocol = skb->protocol, .cpu = bpf_get_smp_processor_id() };

    parse_and_record_packet(&nh, &skey, IS_INGRESS);

    return 1;
}

// initial handler for each packet on an egress tc filter
int handle_tc_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
    struct hdr_cursor nh = { .data = data, .data_end = data_end, .pos = data };
    struct statskey skey = { .ifindex = skb->ifindex, .protocol = skb->protocol, .cpu = bpf_get_smp_processor_id() };

    parse_and_record_packet(&nh, &skey, 0);

    return 1;
}

int xdp_prog(struct xdp_md *ctx) {
    int action = XDP_PASS;
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = { .data = data, .data_end = data_end, .pos = data };
    struct statskey skey = { .ifindex = ctx->ingress_ifindex, .protocol = 0, .cpu = bpf_get_smp_processor_id() };
    __u32 key = 0;

    parse_and_record_packet(&nh, &skey, IS_INGRESS);
    // Access the map for storing the count
    long *value = counts.lookup(&key);
    if (value)
        *value += 1;

    return action;  // Pass the packet to the network stack
}
