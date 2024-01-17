#include "utils.h"
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>

// const volatile struct trafficgen_config config;
BPF_ARRAY(config_map, struct trafficgen_config, 1);
BPF_ARRAY(state_map, struct trafficgen_state, 1);
BPF_ARRAY(supi_record_map, struct supi_record_state, 100);
BPF_PERCPU_ARRAY(txcnt, long, 1);

int xdp_redirect_update_gtpu(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	int action = XDP_ABORTED;
	struct trafficgen_state *state;
	struct trafficgen_config *config;
	struct gtpuhdr *ghdr;
	struct gtp_pdu_session_container *pdu;
	struct ethhdr *eth_header;
    struct ipv6hdr *ipv6_header;
    struct iphdr *ip_header;
	__u32 key = 0;

	__u32 cpu_id = bpf_get_smp_processor_id();
    config = config_map.lookup(&key);
	if (!config) {
		goto out;
	}

    if (config->supi_range == 0) {
        // No UE records have been added
        goto out;
    }
    
    struct ethhdr *eth = data;
	if ((void*)&eth[1] > data_end) {
        goto out;
    }


	/* Check for IPv4 or IPv6 */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = data + sizeof(*eth);
		if ((void*)&iph[1] > data_end) {
			goto out;
		}
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = data + sizeof(*eth);
		if ((void*)&ip6h[1] > data_end) {
			goto out;
		}
    } else {
        goto out;
    }

	// bpf_trace_printk("Program called");
	// Determine IP version using Ethernet frame type field
    eth_header = data;
    if ((void*)&eth_header[1] > data_end) {
        goto out;
    }

	if (eth_header->h_proto == bpf_htons(ETH_P_IP)) {
		ghdr = data + (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
    } else if (eth_header->h_proto == bpf_htons(ETH_P_IPV6)) {
		ghdr = data + (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr));
    } else {
        goto out; // Not an IP packet, don't process it.
    }

	if ((void*)&ghdr[1] > data_end) {
		goto out;
	}

	ip_header = (void *) ghdr + ( (sizeof(struct gtpuhdr) + sizeof(struct gtpu_hdr_ext) + sizeof(struct gtp_pdu_session_container)) );
	if ((void*)&ip_header[1] > data_end) {
		goto out;
	}

	pdu = (struct gtp_pdu_session_container *)((void *)ghdr + sizeof(struct gtpuhdr) + sizeof(struct gtpu_hdr_ext));
    if ((void*)&pdu[1] > data_end) {
		goto out;
	}

	state = state_map.lookup(&key);
	if (!state) {
		goto out;
	}

	struct supi_record_state *tstate = supi_record_map.lookup(&state->next_supi);
	if (!tstate) {
		goto out;
	}

	// Update teid on gtpuhdr
    ghdr->teid = bpf_htonl(tstate->teid);
	
	// Update qfi on gtp_pdu_session_container
    pdu->qfi = (__u8)tstate->qfi;

	// Determine IP header version and Update inner IP header
	if (ip_header->version != tstate->ip_src.version) {
		goto out;
	}
	if (ip_header->version == 4) {
		__builtin_memcpy(&ip_header->saddr, &tstate->ip_src.addr, sizeof(struct in_addr));
	} 
	else if (ip_header->version == 6) {
		ipv6_header = (struct ipv6hdr *) ip_header;
		if ((void*)&ipv6_header[1] > data_end) {
			goto out;
		}
		__builtin_memcpy(&ipv6_header->saddr, &tstate->ip_src.addr, sizeof(struct in6_addr));
	}

	// Advance next supi key
	if (state->next_supi++ >= config->supi_range - 1)
		state->next_supi = 0;
	action = bpf_redirect(config->ifindex_out, 0);
	long *value = txcnt.lookup(&key);
    if (value)
        *value += 1;
out:
	return action;

}