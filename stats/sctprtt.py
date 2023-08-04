#!/usr/bin/env python

from bcc import BPF
import time
import os
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

bpf_text = """
#include <net/sctp/structs.h>

struct rtt_key_t {
    u64 proto;
    u64 ipaddr[2]; // IPv4: store in laddr[0]
    u64 nsecs;
};

BPF_HASH(rtt_map, struct rtt_key_t, u32);
BPF_ARRAY(g_rtt, u64, 1);

int kprobe__sctp_transport_update_rto(struct pt_regs *ctx, struct sctp_transport *tp, __u32 rtt)
{

    int index = 0;
    u64 *c_rtt = g_rtt.lookup(&index);
    if (!c_rtt || *c_rtt == rtt) {
        return 0;
    }

    struct rtt_key_t key = {.proto = AF_INET, .nsecs = bpf_ktime_get_ns() };

    if (tp->ipaddr.sa.sa_family == AF_INET) {
       key.ipaddr[0] = tp->ipaddr.v4.sin_addr.s_addr;
    }

    *c_rtt = rtt;
    rtt_map.update(&key, &rtt);
    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)

print("Tracing SCTP associations")

rtt_map = b.get_table("rtt_map")

try:
    time.sleep(99999999)
except KeyboardInterrupt:
    print("\n%-32s %-14s %8s" % ("ADDR", "TIME (ns)", "RTT (ms)"))
    for k, v in sorted(rtt_map.items(), key=lambda rtt_map: rtt_map[0].nsecs):
        address = ""
        if k.proto == AF_INET:
            address = inet_ntop(AF_INET, pack("I", k.ipaddr[0]))
        elif  k.proto == AF_INET6:
            address = inet_ntop(AF_INET6, k.ipaddr)
        print("%-32s %-14d %8d" % (address, k.nsecs, v.value))