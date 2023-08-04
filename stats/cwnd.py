#!/usr/bin/env python

from bcc import BPF
import time
import os
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

bpf_text = """
#include <net/sctp/structs.h>
#define MAX_ENTRIES 1024

struct cwnd_key_t {
    u64 proto;    // familiy << 16 | type
    u64 ipaddr[2]; // IPv4: store in laddr[0]
    u64 nsecs;
};

BPF_HASH(cwnd_map, struct cwnd_key_t, u32);
BPF_ARRAY(g_cwnd, u64, 1);

TRACEPOINT_PROBE(sctp, sctp_probe_path)
{
    int index = 0;
    u64 *c_cwnd = g_cwnd.lookup(&index);
    if (!c_cwnd || *c_cwnd == args->cwnd) {
        return 0;
    }

    u32 cwnd;
    struct cwnd_key_t key = {.proto = AF_INET, .nsecs = bpf_ktime_get_ns() };
    cwnd = args->cwnd;

    union sctp_addr * addr = (union sctp_addr *)args->ipaddr;

    if (addr->sa.sa_family == AF_INET) {
       key.ipaddr[0] = addr->v4.sin_addr.s_addr;
    }

    *c_cwnd = cwnd;
    cwnd_map.update(&key, &cwnd);
    return 0;
}
"""

# load BPF program
b = BPF(text=bpf_text)

print("Tracing SCTP associations")

cwnd_map = b.get_table("cwnd_map")

try:
    time.sleep(99999999)
except KeyboardInterrupt:
    print("\n%-32s %-14s %8s" % ("ADDR", "TIME (ns)", "CWND(bytes)"))
    for k, v in sorted(cwnd_map.items(), key=lambda cwnd_map: cwnd_map[0].nsecs):
        address = ""
        if k.proto == AF_INET:
            address = inet_ntop(AF_INET, pack("I", k.ipaddr[0]))
        elif  k.proto == AF_INET6:
            address = inet_ntop(AF_INET6, k.ipaddr)
        print("%-32s %-14d %8d" % (address, k.nsecs, v.value))