#!/usr/bin/env python

from bcc import BPF
import time
import os
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

bpf_text = """
#include <net/sctp/structs.h>
#define MAX_ENTRIES 1024

// Define keys for the maps
KEY

// Define maps for storage
STORE

PROGRAM
"""

key_str = ""
store_str = ""
program_str = ""

# Define program for SCTP rwnd stats
rwnd_key_text = """
struct rwnd_key_t {
    u64 peer_port;
    u64 nsecs;
};
"""

rwnd_store_text = """
BPF_HASH(rwnd_map, struct rwnd_key_t, u32);
BPF_ARRAY(g_rwnd, u64, 1);
"""

rwnd_program_text = """
TRACEPOINT_PROBE(sctp, sctp_probe)
{
    int index = 0;
    u64 *c_rwnd = g_rwnd.lookup(&index);
    if (!c_rwnd || *c_rwnd == args->rwnd) {
        return 0;
    }

    u32 rwnd;
    struct rwnd_key_t key = {.peer_port = args->peer_port, .nsecs = bpf_ktime_get_ns() };
    rwnd = args->rwnd;

    *c_rwnd = rwnd;
    rwnd_map.update(&key, &rwnd);
    return 0;
}
"""

key_str += rwnd_key_text
store_str += rwnd_store_text
program_str += rwnd_program_text

# Define program for SCTP cwnd stats
cwnd_key_text = """
struct cwnd_key_t {
    u64 proto;
    u64 ipaddr[2]; // IPv4: store in laddr[0]
    u64 nsecs;
};
"""

cwnd_store_text = """
BPF_HASH(cwnd_map, struct cwnd_key_t, u32);
BPF_ARRAY(g_cwnd, u64, 1);
"""

cwnd_program_text = """
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

key_str += cwnd_key_text
store_str += cwnd_store_text
program_str += cwnd_program_text

# Replace 
bpf_text = bpf_text.replace("KEY", key_str)
bpf_text = bpf_text.replace("STORE", store_str)
bpf_text = bpf_text.replace("PROGRAM", program_str)

# load BPF program
b = BPF(text=bpf_text)

print("Tracing SCTP associations")

rwnd_map = b.get_table("rwnd_map")

cwnd_map = b.get_table("cwnd_map")

# try:
#     time.sleep(99999999)
# except KeyboardInterrupt:
#     print("\n%-16s %-14s %8s" % ("PEER PORT", "TIME (ns)", "RWND(bytes)"))
#     for k, v in sorted(rwnd_map.items(), key=lambda rwnd_map: rwnd_map[0].nsecs):
#         print("%-16d %-14d %8d" % (k.peer_port, k.nsecs, v.value))

#     print("\n%-32s %-14s %8s" % ("ADDR", "TIME (ns)", "CWND(bytes)"))
#     for k, v in sorted(cwnd_map.items(), key=lambda cwnd_map: cwnd_map[0].nsecs):
#         address = ""
#         if k.proto == AF_INET:
#             address = inet_ntop(AF_INET, pack("I", k.ipaddr[0]))
#         elif  k.proto == AF_INET6:
#             address = inet_ntop(AF_INET6, k.ipaddr)
#         print("%-32s %-14d %8d" % (address, k.nsecs, v.value))