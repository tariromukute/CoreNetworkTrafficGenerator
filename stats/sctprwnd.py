#!/usr/bin/env python

from bcc import BPF

bpf_text = """
#include <net/sctp/structs.h>
#define MAX_ENTRIES 1024

struct key_t {
    u64 peer_port;
    u64 nsecs;
};

BPF_HASH(rwnd_map, struct key_t, u32);
BPF_ARRAY(g_rwnd, u64, 1);

TRACEPOINT_PROBE(sctp, sctp_probe)
{
    int index = 0;
    u64 *c_rwnd = g_rwnd.lookup(&index);
    if (!c_rwnd || *c_rwnd == args->rwnd) {
        return 0;
    }

    u32 rwnd;
    struct key_t key = {.peer_port = args->peer_port, .nsecs = bpf_ktime_get_ns() };
    rwnd = args->rwnd;

    *c_rwnd = rwnd;
    rwnd_map.update(&key, &rwnd);
    return 0;
}
"""

# load BPF program
b = BPF(text=bpf_text)

print("Tracing SCTP associations")

rwnd_map = b.get_table("rwnd_map")

# try:
#     sleep(99999999)
# except KeyboardInterrupt:
#     for k, v in sorted(rwnd_map.items(), key=lambda rwnd_map: rwnd_map[0].nsecs):
#         print("%d %d %8d" % (k.peer_port, k.nsecs, v.value))