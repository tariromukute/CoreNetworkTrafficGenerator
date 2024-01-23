// clang -shared xdpgen.c -o xdpgen.so -lbpf
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <net/if.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
// #include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <arpa/inet.h>

#ifndef BPF_F_TEST_XDP_LIVE_FRAMES
#define BPF_F_TEST_XDP_LIVE_FRAMES	(1U << 1)
#endif

static bool status_exited = false;

void print_packet(const unsigned char *packet, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n"); // separate lines every 16 bytes
        }
    }
    printf("\n");
}

// Create function that takes the xdp_prog_fd, the packet data, ifindex
int xdp_gen(int xdp_prog_fd, int num_pkts, char *pkt, int size)
{
    // print_packet((unsigned char *)pkt, size);
    char data[size + sizeof(__u32)];
    int err;
    struct xdp_md ctx_in = { .data = sizeof(__u32),
                 .data_end = sizeof(data) };
    DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
                .data_in = &data,
                .data_size_in = sizeof(data),
                .ctx_in = &ctx_in,
                .ctx_size_in = sizeof(ctx_in),
                .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
                .repeat = num_pkts
    );

    memcpy(&data[sizeof(__u32)], pkt, size);

    err = bpf_prog_test_run_opts(xdp_prog_fd, &opts);
    if (err) {
        err = -errno;
        printf("Failed to load test program %s\n", strerror(-err));
        return -1;
    }

    return 0;
}
