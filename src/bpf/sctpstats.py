from bcc import BPF
import socket
import time
import netifaces

XDP_FLAGS_UPDATE_IF_NOEXIST = (1 << 0)
XDP_FLAGS_SKB_MODE = (1 << 1)
XDP_FLAGS_DRV_MODE = (1 << 2)
XDP_FLAGS_HW_MODE = (1 << 3)
XDP_FLAGS_REPLACE = (1 << 4)

GTP_UDP_PORT = 2152

include_path = "/home/azureuser/cn-tg"

def get_network_interfaces_map():
    interface_map = {}

    interfaces = netifaces.interfaces()  # Get interface names using netifaces

    for interface_name in interfaces:
        try:
            if_index = socket.if_nametoindex(interface_name)
            interface_map[if_index] = interface_name
        except OSError:
            print(f"Error retrieving if_index for interface: {interface_name}")

    return interface_map

interfaces_map = get_network_interfaces_map()
# Load the XDP program (replace with the path to your compiled program)
b = BPF(src_file="sctpstats.bpf.c", cflags=[f"-I{include_path}/src/bpf", "-Wno-macro-redefined"])
b.attach_xdp("eth2", b.load_func("xdp_prog", BPF.XDP), XDP_FLAGS_SKB_MODE)
# Attach the XDP program all the interfaces
for ifname in interfaces_map.values():
    try: 
        b.attach_xdp(ifname, b.load_func("xdp_prog", BPF.XDP), XDP_FLAGS_SKB_MODE)
    except Exception as e:
        print(f"Failed to attach XDP program on {ifname}: {e}")

# b.attach_xdp("lo", b.load_func("xdp_prog", BPF.XDP), XDP_FLAGS_SKB_MODE)
import collections
import socket
protocol_names = {
    socket.IPPROTO_TCP: "TCP",
    socket.IPPROTO_UDP: "UDP",
    socket.IPPROTO_ICMP: "ICMP",
    socket.IPPROTO_SCTP: "SCTP",  # Add SCTP to the mapping
    GTP_UDP_PORT: 'GTPU',
    # ... Add other protocols as needed
}

pkt_s = "pkts/s"
bytes_s = "kb/s"
print(f"{'':<6} | {' '.join(f'{interfaces_map[if_index]:^20}' for if_index in sorted(interfaces_map))}") # Headers
print(f"{'':<6} | {' '.join(f'{pkt_s:>10}{bytes_s:>10}' for _ in sorted(interfaces_map))}") # Subheaders

previous_data = {}  # Store previous results for delta calculations

while True:
    try:
        # Retrieve and process statistics
        grouped_data = collections.defaultdict(lambda: {"rx_bytes": 0, "rx_packets": 0})
        stats_map = b.get_table("stats_map")  # Assuming `b` is defined elsewhere
        for key, value in stats_map.items():
            grouped_data[(key.ifindex, key.protocol)]["rx_bytes"] += value.rx_bytes
            grouped_data[(key.ifindex, key.protocol)]["rx_packets"] += value.rx_packets

        # Print data for each protocol
        for proto, p_name in protocol_names.items():
            row_data = [
                f"{delta_packets:>10}{delta_bytes:>10}"
                for if_index in sorted(interfaces_map.keys())
                for delta_packets, delta_bytes in [
                    (
                        grouped_data.get((if_index, proto), {}).get("rx_packets", 0)
                        - previous_data.get((if_index, proto), {}).get("rx_packets", 0),
                        grouped_data.get((if_index, proto), {}).get("rx_bytes", 0)
                        - previous_data.get((if_index, proto), {}).get("rx_bytes", 0),
                    )
                ]
            ]
            print(f"{p_name:<6} | {' '.join(row_data)}")

        print()  # Add spacing between iterations
        previous_data = grouped_data
        time.sleep(1)

    except Exception as e:
        print(f"Error reading map: {e}")

    except KeyboardInterrupt:
        break  # Exit gracefully on Ctrl+C


# Detach the XDP program when exiting
for ifname in interfaces_map.values():
    try:
        b.remove_xdp(ifname, XDP_FLAGS_SKB_MODE)
    except Exception as e:
        print(f"Failed to detach XDP program on {ifname}: {e}")
# b.remove_xdp("eth2", XDP_FLAGS_SKB_MODE)