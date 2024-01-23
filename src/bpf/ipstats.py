from bcc import BPF
import socket
import time
import netifaces
import collections
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen

include_path = "/home/azureuser/cn-tg"

XDP_FLAGS_UPDATE_IF_NOEXIST = (1 << 0)
XDP_FLAGS_SKB_MODE = (1 << 1)
XDP_FLAGS_DRV_MODE = (1 << 2)
XDP_FLAGS_HW_MODE = (1 << 3)
XDP_FLAGS_REPLACE = (1 << 4)
GTP_UDP_PORT = 2152

protocol_names = {
    socket.IPPROTO_TCP: "TCP",
    socket.IPPROTO_UDP: "UDP",
    socket.IPPROTO_ICMP: "ICMP",
    socket.IPPROTO_SCTP: "SCTP",
    GTP_UDP_PORT: 'GTPU',
    # ... Add other protocols as needed
}
class IPStats:
    
    def __init__(self):
        self.previous_data = {}
        self.interfaces_map = self.get_network_interfaces_map()
        self.b = None

        self.load()
        
    @staticmethod
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
    
    def run(self):
        pkt_s = "pkts/s"
        bytes_s = "kb/s"

        while True:
            try:
                print(f"{'':<8} | {' '.join(f'{self.interfaces_map[if_index]:^20}' for if_index in sorted(self.interfaces_map))}") # Headers
                print(f"{'':<8} | {' '.join(f'{pkt_s:>10}{bytes_s:>10}' for _ in sorted(self.interfaces_map))}") # Subheaders
                grouped_data = collections.defaultdict(
                    lambda: {"rx_bytes": 0, "rx_packets": 0, "tx_bytes": 0, "tx_packets": 0}
                )
                stats_map = self.b.get_table("stats_map")
                for key, value in stats_map.items():
                    group = grouped_data[(key.ifindex, key.protocol)]
                    for field in ("rx_bytes", "rx_packets", "tx_bytes", "tx_packets"):
                        group[field] += getattr(value, field)  # Dynamically access fields

                for proto, p_name in protocol_names.items():
                    for direction, label in ("rx", "rx"), ("tx", "tx"):
                        row_data = [
                            f"{delta_packets:>10}{delta_bytes:>10}"
                            for if_index in sorted(self.interfaces_map.keys())
                            for delta_packets, delta_bytes in [
                                (
                                    grouped_data.get((if_index, proto), {}).get(f"{direction}_packets", 0)
                                    - self.previous_data.get((if_index, proto), {}).get(f"{direction}_packets", 0),
                                    grouped_data.get((if_index, proto), {}).get(f"{direction}_bytes", 0)
                                    - self.previous_data.get((if_index, proto), {}).get(f"{direction}_bytes", 0),
                                )
                            ]
                        ]
                        # stats.append(f"{p_name} {label} | {' '.join(row_data)}")
                        print(f"{p_name:<6} {label:<2} | {' '.join(row_data)}")

                print()  # Add spacing between iterations
                self.previous_data = grouped_data
                time.sleep(1)

            except Exception as e:
                print(f"Error reading map: {e}")

            except KeyboardInterrupt:
                break  # Exit gracefully on Ctrl+C

        for if_index in self.interfaces_map.keys():
            self.clean(if_index)
                
    def get_stats(self):
        # Retrieve and process statistics
        grouped_data = collections.defaultdict(
            lambda: {"rx_bytes": 0, "rx_packets": 0, "tx_bytes": 0, "tx_packets": 0}
        )
        stats_map = self.b.get_table("stats_map")

        for key, value in stats_map.items():
            group = grouped_data[(key.ifindex, key.protocol)]
            for field in ("rx_bytes", "rx_packets", "tx_bytes", "tx_packets"):
                group[field] += getattr(value, field)  # Dynamically access fields

        return grouped_data
        
    def load(self):
        ipr = IPRoute()

        self.b = BPF(src_file=f"{include_path}/src/bpf/ipstats.bpf.c", cflags=[f"-I{include_path}/src/bpf", "-Wno-macro-redefined"])
        
        ingress_fn = self.b.load_func("handle_tc_ingress", BPF.SCHED_CLS)
        egress_fn = self.b.load_func("handle_tc_egress", BPF.SCHED_CLS)
        
        # Attach the XDP program to all the interfaces
        for if_index in self.interfaces_map.keys():
            try: 
                # Try cleaning first
                try:
                    self.clean(if_index)
                except Exception as e:
                    pass

                ipr.tc("add", "ingress", if_index, "ffff:")
                ipr.tc("add-filter", "bpf", if_index, ":1", fd=ingress_fn.fd,
                    name=ingress_fn.name, parent="ffff:", action="ok", classid=1)
                
                ipr.tc("add", "sfq", if_index, "1:")
                ipr.tc("add-filter", "bpf", if_index, ":1", fd=egress_fn.fd,
                    name=egress_fn.name, parent="1:", action="ok", classid=1)
            except Exception as e:
                print(f"Failed to attach XDP program on (if index) {if_index}: {e}")
                raise e
        self.previous_data = {}  # Store previous results for delta calculations

    def clean(self, if_index):
        ipr = IPRoute()
        ipr.tc('del', 'ingress', if_index, 'ffff:')
        ipr.tc('del', 'sfq', if_index, '1:')

    def detach(self):
        # Detach the XDP program when exiting
        for ifname in self.interfaces_map.values():
            try:
                self.b.remove_xdp(ifname, XDP_FLAGS_SKB_MODE)
            except Exception as e:
                print(f"Failed to detach XDP program on {ifname}: {e}")
        self.b = None

# ipstats = IPStats()
# # ipstats.load()
# ipstats.run()