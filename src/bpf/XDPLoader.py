from bcc import BPF, libbcc
import ctypes
import time
import socket
from scapy.all import *
from scapy.contrib.gtp import (
        GTP_U_Header,
        GTPPDUSessionContainer)

import ipaddress
import netifaces

GTP_UDP_PORT = 2152


protocol_names = {
    # socket.IPPROTO_TCP: "TCP",
    # socket.IPPROTO_UDP: "UDP",
    # socket.IPPROTO_ICMP: "ICMP",
    # socket.IPPROTO_SCTP: "SCTP",
    GTP_UDP_PORT: 'GTPU',
    # ... Add other protocols as needed
}

include_path = "/home/azureuser/cn-tg" # os.environ['APP_INCLUDE_PATH']

class IpAddress(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("addr", ctypes.c_byte * 16)
    ]

class SupiRecordState(ctypes.Structure):
    _fields_ = [
        ("ip_src", IpAddress),
        ("teid", ctypes.c_uint32),
        ("qfi", ctypes.c_uint32)
    ]

class TrafficgenState(ctypes.Structure):
    _fields_ = [
        ("next_supi", ctypes.c_uint32)
    ]

class TrafficgenConfig(ctypes.Structure):
    _fields_ = [
        ("ifindex_out", ctypes.c_int),
        ("supi_range", ctypes.c_uint32)
    ]

class Trafficgen:
    def __init__(self, ifname: str):
        self.ifname = ifname
        self.ifindex = socket.if_nametoindex(self.ifname)
        self.interfaces_map = self.get_network_interfaces_map()
        self.num_ues = 0
        self.prev = 0
        self.config = None
        self.state = None
        self.state_map = None
        self.config_map = None
        self.b = None
        self.func = None
        self.load()
        self.previous_data = {}

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

    def load(self):
        # Use socket to get the ifindex

        self.b = BPF(src_file=f"{include_path}/src/bpf/xdpgen.bpf.c", cflags=[f"-I{include_path}/src/bpf", "-Wno-macro-redefined"])
        self.func = self.b.load_func("xdp_redirect_update_gtpu", BPF.XDP)

        # TODO: add entries to map supi_record_map, the struct is as follows

        # Initialise
        # Create state
        self.state = TrafficgenState(next_supi=0)
        self.state_map = self.b.get_table("state_map")
        self.state_map[0] = self.state

        self.config = TrafficgenConfig(
            ifindex_out=self.ifindex,
            supi_range=self.num_ues
        )
        self.config_map = self.b.get_table("config_map")
        self.config_map[0] = self.config

    def run(self, packet):
        # Load shared library

        lib = ctypes.CDLL(f"{include_path}/src/bpf/libxdpgen.so")

        # Define argument types for xdp_gen function
        lib.xdp_gen.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]

        c_packet = ctypes.create_string_buffer(raw(packet), len(packet))

        num_pkts = 1 << 20
        err = lib.xdp_gen(self.func.fd, num_pkts, c_packet, len(c_packet))
        if err != 0:
            print("Failed to call xdp_gen function")

    def add_ue_record(self, ip_address_str: str, teid: int, qfi: int) -> None:
        """ This function adds a new user equipment (UE) record to the specified supi_record_map iterated through when generating 
        PDU session traffic. The UE record is identified by its IP address, teid and qfi values. """

        supi_record_map = self.b.get_table("supi_record_map")

        ip_address_bytes = ipaddress.ip_address(ip_address_str).packed

        ip_version = 4 if len(ip_address_bytes) == 4 else 6
        # create an instance of the struct and populate its value
        state = SupiRecordState(
            ip_src=IpAddress(
                version=ip_version,
                addr=(ctypes.c_byte * 16).from_buffer_copy(ip_address_bytes + bytes([0] * 12)) if ip_version == 4 else (ctypes.c_byte * 16).from_buffer_copy(ip_address_bytes)
            ),
            teid=teid,
            qfi=qfi
        )
        # insert the struct into the hash table
        supi_record_map[self.num_ues] = state
        self.num_ues += 1

        # Create configs
        self.config = TrafficgenConfig(
            ifindex_out=self.ifindex,
            supi_range=self.num_ues
        )
        self.config_map[0] = self.config

    def get_stats(self):
        stats = []
        # Retrieve and process statistics
        grouped_data = collections.defaultdict(lambda: {"rx_bytes": 0, "rx_packets": 0})
        stats_map = self.b.get_table("stats_map")  # Assuming `b` is defined elsewhere
        for key, value in stats_map.items():
            grouped_data[(key.ifindex, key.protocol)]["rx_bytes"] += value.rx_bytes
            grouped_data[(key.ifindex, key.protocol)]["rx_packets"] += value.rx_packets

        for proto, p_name in protocol_names.items():
            row_data = [
                f"{delta_packets:>10}{delta_bytes / 1024:>10.0f}"
                for if_index in sorted(self.interfaces_map.keys())
                for delta_packets, delta_bytes in [
                    (
                        grouped_data.get((if_index, proto), {}).get("rx_packets", 0)
                        - self.previous_data.get((if_index, proto), {}).get("rx_packets", 0),
                        grouped_data.get((if_index, proto), {}).get("rx_bytes", 0)
                        - self.previous_data.get((if_index, proto), {}).get("rx_bytes", 0),
                    )
                ]
            ]
            stats.append(f"{p_name:<6} | {' '.join(row_data)}")

        self.previous_data = grouped_data
        return stats

    def print_stats(self):
        pkt_s = "pkts/s"
        bytes_s = "kb/s"
        print(f"{'':<6} | {' '.join(f'{self.interfaces_map[if_index]:^20}' for if_index in sorted(self.interfaces_map))}") # Headers
        print(f"{'':<6} | {' '.join(f'{pkt_s:>10}{bytes_s:>10}' for _ in sorted(self.interfaces_map))}") # Subheaders

        while True:
            try:
                # Retrieve and process statistics
                grouped_data = collections.defaultdict(lambda: {"rx_bytes": 0, "rx_packets": 0})
                stats_map = self.b.get_table("stats_map")  # Assuming `b` is defined elsewhere
                for key, value in stats_map.items():
                    grouped_data[(key.ifindex, key.protocol)]["rx_bytes"] += value.rx_bytes
                    grouped_data[(key.ifindex, key.protocol)]["rx_packets"] += value.rx_packets

                # Print data for each protocol
                for proto, p_name in protocol_names.items():
                    row_data = [
                        f"{delta_packets:>10}{delta_bytes / 1024:>10.0f}"
                        for if_index in sorted(self.interfaces_map.keys())
                        for delta_packets, delta_bytes in [
                            (
                                grouped_data.get((if_index, proto), {}).get("rx_packets", 0)
                                - self.previous_data.get((if_index, proto), {}).get("rx_packets", 0),
                                grouped_data.get((if_index, proto), {}).get("rx_bytes", 0)
                                - self.previous_data.get((if_index, proto), {}).get("rx_bytes", 0),
                            )
                        ]
                    ]
                    print(f"{p_name:<6} | {' '.join(row_data)}")

                print()  # Add spacing between iterations
                self.previous_data = grouped_data
                time.sleep(1)

            except Exception as e:
                print(f"Error reading map: {e}")

            except KeyboardInterrupt:
                break  # Exit gracefully on Ctrl+C
        self.b.remove_xdp(self.ifname, 0)
