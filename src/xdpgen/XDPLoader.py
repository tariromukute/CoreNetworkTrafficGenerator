from bcc import BPF, libbcc
import ctypes
import time
import socket
from scapy.all import *
from scapy.contrib.gtp import (
        GTP_U_Header,
        GTPPDUSessionContainer)

import ipaddress

import socket
import os

include_path = "/home/azureuser/cn-tg" # os.environ['APP_INCLUDE_PATH']

num_ues = 0

ethernet = Ether(dst="60:45:bd:43:3a:17", src="00:22:48:13:95:78")
outerIp = IP(src="10.0.3.4", dst="10.0.3.5")
outerUdp = UDP(sport=2152, dport=2152,chksum=0)
innerIp = IP(src="10.1.1.4", dst="10.50.100.1")
icmpPkt = ICMP()
innerUdp = UDP(sport=12345, dport=54321)
gtpHeader = GTP_U_Header(teid=0, next_ex=133)/GTPPDUSessionContainer(type=1, QFI=9)
payload = "This is a test message"

packet = ethernet/outerIp/outerUdp/gtpHeader/innerIp/innerUdp/payload

sendingPacket = ctypes.create_string_buffer(raw(packet), len(packet))

# Replace "eth0" with the name of your interface
ifname = "eth2"

# Use socket to get the ifindex
ifindex = socket.if_nametoindex(ifname)

b = BPF(src_file=f"{include_path}/src/xdpgen/xdpgen.bpf.c", cflags=[f"-I{include_path}/src/xdpgen", "-Wno-macro-redefined"])
func = b.load_func("xdp_redirect_update_gtpu", BPF.XDP)

# TODO: add entries to map supi_record_map, the struct is as follows
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

# Initialise
# Create state
state = TrafficgenState(next_supi=0)
state_map = b.get_table("state_map")
state_map[0] = state

config = TrafficgenConfig(
    ifindex_out=ifindex,
    supi_range=num_ues
)
config_map = b.get_table("config_map")
config_map[0] = config

def load():
    # Load shared library
    lib = ctypes.CDLL(f"{include_path}/src/xdpgen/libxdpgen.so")

    # Define argument types for xdp_gen function
    lib.xdp_gen.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]

    # print(ctypes.byref(sendingPacket))
    num_pkts = 1 << 20
    err = lib.xdp_gen(func.fd, num_pkts, sendingPacket, len(sendingPacket))
    if err != 0:
        print("Failed to call xdp_gen function")


def add_ue_record(ip_address_str: str, teid: int, qfi: int) -> None:
    """ This function adds a new user equipment (UE) record to the specified supi_record_map iterated through when generating 
    PDU session traffic. The UE record is identified by its IP address, teid and qfi values. """
    global num_ues
    global b

    supi_record_map = b.get_table("supi_record_map")

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
    supi_record_map[num_ues] = state
    num_ues += 1

    # Create configs
    config = TrafficgenConfig(
        ifindex_out=ifindex,
        supi_range=num_ues
    )
    config_map = b.get_table("config_map")
    config_map[0] = config


def records():
    txcnt = b.get_table("txcnt")
    try:
        return txcnt.sum(0).value
    except Exception as e:
        print(f"Failed to get packet stats: {e}")
        raise e

def remove_program():
    b.remove_xdp(ifname, 0)

# txcnt = b.get_table("txcnt")
# prev = 0
# print("Printing generated packets, hit CTRL+C to stop")
# while 1:
#     try:
#         val = txcnt.sum(0).value
#         if val:
#             delta = val - prev
#             prev = val
#             print("{} pkt/s".format(delta))
#         time.sleep(1)
#     except KeyboardInterrupt:
#         print("Removing filter from device")
#         break

# b.remove_xdp(ifname, 0)