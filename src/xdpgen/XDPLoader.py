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


src_port = 12345
dst_port = 54321

ethernet = Ether(dst="00:22:48:ce:14:39", src="60:45:bd:41:38:71")
outerIp = IPv6(src="2404:f800:8000:122::4", dst="2404:f800:8000:122::5")
outerUdp = UDP(sport=2152, dport=2152,chksum=0)
# innerIp = IP(src="12.1.1.4", dst="10.50.100.1")
innerIp = IPv6(src="2404:f800:8000:121::4", dst="2404:f800:8000:124::5")
icmpPkt = ICMP()
innerUdp = UDP(sport=src_port, dport=dst_port)
gtpHeader = GTP_U_Header(teid=0, next_ex=133)/GTPPDUSessionContainer(type=1, QFI=9)

payload = "This is a test message"

packet = ethernet/outerIp/outerUdp/gtpHeader/innerIp/innerUdp/payload

sendingPacket = ctypes.create_string_buffer(raw(packet), len(packet))

# Replace "eth0" with the name of your interface
ifname = "eth1"

# Use socket to get the ifindex
ifindex = socket.if_nametoindex(ifname)

print(ifindex)

b = BPF(src_file="gtpu.bpf.c", cflags=["-I/home/azureuser", "-Wno-macro-redefined"])
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

supi_record_map = b.get_table("supi_record_map")

ip_address_str = "2404:f800:8000:124::4"

ip_address_bytes = ipaddress.ip_address(ip_address_str).packed

print(len(ip_address_bytes))
ip_version = 4 if len(ip_address_bytes) == 4 else 6
for i in range(0,10):
    # create an instance of the struct and populate its value
    state = SupiRecordState(
        ip_src=IpAddress(
            version=ip_version,
            addr=(ctypes.c_byte * 16).from_buffer_copy(ip_address_bytes + bytes([0] * 12)) if ip_version == 4 else (ctypes.c_byte * 16).from_buffer_copy(ip_address_bytes)
        ),
        teid=1 + i,
        qfi=(i % 6) + 1
    )

    # insert the struct into the hash table
    supi_record_map[i] = state

# Create configs
config = TrafficgenConfig(
    ifindex_out=ifindex,
    supi_range=10
)
config_map = b.get_table("config_map")
config_map[0] = config

# Create state
state = TrafficgenState(next_supi=0)
state_map = b.get_table("state_map")
state_map[0] = state

# Load shared library
lib = ctypes.CDLL("/home/azureuser/xdpgen.so")

# Define argument types for xdp_gen function
lib.xdp_gen.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]

# print(ctypes.byref(sendingPacket))
num_pkts = 40
err = lib.xdp_gen(func.fd, num_pkts, sendingPacket, len(sendingPacket))
if err != 0:
    print("Failed to call xdp_gen function")


txcnt = b.get_table("txcnt")
prev = 0
print("Printing generated packets, hit CTRL+C to stop")
while 1:
    try:
        val = txcnt.sum(0).value
        if val:
            delta = val - prev
            prev = val
            print("{} pkt/s".format(delta))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(ifname, 0)