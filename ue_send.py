import argparse
import time
import random
from scapy.contrib.gtp import (
        GTP_U_Header,
        GTPPDUSessionContainer)
from scapy.all import *
import binascii

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-d', '--destination', type=str, help="Destination IPv4 address")
    parser.add_argument('-m', '--macaddress', type=str, help="Destination host MAC address")
    parser.add_argument('-s', '--source', type=str, help="IPv4 address assigned to UE")
    # binascii.hexlify( raw(IP(dst='8.8.8.8')/ICMP()) ) => 4500001c00010000400160c10a000010080808080800f7ff00000000
    parser.add_argument('-p', '--packet', type=str, help="The IP packet to be sent by UE in byte string [ binascii.hexlify( raw(IP(dst='8.8.8.8')/ICMP()) ) ]",
                        default='4500001c00010000400160c10a000010080808080800f7ff00000000')
    parser.add_argument('-t', '--teid', default=1,
                        type=int, help="GTP-U Tunnel Endpoint Identifier(TEID)")
    parser.add_argument('-q', '--qfi', default=1,
                        type=int, help="QoS Flow ID(QFI)")
    parser.add_argument('-u', '--duration', default=5,
                        type=int, help="Packet sending duration [sec]")
    parser.add_argument('-i', '--interval', default=1000,
                        type=int, help="Packet sending interval [msec]")
    args = parser.parse_args()

    try:
        # Convert user packet string to binary format
        ue_ip_packet = binascii.unhexlify(args.packet)

        # Define Ethernet/IPv4/UDP/GTP-U headers for the outer packet
        ethernet = Ether(dst=args.macaddress)
        outerIp = IP(dst=args.destination)
        outerUdp = UDP(sport=2152, dport=2152)
        gtpHeader = GTP_U_Header(teid=args.teid, next_ex=133)/GTPPDUSessionContainer(type=1, QFI=args.qfi)
        
        innerIp = IP(ue_ip_packet)
        innerIp.src=args.source

        # Delete IP/ICMP checksum fields so that they can be recalculate by scapy
        del innerIp[IP].chksum
        if innerIp.proto == 1: 
            del innerIp[ICMP].chksum

        delta = args.interval/1000.0
        count = int(args.duration / delta)

        # Send packets at a regular interval
        for i in range(count):
            time.sleep(delta)
            sendingPacket = ethernet/outerIp/outerUdp/gtpHeader/innerIp
            # sendingPacket.show()
            # sendp(sendingPacket, verbose=True)
            p = srp1(sendingPacket, timeout=2)

    except Exception as e:
        # Handle any exception that occurs and print error message
        print(f"An error occurred: {e}")
        exit(1)