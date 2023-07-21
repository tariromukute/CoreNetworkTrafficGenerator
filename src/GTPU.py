import argparse
import time
import random
from scapy.contrib.gtp import (
        GTP_U_Header,
        GTPPDUSessionContainer)
from scapy.all import *
import binascii

logger = logging.getLogger('__GPTU__') 

class GTPU():
    def __init__(self, config, upf_to_ue) -> None:
        self.config = config
        self.upf_to_ue = upf_to_ue

    def send(self, ue_data, ip_pkt_data):
        ip_pkt = binascii.unhexlify(ip_pkt_data)
        ethernet = Ether(dst=self.config['gtpMac'])
        outerIp = IP(src=self.config['gtpIp'], dst=ue_data['upf_address'])
        outerUdp = UDP(sport=2152, dport=2152)
        innerIp = IP(ip_pkt)
        gtpHeader = GTP_U_Header(teid=ue_data['ul_tied'], next_ex=133)/GTPPDUSessionContainer(type=1, QFI=ue_data['qfi'])

        del outerIp[IP].chksum
        # Delete IP/ICMP checksum fields so that they can be recalculate by scapy
        del innerIp[IP].chksum
        if innerIp.proto == 1: 
            del innerIp[ICMP].chksum

        sendingPacket = ethernet/outerIp/outerUdp/gtpHeader/innerIp
        logger.debug(f"Send GTPU packet \n{sendingPacket.show(dump=True)}")
        p = srp1(sendingPacket, verbose=True, timeout=5)
        if p:
            self.forward(p[GTP_U_Header])
        # Send byte 0 to UE to indicate timeout
        self.upf_to_ue.send((b'0', ue_data['dl_tied']))


    def forward(self, gtpu_pkt):
        # UE supi is the teid
        supi = gtpu_pkt[GTP_U_Header].teid
        raw_ip_pkt = raw(gtpu_pkt[IP])
        ip_data = binascii.hexlify(raw_ip_pkt)
        self.upf_to_ue.send((ip_data, supi))
        

