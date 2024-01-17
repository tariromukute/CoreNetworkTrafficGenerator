import argparse
import time
import random
from scapy.contrib.gtp import (
        GTP_U_Header,
        GTPPDUSessionContainer)
from scapy.all import *
import binascii
from src.xdpgen.XDPLoader import add_ue_record, load, records
import socket
logger = logging.getLogger('__GPTU__')

class GTPU():
    def __init__(self, config, upf_to_ue, verbose) -> None:
        self.config = config
        self.upf_to_ue = upf_to_ue
        self.verbose = verbose
        self.generate = False

    def send(self, ue_data, ip_pkt_data):
        # ip_pkt = binascii.unhexlify(ip_pkt_data)
        # ethernet = Ether(dst=self.config['fgcMac'])
        # outerIp = IP(src=self.config['gtpIp'], dst=ue_data['upf_address'])
        # outerUdp = UDP(sport=2152, dport=2152)
        # innerIp = IP(ip_pkt)
        # gtpHeader = GTP_U_Header(teid=ue_data['ul_teid'], next_ex=133)/GTPPDUSessionContainer(type=1, QFI=ue_data['qfi'])

        # del outerIp[IP].chksum
        # # Delete IP/ICMP checksum fields so that they can be recalculate by scapy
        # del innerIp[IP].chksum
        # if innerIp.proto == 1: 
        #     del innerIp[ICMP].chksum

        # sendingPacket = ethernet/outerIp/outerUdp/gtpHeader/innerIp
        # logger.debug(f"Send GTPU packet \n{sendingPacket.show(dump=True)}")
        # p = srp1(sendingPacket, verbose=self.verbose, timeout=5)
        # if p:
        #     self.forward(p[GTP_U_Header])
        # else:
        #     # Send byte 0 to UE to indicate timeout
        #     self.upf_to_ue.send((b'0', ue_data['dl_teid']))
        ip_addr = socket.inet_ntoa(ip_pkt_data)
        print(f"UE ip address received {ip_addr}")
        add_ue_record(ip_addr, ue_data['ul_teid'], ue_data['qfi'])
        if not self.generate:
            self.start()


    def forward(self, gtpu_pkt):
        # UE supi is the teid
        supi = gtpu_pkt[GTP_U_Header].teid
        raw_ip_pkt = raw(gtpu_pkt[IP])
        ip_data = binascii.hexlify(raw_ip_pkt)
        self.upf_to_ue.send((ip_data, supi))
        
    def run_gtpu_generator(self, cpu):
        affinity_mask = { cpu } 
        pid = 0
        os.sched_setaffinity(0, affinity_mask)
        while self.generate:
            # Perform some action in a loop
            load()

    def print_stats(self):
        prev = 0
        while self.generate:
            val = records()
            if val:
                delta = val - prev
                prev = val
                print("{} pkt/s".format(delta))
            time.sleep(1) 

    def stop(self):
        self.generate = False

    def start(self):
        self.generate = True
        # Create and run thread for printing stats
        thread = threading.Thread(target=self.print_stats)
        thread.start()

        # Create and run threads for generating traffic on different CPU
        threads = []
        for i in range(4):
            t = threading.Thread(target=self.run_gtpu_generator, args=(i,))
            t.daemon = True
            threads.append(t)

        # start all threads
        for t in threads:
            t.start()
        # ngap_to_ue_thread = threading.Thread(target=ngap_to_ue_thread_function)
        # ngap_to_ue_thread.start()
        # return ngap_to_ue_thread
        return threads

