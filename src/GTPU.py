import argparse
import time
import random
from scapy.contrib.gtp import (
        GTP_U_Header,
        GTPPDUSessionContainer)
from scapy.all import *
import binascii
import socket
logger = logging.getLogger('__GPTU__')

from typing import NamedTuple

class GTPUConfig(NamedTuple):
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    cpu_cores: List[int]

class GTPU():
    def __init__(self, config: GTPUConfig, trafficgen, verbose):
        self.config = config
        self.verbose = verbose
        self.generate = False
        self.gtpu_pkt = self.prepare_gtpu_pkt(config)
        self.cpu_cores = config.cpu_cores if config.cpu_cores != None else [0, 1, 2, 3]
        self.tg = trafficgen

    def prepare_gtpu_pkt(self, pkt_cfg):
        # TODO: accomodate IPv6
        ethernet = Ether(src=pkt_cfg.src_mac, dst=pkt_cfg.dst_mac)
        outerIp = IP(src=pkt_cfg.src_ip, dst=pkt_cfg.dst_ip)
        outerUdp = UDP(sport=2152, dport=2152, chksum=0)
        innerIp = IP(src="10.1.1.4", dst="10.50.100.1")
        innerUdp = UDP(sport=12345, dport=54321)
        gtpHeader = GTP_U_Header(teid=0, next_ex=133) / GTPPDUSessionContainer(type=1, QFI=9)
        payload = "This is a test message"

        packet = ethernet / outerIp / outerUdp / gtpHeader / innerIp / innerUdp / payload
        logger.debug(packet.summary())
        return bytes(packet)

    def send(self, ue_data, ip_pkt_data):
        try:
            ip_addr = socket.inet_ntoa(ip_pkt_data)
            logger.debug(f"Received request for UE with ip address {ip_addr}")
            self.tg.add_ue_record(ip_addr, ue_data['ul_teid'], ue_data['qfi'])
            if not self.generate:
                self.start()
        except Exception as e:
            print(f"Error sending: {e}")
        
    def run_gtpu_generator(self, cpu):
        affinity_mask = { cpu } 
        pid = 0
        os.sched_setaffinity(0, affinity_mask)
        while self.generate:
            # Perform some action in a loop
            self.tg.run(self.gtpu_pkt)

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
        logger.info("Starting GTPU traffic generator")
        try:
            # Create and run threads for generating traffic on different CPU
            threads = []
            for i in self.cpu_cores:
                t = threading.Thread(target=self.run_gtpu_generator, args=(i,))
                t.daemon = True
                threads.append(t)

            # start all threads
            for t in threads:
                t.start()
            return threads
        except Exception as e:
            print(f"Error starting generator: {e}")

