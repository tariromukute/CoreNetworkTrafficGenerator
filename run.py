import time
from argparse import ArgumentParser
# Define struct for arguments
import signal
from src.UESim import UESim
from src.SCTP import SCTPClient
from src.NGAPSim import GNB
from src.GTPU import GTPU, GTPUConfig
from src.bpf.XDPLoader import Trafficgen
from src.bpf.ipstats import IPStats
from multiprocessing import Process, active_children, Pipe, Value
import logging
import yaml
import json
import netifaces
import socket
import os

GTP_UDP_PORT = 2152

protocol_names = {
    # socket.IPPROTO_TCP: "tcp",
    # socket.IPPROTO_UDP: "udp",
    # socket.IPPROTO_ICMP: "icmp",
    socket.IPPROTO_SCTP: "sctp",
    GTP_UDP_PORT: 'gtpu',
    # ... Add other protocols as needed
}

logger = logging.getLogger('__app__')

# Multi process class
class MultiProcess:
    def __init__(self, gtpu, server_config, ue_config, interval, statistics, verbose, ue_sim_time):
        # TODO: remove None and add the other configs
        self.processes = []
        for i in range(len(ue_config['ue_profiles'])):
            sctp_client = SCTPClient(server_config)
            ngap_to_ue, ue_to_ngap = Pipe(duplex=True)
            upf_to_ue, ue_to_upf = Pipe(duplex=True)
            config = {}
            config['ue_profiles'] = [ue_config['ue_profiles'][i]]
            gnb = GNB(sctp_client, gtpu, server_config, ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, verbose)
            ueSim = UESim(ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, config, interval, statistics, verbose, ue_sim_time)
            self.processes.append(Process(target=gnb.run))
            self.processes.append(Process(target=ueSim.run))

    def run(self):
        for process in self.processes:
            process.start()

class Arguments:
    def __init__(self, log, console, file, interval, num_pkts, ue_config_file, gnb_config_file, statistics, verbose):
        self.log = log
        self.console = console
        self.interval = interval
        self.num_pkts = num_pkts
        self.file = file
        self.ue_config_file = ue_config_file
        self.gnb_config_file = gnb_config_file
        self.statistics = statistics
        self.verbose = verbose

class TimeRange():
    def __init__(self, start_time, end_time):
        self.start_time = Value('f', start_time)
        self.end_time = Value('f', end_time)
        

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
# Main function
def main(args: Arguments):
    # Read server configuration
    with open(args.gnb_config_file, 'r') as stream:
        try:
            server_config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)

    with open(args.ue_config_file, 'r') as stream:
        try:
            ue_config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)

    num_cpus = len(os.sched_getaffinity(0))

    duration = 5
    interfaces_map = get_network_interfaces_map()
    gtpuTrafficgen = Trafficgen(server_config['gtpuConfig']['interface'])
    gtpuConfig = GTPUConfig(
        src_mac=server_config['gtpuConfig']['srcMac'],
        dst_mac=server_config['gtpuConfig']['dstMac'],
        src_ip=server_config['gtpuConfig']['srcIp'],
        dst_ip=server_config['gtpuConfig']['dstIp'],
        cpu_cores=range(num_cpus // 2),
        num_pkts=args.num_pkts
    )
    gtpu = GTPU(gtpuConfig, gtpuTrafficgen, args.verbose)

    # Calculate the number of seconds between the monotonic starting point and the Unix epoch
    epoch_to_monotonic_s = time.monotonic() - time.time()
    
    # Convert the Unix timestamp to monotonic time in nanoseconds
    start_time_ns = int((time.time() + epoch_to_monotonic_s) * 1e9)
   
    # This will store the start and end time of the UE simulation/emulation
    ue_sim_time = TimeRange(0.0, 0.0)
    # # Create multi process
    multi_process = MultiProcess(gtpu, server_config, ue_config, args.interval, args.statistics, args.verbose, ue_sim_time)
    multi_process.run()

    ipstats = IPStats()
    previous_data = {}
    pkt_s = "pkts/s"
    bytes_s = "kb/s"
    while True:
        print()
        print(f"{'':<8} | {' '.join(f'{interfaces_map[if_index]:^20}' for if_index in sorted(interfaces_map))}") # Headers
        print(f"{'':<8} | {' '.join(f'{pkt_s:>10}{bytes_s:>10}' for _ in sorted(interfaces_map))}") # Subheaders
        try:
            ip_stats = ipstats.get_stats()
            gtpu_stats = gtpuTrafficgen.get_stats()
            # Merge GTPU stats with ip stats
            for key, value in gtpu_stats.items():
                group = ip_stats[key]
                for field in ("rx_bytes", "rx_packets", "tx_bytes", "tx_packets"):
                    group[field] += value[field]  # Dynamically access fields

            for proto, p_name in protocol_names.items():
                for direction, label in ("rx", "rx"), ("tx", "tx"):
                    row_data = [
                        f"{delta_packets:>10}{delta_bytes / 1024:>10.0f}"
                        for if_index in sorted(interfaces_map.keys())
                        for delta_packets, delta_bytes in [
                            (
                                ip_stats.get((if_index, proto), {}).get(f"{direction}_packets", 0)
                                - previous_data.get((if_index, proto), {}).get(f"{direction}_packets", 0),
                                ip_stats.get((if_index, proto), {}).get(f"{direction}_bytes", 0)
                                - previous_data.get((if_index, proto), {}).get(f"{direction}_bytes", 0),
                            )
                        ]
                    ]
                    # stats.append(f"{p_name} {label} | {' '.join(row_data)}")
                    print(f"{p_name:<6}{label:<2} | {' '.join(row_data)}")
            previous_data = ip_stats
            
            if len(active_children()) == 0:
                break
            # Wait for a short time before checking again
            time.sleep(1)
        except KeyboardInterrupt:
            print()

# Define parser arguments
parser = ArgumentParser(description='Run 5G Core traffic generator')
parser.add_argument('-i', '--interval', type=float, default=0,
                    help='Interval of adding UEs in seconds')
parser.add_argument('-n', '--num_pkts', type=float, default=(1 << 20),
                    help='Number of num-packets to send per second')
parser.add_argument('-u', '--ue_config_file', type=str,
                    default='./config/open5gs-ue.yaml', help='UE configuration file')
parser.add_argument('-g', '--gnb_config_file', type=str,
                    default='./config/open5gs-gnb.yaml', help='GNB configuration file')
parser.add_argument('-f', '--file', type=str, default='.',
                    help='Log file directory')
parser.add_argument('-v', '--verbose', action='count', default=0, 
                    help='Increase verbosity (can be specified multiple times)')
parser.add_argument('-s', '--statistics', action='store_true',
                    help='Enable print of statistics')
args = parser.parse_args()

arguments = Arguments(False, False, '.',
                      args.interval, args.num_pkts, args.ue_config_file, args.gnb_config_file, args.statistics, args.verbose)
main(arguments)
