import time
import csv
from argparse import ArgumentParser

# Define struct for arguments
import signal
from src.UESim import UESim
from src.SCTP import SCTPClient
from src.NGAPSim import GNB
from src.GTPU import GTPU, GTPUConfig
from src.bpf.XDPLoader import Trafficgen
from src.bpf.ipstats import IPStats
from src.UE import *
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
    GTP_UDP_PORT: "gtpu",
    # ... Add other protocols as needed
}

pkt_s = "pkts/s"
bytes_s = "kb/s"

logger = logging.getLogger("__app__")


class Arguments:
    def __init__(
        self,
        log,
        console,
        file,
        interval,
        num_pkts,
        ue_config_file,
        gnb_config_file,
        statistics,
        ebpf,
        verbose,
    ):
        self.log = log
        self.console = console
        self.interval = interval
        self.num_pkts = num_pkts
        self.file = file
        self.ue_config_file = ue_config_file
        self.gnb_config_file = gnb_config_file
        self.statistics = statistics
        self.ebpf = ebpf
        self.verbose = verbose


class TimeRange:
    def __init__(
        self,
        start_time,
        end_time,
        min_interval,
        sum_interval,
        max_interval,
        duration,
        completed_in,
        success,
        failed,
    ):
        self.start_time = Value("f", start_time)
        self.end_time = Value("f", end_time)
        self.min_interval = Value("f", min_interval)
        self.sum_interval = Value("f", sum_interval)
        self.max_interval = Value("f", max_interval)
        self.duration = Value("f", duration)
        self.completed_in = Value("f", completed_in)
        self.success = Value("i", success)
        self.failed = Value("i", failed)

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


def create_ues(ue_profiles, x):
    dict_list = [{} for _ in range(x)]
    p = 0
    for ue_config in ue_profiles:
        count, base_imsi, init_imsi = (
            ue_config["count"],
            ue_config["supi"][:-10],
            int(ue_config["supi"][-10:]),
        )
        for i in range(init_imsi, init_imsi + count):
            imsi = f"{base_imsi}{i:010d}"
            ue = UE({**ue_config, "supi": imsi})
            dict_list[p % x][i] = ue
            p += 1
    if p < x:
        dict_list = dict_list[:p]
    return dict_list, p


def print_state_states(ue_fg_msg_states):
    for value, code in fg_msg_codes.items():
        ue_count = ue_fg_msg_states[code - FGMM_MIN_TYPE]
        row = f"{value:{50}s} | {ue_count:{6}d}"
        print(row)

    print()


def print_stats(
    previous_data, min_data, max_data, ipstats, gtpuTrafficgen, interfaces_map
):
    try:
        print()
        print(
            f"{'':<8} | {' '.join(f'{interfaces_map[if_index]:^20}' for if_index in sorted(interfaces_map))}"
        )  # Headers
        print(
            f"{'':<8} | {' '.join(f'{pkt_s:>10}{bytes_s:>10}' for _ in sorted(interfaces_map))}"
        )  # Subheaders
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
                    # f"{delta_packets:>10}{delta_bytes / 1024:>10.0f}"
                    (delta_packets, delta_bytes / 1024)
                    for if_index in sorted(interfaces_map.keys())
                    for delta_packets, delta_bytes in [
                        (
                            ip_stats.get((if_index, proto), {}).get(
                                f"{direction}_packets", 0
                            )
                            - previous_data.get((if_index, proto), {}).get(
                                f"{direction}_packets", 0
                            ),
                            ip_stats.get((if_index, proto), {}).get(
                                f"{direction}_bytes", 0
                            )
                            - previous_data.get((if_index, proto), {}).get(
                                f"{direction}_bytes", 0
                            ),
                        )
                    ]
                ]
                print(
                    f"{p_name:<6}{label:<2} | {' '.join(f'{dp:>10.0f}{db:>10.0f}' for dp, db in row_data)}"
                )

                # Update min_data and max_data
                for if_index, (delta_packets, delta_bytes) in enumerate(row_data):
                    key = (if_index, proto, direction)
                    min_data[key] = min(min_data.get(key, delta_packets), delta_packets)
                    max_data[key] = max(max_data.get(key, delta_packets), delta_packets)

        previous_data = ip_stats

    except KeyboardInterrupt:
        print()


# Main function
def main(args):
    # Read server configuration
    with open(args.gnb_config_file, "r") as stream:
        try:
            server_config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)

    with open(args.ue_config_file, "r") as stream:
        try:
            ue_config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)

    num_cpus = len(os.sched_getaffinity(0))

    interfaces_map = get_network_interfaces_map()
    gtpuTrafficgen = Trafficgen(server_config["gtpuConfig"]["interface"])
    gtpuConfig = GTPUConfig(
        src_mac=server_config["gtpuConfig"]["srcMac"],
        dst_mac=server_config["gtpuConfig"]["dstMac"],
        src_ip=server_config["gtpuConfig"]["srcIp"],
        dst_ip=server_config["gtpuConfig"]["dstIp"],
        cpu_cores=range(num_cpus // 2),
        num_pkts=args.num_pkts,
    )
    gtpu = GTPU(gtpuConfig, gtpuTrafficgen, args.verbose)

    # This will store the start and end time of the UE simulation/emulation
    ue_sim_time = TimeRange(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0)

    ue_fg_msg_states = multiprocessing.Array(
        "i", tuple([0] * (FGSM_MAX_TYPE - FGMM_MIN_TYPE + 1)), lock=True
    )
    exit_program = multiprocessing.Value("i", 0)

    processes = []
    ue_lists, num_ues = create_ues(
        ue_config["ue_profiles"], num_cpus - 1 if num_cpus > 1 else 1
    )
    for i in range(len(ue_lists)):
        sctp_client = SCTPClient(server_config)
        ngap_to_ue, ue_to_ngap = Pipe(duplex=True)
        upf_to_ue, ue_to_upf = Pipe(duplex=True)
        config = {}
        gnb = GNB(
            exit_program,
            sctp_client,
            gtpu,
            server_config,
            ngap_to_ue,
            ue_to_ngap,
            upf_to_ue,
            ue_to_upf,
            args.verbose,
        )
        ueSim = UESim(
            ue_fg_msg_states,
            exit_program,
            ue_lists[i],
            ngap_to_ue,
            ue_to_ngap,
            upf_to_ue,
            ue_to_upf,
            args.interval,
            args.statistics,
            args.verbose,
            ue_sim_time,
        )
        # % num_cpus so that on single CPU, affirnity is set to CPU 0
        processes.append(
            Process(name=f"ueSIM-{i}", target=ueSim.run, args=((i + 1) % num_cpus,))
        )
        processes.append(
            Process(name=f"gnb-{i}", target=gnb.run, args=((i + 1) % num_cpus,))
        )

    for process in processes:
        process.start()

    ipstats = None
    if args.ebpf:
        ipstats = IPStats()

    previous_data = {}
    min_data = {}
    max_data = {}
    while True:
        try:
            if args.statistics:
                print_state_states(ue_fg_msg_states)

                if args.ebpf:
                    print_stats(
                        previous_data,
                        min_data,
                        max_data,
                        ipstats,
                        gtpuTrafficgen,
                        interfaces_map,
                    )

            # If all UEs are in state 74 (5GMMANConnectionReleaseComplete) exit processes
            if ue_fg_msg_states[74 - FGMM_MIN_TYPE] == num_ues:
                exit_program.value = True
                break

            # report the value
            if len(active_children()) == 0:
                break
            # Wait for a short time before checking again
            time.sleep(args.period)
        except KeyboardInterrupt:
            break

    # Allow for sime for process to exit after setting exit_program.value = True
    time.sleep(2)

    for process in processes:
        process.join(timeout=0.2)

    # TODO: fix processes requiring forceful termination
    children = multiprocessing.active_children()
    for child in children:
        child.terminate()

    # Collect the time on each UE
    table = [
        [
            "Duration",
            f" {ue_sim_time.end_time.value - ue_sim_time.start_time.value} seconds",
        ],
        # ["Completed in",f" {latest_time - start_time} seconds"],
        ["N# of UEs", num_ues],
        ["Successful procedures ", f"{ue_sim_time.success.value} UEs"],
        ["Failed procedures", f"{num_ues - ue_sim_time.success.value} UEs"],
        ["Min interval", f"{ue_sim_time.min_interval.value} seconds"],
        [
            "Avg interval",
            f"{ue_sim_time.sum_interval.value/ue_sim_time.success.value if ue_sim_time.success.value > 0 else -1} seconds",
        ],
        ["Max interval", f"{ue_sim_time.max_interval.value} seconds"],
    ]
    print("\n\n")
    print(tabulate(table, ["Item", "Results"], tablefmt="heavy_outline"))

    # Post process and save to file
    with open("summary_stats.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            [
                "Duration",
                "N# of UEs",
                "Successful procedures",
                "Failed procedures",
                "Min interval",
                "Avg interval",
                "Max interval",
            ]
        )
        writer.writerow(
            [
                ue_sim_time.end_time.value - ue_sim_time.start_time.value,
                num_ues,
                ue_sim_time.success.value,
                num_ues - ue_sim_time.success.value,
                ue_sim_time.min_interval.value,
                (
                    ue_sim_time.sum_interval.value / ue_sim_time.success.value
                    if ue_sim_time.success.value > 0
                    else -1
                ),
                ue_sim_time.max_interval.value,
            ]
        )


# Define parser arguments
parser = ArgumentParser(description="Run 5G Core traffic generator")
parser.add_argument("-l", "--log", type=float, default=1, help="Log to file")
parser.add_argument(
    "-c", "--console", type=bool, default=False, help="Print to console"
)
parser.add_argument(
    "-i",
    "--interval",
    type=bool,
    default=False,
    help="Interval of adding UEs in seconds",
)
parser.add_argument(
    "-n",
    "--num_pkts",
    type=float,
    default=(1 << 20),
    help="Number of num-packets to send per second",
)
parser.add_argument(
    "-u",
    "--ue_config_file",
    type=str,
    default="./config/ue.yaml",
    help="UE configuration file",
)
parser.add_argument(
    "-g",
    "--gnb_config_file",
    type=str,
    default="./config/gnb.yaml",
    help="GNB configuration file",
)
parser.add_argument("-f", "--file", type=str, default=".", help="Log file directory")
parser.add_argument(
    "-v",
    "--verbose",
    action="count",
    default=0,
    help="Increase verbosity (can be specified multiple times)",
)
parser.add_argument(
    "-s", "--statistics", action="store_true", help="Enable print of statistics"
)
parser.add_argument(
    "-e", "--ebpf", action="store_true", help="Enable print of ebpf statistics"
)
parser.add_argument(
    "-p", "--period", type=float, default=1, help="Period/interval (seconds) for printing statistics"
)
args = parser.parse_args()

main(args)
