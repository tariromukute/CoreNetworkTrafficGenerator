# Standard library imports
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


#######################################################################
# Data Structure Classes
#######################################################################
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

#######################################################################
# Network Utility Functions
#######################################################################
def get_network_interfaces_map():
    """
    Creates a mapping between interface indices and interface names.
    
    Returns:
        dict: A dictionary mapping interface indices to interface names
    """

    interface_map = {}
    interfaces = netifaces.interfaces()  # Get interface names using netifaces

    for interface_name in interfaces:
        try:
            if_index = socket.if_nametoindex(interface_name)
            interface_map[if_index] = interface_name
        except OSError:
            print(f"Error retrieving if_index for interface: {interface_name}")

    return interface_map


#######################################################################
# UE Management Functions
#######################################################################
def create_ues(ue_profiles, x):
    """
    Creates UE instances based on the provided profiles and distributes them
    across the specified number of processes.
    
    Args:
        ue_profiles: List of UE configuration profiles
        x: Number of processes to distribute UEs across
        
    Returns:
        tuple: A tuple containing a list of UE dictionaries and the total number of UEs
    """

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


#######################################################################
# Statistics and Monitoring Functions
#######################################################################
def print_state_states(ue_fg_msg_states, state_writer):
    """
    Records the current UE state counts to a CSV file.
    
    Args:
        ue_fg_msg_states: Array of UE state counts
        state_writer: CSV writer for state output
    """
     
    entry = {}
    for value, code in fg_msg_codes.items():
        ue_count = ue_fg_msg_states[code - FGMM_MIN_TYPE]
        entry[value] = ue_count

    state_writer.writerow(entry.values())


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

#######################################################################
# SCTP Tracing Functions
#######################################################################
def setup_sctp_tracers(args, exit_program):
    """
    Sets up SCTP tracers for monitoring SCTP-related metrics.
    
    Args:
        args: Command line arguments
        exit_program: Shared value to signal program exit
        
    Returns:
        Process: A process for running the tracers, or None if no tracers enabled
    """

    # Ensure output directory exists
    if args.folder and not os.path.exists(args.folder):
        os.makedirs(args.folder)

    # Dictionary to hold all active tracers
    tracers = {}

    # Only import the modules when needed to avoid dependencies for users
    # who don't use SCTP tracing

    if args.sctp_rtt:
        from sctptrace.tools.sctp_rtt import SCTPRttTracer

        rtt_file = os.path.join(args.folder, "sctp_rtt.csv") if args.folder else None
        rtt_tracer = SCTPRttTracer(
            interval=args.period, csv_output=True, output_file=rtt_file
        )
        # rtt_tracer.setup()
        tracers["RTT"] = rtt_tracer

    if args.sctp_rto:
        from sctptrace.tools.sctp_rto import SCTPRtoTracer

        rto_file = os.path.join(args.folder, "sctp_rto.csv") if args.folder else None
        rto_tracer = SCTPRtoTracer(
            interval=args.period, csv_output=True, output_file=rto_file
        )
        # rto_tracer.setup()
        tracers["RTO"] = rto_tracer

    if args.sctp_bufmon:
        from sctptrace.tools.sctp_bufmon import SCTPBufmonTracer

        bufmon_file = (
            os.path.join(args.folder, "sctp_bufmon.csv") if args.folder else None
        )
        bufmon_tracer = SCTPBufmonTracer(
            interval=args.period, csv_output=True, output_file=bufmon_file
        )
        # bufmon_tracer.setup()
        tracers["Buffer"] = bufmon_tracer

    if args.sctp_stream:
        from sctptrace.tools.sctp_streamutil import SCTPStreamTracer

        stream_file = (
            os.path.join(args.folder, "sctp_stream.csv") if args.folder else None
        )
        stream_tracer = SCTPStreamTracer(
            interval=args.period, csv_output=True, output_file=stream_file
        )
        # stream_tracer.setup()
        tracers["Stream"] = stream_tracer

    if args.sctp_jitter:
        from sctptrace.tools.sctp_jitter import SCTPJitterTracer

        jitter_file = (
            os.path.join(args.folder, "sctp_jitter.csv") if args.folder else None
        )
        jitter_tracer = SCTPJitterTracer(
            interval=args.period, csv_output=True, output_file=jitter_file
        )
        # jitter_tracer.setup()
        tracers["Jitter"] = jitter_tracer

    # Create a process to handle all tracers with proper signal handling
    if tracers:
        tracer_process = Process(
            target=run_tracers, args=(tracers, args.period, exit_program)
        )
        tracer_process.daemon = True
        return tracer_process

    return None


def run_tracers(tracers, interval, exit_flag):
    """
    Run all tracers in a single process with proper signal handling.
    
    Args:
        tracers: Dictionary of tracer instances
        interval: Polling interval
        exit_flag: Shared value to signal program exit
    """

    # Dictionary to track which tracers have been cleaned up
    cleaned_tracers = {name: False for name in tracers.keys()}

    # Set up signal handlers for graceful shutdown
    def handle_exit_signal(signum, frame):
        cleanup_tracers(tracers, cleaned_tracers)
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_exit_signal)
    signal.signal(signal.SIGINT, handle_exit_signal)

    # Setup all tracers
    for name, tracer in tracers.items():
        tracer.setup()

    try:
        while not exit_flag.value:
            for name, tracer in tracers.items():
                tracer.poll_events()  # Short timeout to check exit flag
            time.sleep(0.1)  # Small sleep to avoid CPU spinning
    except Exception as e:
        print(f"Error in tracer process: {e}")
    finally:
        cleanup_tracers(tracers, cleaned_tracers)


def cleanup_tracers(tracers, cleaned_tracers):
    """
    Ensure all tracers are properly cleaned up.
    
    Args:
        tracers: Dictionary of tracer instances
        cleaned_tracers: Dictionary tracking which tracers have been cleaned
    """

    if cleaned_tracers is None:
        cleaned_tracers = {name: False for name in tracers.keys()}

    for name, tracer in tracers.items():
        if cleaned_tracers.get(name, False):
            continue
        try:
            tracer.print_summary()
            time.sleep(2)
            tracer.cleanup()
            cleaned_tracers[name] = True
            print(f"Tracer {name} cleaned up")
        except Exception as e:
            print(f"Error cleaning up tracer {name}: {e}")

#######################################################################
# Main Application Logic
#######################################################################
def main(args):
    """
    Main function that runs the 5G Core traffic generator.
    
    Args:
        args: Command line arguments
    """

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
    exit_program = multiprocessing.Value("i", 0)

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

    # Start SCTP tracers if requested
    tracer_process = None
    if (
        args.sctp
        or args.sctp_rtt
        or args.sctp_rto
        or args.sctp_bufmon
        or args.sctp_stream
        or args.sctp_jitter
    ):
        tracer_process = setup_sctp_tracers(args, exit_program)
        if tracer_process:
            tracer_process.start()

    # Wait a for ebpf programs to attach
    time.sleep(5)

    # This will store the start and end time of the UE simulation/emulation
    ue_sim_time = TimeRange(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0)

    ue_fg_msg_states = multiprocessing.Array(
        "i", tuple([0] * (FGSM_MAX_TYPE - FGMM_MIN_TYPE + 1)), lock=True
    )

    state_writer = None
    if args.statistics:
        state_log_file = os.path.join(args.folder, "ue_states.csv")
        os.makedirs(os.path.dirname(state_log_file), exist_ok=True)
        state_file = open(state_log_file, "w", newline="")
        state_writer = csv.writer(state_file)
        # Write headers
        state_writer.writerow(list(fg_msg_codes.keys()))

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
                print_state_states(ue_fg_msg_states, state_writer)

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

    if tracer_process:
        tracer_process.join()

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

    summary_log_file = os.path.join(args.folder, "summary_stats.csv")
    os.makedirs(os.path.dirname(summary_log_file), exist_ok=True)
    summary_file = open(summary_log_file, "w", newline="")
    summary_writer = csv.writer(summary_file)
    summary_writer.writerow(
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
    summary_writer.writerow(
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

#######################################################################
# Entry Point
#######################################################################
if __name__ == "__main__":
    # Define parser arguments
    parser = ArgumentParser(description="Run 5G Core traffic generator")
    parser.add_argument("-l", "--log", type=float, default=1, help="Log to file")
    parser.add_argument("-c", "--console", action="store_true", help="Print to console")
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
    parser.add_argument(
        "-f",
        "--folder",
        type=str,
        default=".",
        help="Directory for output (stats and logs)",
    )
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
        "-p",
        "--period",
        type=float,
        default=1,
        help="Period/interval (seconds) for printing statistics",
    )

    # Add SCTP-specific arguments
    parser.add_argument(
        "--sctp", action="store_true", help="Enable all SCTP tracing modules"
    )
    parser.add_argument(
        "--sctp-rtt", action="store_true", help="Enable SCTP RTT tracing"
    )
    parser.add_argument(
        "--sctp-rto", action="store_true", help="Enable SCTP RTO tracing"
    )
    parser.add_argument(
        "--sctp-bufmon", action="store_true", help="Enable SCTP buffer monitoring"
    )
    parser.add_argument(
        "--sctp-stream",
        action="store_true",
        help="Enable SCTP stream utilization analysis",
    )
    parser.add_argument(
        "--sctp-jitter", action="store_true", help="Enable SCTP jitter measurement"
    )

    args = parser.parse_args()

    # If --sctp is specified, enable all SCTP tracing modules
    if args.sctp:
        args.sctp_rtt = True
        args.sctp_rto = True
        args.sctp_bufmon = True
        args.sctp_stream = True
        args.sctp_jitter = True

    main(args)
