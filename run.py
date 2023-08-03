import time
from argparse import ArgumentParser
# Define struct for arguments
import signal
from src.UESim import UESim
from src.SCTP import SCTPClient
from src.NGAPSim import GNB
from multiprocessing import Process, active_children, Pipe, Value
import logging
import yaml
import json

logger = logging.getLogger('__app__')

# Multi process class
class MultiProcess:
    def __init__(self, server_config, ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, ue_config, interval, statistics, verbose, ue_sim_time):
        sctp_client = SCTPClient(server_config)
        self.gnb = GNB(sctp_client, server_config, ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, verbose)
        self.ueSim = UESim(ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, ue_config, interval, statistics, verbose, ue_sim_time)
        self.processes = [
            Process(target=self.gnb.run),
            Process(target=self.ueSim.run),
        ]

    def run(self):
        for process in self.processes:
            process.start()

class Arguments:
    def __init__(self, log, console, file, interval, ue_config_file, gnb_config_file, statistics, verbose, ebpf):
        self.log = log
        self.console = console
        self.interval = interval
        self.file = file
        self.ue_config_file = ue_config_file
        self.gnb_config_file = gnb_config_file
        self.statistics = statistics
        self.verbose = verbose
        self.ebpf = ebpf

class TimeRange():
    def __init__(self, start_time, end_time):
        self.start_time = Value('f', start_time)
        self.end_time = Value('f', end_time)
        


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

    if args.ebpf:
        from stats.sctprwnd import b, rwnd_map

    # Calculate the number of seconds between the monotonic starting point and the Unix epoch
    epoch_to_monotonic_s = time.monotonic() - time.time()
    
    # Convert the Unix timestamp to monotonic time in nanoseconds
    start_time_ns = int((time.time() + epoch_to_monotonic_s) * 1e9)
    print(f"Program starts at {start_time_ns} monotonic time in nanoseconds")
    
    ngap_to_ue, ue_to_ngap = Pipe(duplex=True)
    upf_to_ue, ue_to_upf = Pipe(duplex=True)
   
    # This will store the start and end time of the UE simulation/emulation
    ue_sim_time = TimeRange(0.0, 0.0)
    # Create multi process
    multi_process = MultiProcess(server_config, ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, ue_config, args.interval, args.statistics, args.verbose, ue_sim_time)
    multi_process.run()
    
    while True:
        try:
            # Check if all child processes have terminated
            if len(active_children()) == 0:
                break
            # Wait for a short time before checking again
            time.sleep(1)
        except KeyboardInterrupt:
            print()
            # print("Program Interrupted")
    if args.ebpf:
        from collections import defaultdict
        
        # to hold json data of rwnd stats
        rwnd_dict = defaultdict(lambda: {"port": None, "values": []})
        
        # Filter rwnd_map to get values before completed_at.value
        filtered_rwnd_map = list(filter(lambda x: x[0].nsecs < ue_sim_time.end_time.value, rwnd_map.items()))
        # We assume the last value recorded was still the value when the program was terminated
        last_value = filtered_rwnd_map[-1]
        last_key = last_value[0]
        last_key.nsecs = int(ue_sim_time.end_time.value)
        end_value = (last_key, last_value[1])
        filtered_rwnd_map.append(end_value)
        
        # Sort filtered_rwnd_map by key
        sorted_rwnd_map = sorted(filtered_rwnd_map, key=lambda x: x[0].nsecs)
        init_nsecs_time = sorted_rwnd_map[0][0].nsecs

        # calculate the average which is average of (current k.necs - previous k.nsecs) * previous v.value 
        for k, v in sorted_rwnd_map:
            rwnd_dict[k.peer_port]["port"] = k.peer_port
            rwnd_dict[k.peer_port]["values"].append({"time_ns": k.nsecs - init_nsecs_time, "value": v.value})
        
        

        rwnd_results = list(rwnd_dict.values())

        # Plot SCTP rwnd graph using matlibplot
        import matplotlib.pyplot as plt
        
        # Get the list of x and y values from the data
        x = [point["time_ns"] for point in rwnd_results[0]["values"]]
        y = [point["value"] for point in rwnd_results[0]["values"]]
        min_index = y.index(min(y))

        # Plot the data and format the plot
        plt.plot(x, y)
        plt.title(f"SCTP rwnd over duration of simulation")
        plt.xlabel("Time (ns)")
        plt.ylabel("SCTP rwnd value (bytes)")

        # Add a vertical line at the simulation start time
        plt.axvline(x=(ue_sim_time.start_time.value - init_nsecs_time), color='r', linestyle='--',
                    label='Simulation started'
                    )
        
        # Add a marker at the lowest point
        plt.plot(x[min_index], y[min_index], marker='o', color='red')

        # Label the marker
        plt.text(x[min_index], y[min_index], f'Lowest Point ({y[min_index]})')
        
        # Add a legend to the plot
        plt.legend()

        plt.savefig("rwnd_plot.png")

        print(f"Lowest rwnd is {y[min_index]}")

# Define parser arguments
parser = ArgumentParser(description='Run 5G Core traffic generator')
parser.add_argument('-i', '--interval', type=float, default=0,
                    help='Interval of adding UEs in seconds')
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
parser.add_argument('-e', '--ebpf', action='store_true',
                    help='Load ebpf programs to collect and graph SCTP stats')
args = parser.parse_args()

arguments = Arguments(False, False, '.',
                      args.interval, args.ue_config_file, args.gnb_config_file, args.statistics, args.verbose, args.ebpf)
main(arguments)
