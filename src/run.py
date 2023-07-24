import time
from argparse import ArgumentParser
# Define struct for arguments
import signal
from UESim import UESim
from SCTP import SCTPClient
from NGAPSim import GNB

from multiprocessing import Process, active_children, Pipe
import logging
import yaml


logger = logging.getLogger('__app__')

# Multi process class
class MultiProcess:
    def __init__(self, server_config, ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, ue_config, interval, statistics, verbose):
        sctp_client = SCTPClient(server_config)
        self.gnb = GNB(sctp_client, server_config, ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, verbose)
        self.ueSim = UESim(ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, ue_config, interval, statistics, verbose)
        self.processes = [
            Process(target=self.gnb.run),
            Process(target=self.ueSim.run),
        ]

    def run(self):
        for process in self.processes:
            process.start()

class Arguments:
    def __init__(self, log, console, file, interval, ue_config_file, gnb_config_file, statistics, verbose):
        self.log = log
        self.console = console
        self.interval = interval
        self.file = file
        self.ue_config_file = ue_config_file
        self.gnb_config_file = gnb_config_file
        self.statistics = statistics
        self.verbose = verbose


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

    ngap_to_ue, ue_to_ngap = Pipe(duplex=True)
    upf_to_ue, ue_to_upf = Pipe(duplex=True)
   
    # Create multi process
    multi_process = MultiProcess(server_config, ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, ue_config, args.interval, args.statistics, args.verbose)
    multi_process.run()
    
    while True:
        try:
            # Check if all child processes have terminated
            if len(active_children()) == 0:
                print("Exiting......")
                break
            # Wait for a short time before checking again
            time.sleep(1)
        except KeyboardInterrupt:
            print("Program Interrupted")


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
args = parser.parse_args()

arguments = Arguments(False, False, '.',
                      args.interval, args.ue_config_file, args.gnb_config_file, args.statistics, args.verbose)
main(arguments)
