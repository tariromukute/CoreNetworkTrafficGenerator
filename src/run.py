import threading
import time
import array
import sys
import traceback
from argparse import ArgumentParser

from UESim import UE, UESim, FGMMState
from SCTP import SCTPClient
from NGAPSim import GNB

from multiprocessing import Process, Manager, cpu_count, active_children, Pipe
from logging.handlers import QueueHandler
import logging
import yaml


logger = logging.getLogger('__app__')

# Multi process class
class MultiProcess:
    def __init__(self, server_config, ngap_to_ue, ue_to_ngap, ue_config, interval, verbose):
        sctp_client = SCTPClient(server_config)
        self.gnb = GNB(sctp_client, server_config, ngap_to_ue, ue_to_ngap, verbose)
        self.ueSim = UESim(ngap_to_ue, ue_to_ngap, ue_config, interval, verbose)
        self.processes = [
            Process(target=self.gnb.run),
            Process(target=self.ueSim.run),
        ]

    # Listen for SIGTERM signal
        signal.signal(signal.SIGTERM, self._sigterm_handler)
        signal.signal(signal.SIGCHLD, self._sigterm_handler)

    def _sigterm_handler(self, signum, frame):
        # Stop child processes
        for process in self.processes:
            process.terminate()

    def run(self):
        for process in self.processes:
            process.start()

    def stop(self):
        for process in self.processes:
            process.terminate()

# Define struct for arguments
import os
import signal

# Keep track of the number of child processes still running
num_children = 0

# Define a signal handler function for SIGCHLD
def sigchld_handler(signum, frame):
    global num_children
    while True:
        try:
            # Call os.waitpid() to get the exit status of the child process
            # WNOHANG makes sure we don't block if there are no child processes left to wait for
            pid, status = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
            print("Exiting...")
            sys.exit(0)
        except OSError:
            break
    

# Register the signal handler function for SIGCHLD
signal.signal(signal.SIGCHLD, sigchld_handler)


class Arguments:
    def __init__(self, log, console, file, interval, ue_config_file, gnb_config_file, verbose):
        self.log = log
        self.console = console
        self.interval = interval
        self.file = file
        self.ue_config_file = ue_config_file
        self.gnb_config_file = gnb_config_file
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
   
    # Create multi process
    multi_process = MultiProcess(server_config, ngap_to_ue, ue_to_ngap, ue_config, args.interval, args.verbose)
    multi_process.run()
    
    while True:
        # Check if all child processes have terminated
        if len(active_children()) == 0:
            print("Exiting......")
            break
        # Wait for a short time before checking again
        time.sleep(1)


# Define parser arguments
parser = ArgumentParser(description='Run 5G Core traffic generator')
parser.add_argument('-i', '--interval', type=float, default=0,
                    help='Interval of adding UEs in seconds')
parser.add_argument('-n', '--number', type=int, default=1,
                    help='Number of UEs to add')
parser.add_argument('-u', '--ue_config_file', type=str,
                    default='src/config/open5gs-ue.yaml', help='UE configuration file')
parser.add_argument('-g', '--gnb_config_file', type=str,
                    default='src/config/open5gs-gnb.yaml', help='GNB configuration file')
parser.add_argument('-f', '--file', type=str, default='.',
                    help='Log file directory')
parser.add_argument('-v', '--verbose', action='count', default=0, 
                    help='Increase verbosity (can be specified multiple times)')
args = parser.parse_args()

arguments = Arguments(False, False, '.',
                      args.interval, args.ue_config_file, args.gnb_config_file, args.verbose)
main(arguments)
