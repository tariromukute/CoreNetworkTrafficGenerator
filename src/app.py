import threading
import time
import array
import sys
import traceback
from argparse import ArgumentParser

from UE import UE, FGMMState
from NAS import NAS
from SCTP import SCTPClient
from NGAP import GNB

from multiprocessing import Process, Manager, cpu_count, active_children
from logging.handlers import QueueHandler
import logging
import yaml


logger = logging.getLogger('__app__')

# Multi process class
class MultiProcess:
    def __init__(self, logger_queue, server_config, nas_dl_queue, nas_ul_queue, ues_queue, ue_list):
        sctp_client = SCTPClient(logger_queue, server_config)
        self.gnb = GNB(sctp_client, logger_queue, server_config, nas_dl_queue, nas_ul_queue, ues_queue, ue_list)
        self.nas = NAS(logger_queue, nas_dl_queue, nas_ul_queue, ue_list)
        self.processes = [
            Process(target=self.gnb.run),
            Process(target=self.nas.run),
        ]

    def run(self):
        for process in self.processes:
            process.start()

    def stop(self):
        for process in self.processes:
            process.terminate()


# Logging process
class LoggingProcess(Process):
    def __init__(self, queue, filepath=".", filename="core-tg.log", name="core-tg", level=logging.DEBUG):
        Process.__init__(self)
        self.queue = queue
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        formatter = logging.Formatter(
            '%(asctime)s : %(levelname)s:%(name)s:%(message)s')
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        file_handler = logging.FileHandler(f"{filepath}/{filename}")
        file_handler.setFormatter(formatter)

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    def run(self):
        while True:
            record = self.queue.get()
            if record is None:
                break
            self.logger.handle(record)

# Create Util function to add UEs


def util_add_ue_process(ue_list, ues_queue, ue_config, number, interval):
    start_time = time.time()
    base_imsi = ue_config['supi'][:-10]
    init_imsi = int(ue_config['supi'][-10:])
    for i in range(0, number):
        imsi = '{}{}'.format(base_imsi, format(init_imsi + i, '010d'))
        config = ue_config
        config['supi'] = imsi
        ue = UE(config)
        logger.debug("Adding to Queue UE: %s", ue)
        ues_queue.put(ue)
        if interval > 0:
            time.sleep(interval)

    # Wait for GNB to be ready before checking UE states
    time.sleep(5)

    # run forever
    while True:
        try:
            # Create array of size 10
            ue_state_count = array.array('i', [0] * 10)
            for ue in ue_list:
                if ue.supi:
                    if ue.state < FGMMState.FGMM_STATE_MAX:
                        ue_state_count[ue.state] += 1
                    else:
                        logging.error(
                            "UE: %s has unknown state: %s", ue.supi, ue.state)
            # Get FGMMState names
            fgmm_state_names = [
                FGMMState(i).name for i in range(FGMMState.FGMM_STATE_MAX)]
            logger.info("UE state count: %s", dict(
                zip(fgmm_state_names, ue_state_count)))
            # If all the UEs have registered exit
            if ue_state_count[FGMMState.REGISTERED] >= number:
                # Get the UE that had the latest state_time and calculate the time it took all UEs to be registered
                latest_time = start_time
                for ue in ue_list:
                    if ue.supi:
                        latest_time = ue.state_time if latest_time < ue.state_time else latest_time

                logger.info("Registered {} UEs in {}".format(
                    number, latest_time - start_time))
                sys.exit(0)
            time.sleep(1)
        except Exception:
            logger.exception('Whoops! Problem:', file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

# Define struct for arguments


class Arguments:
    def __init__(self, verbose, debug, log, console, file, duration, interval, number, ue_config_file, gnb_config_file):
        self.verbose = verbose
        self.debug = debug
        self.log = log
        self.console = console
        self.duration = duration
        self.interval = interval
        self.number = number
        self.file = file
        self.ue_config_file = ue_config_file
        self.gnb_config_file = gnb_config_file


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

    manager = Manager()
    # create the shared queue
    nas_dl_queue = manager.Queue()
    nas_ul_queue = manager.Queue()
    ues_queue = manager.Queue()
    # Create ctype array of object to store UEs
    ue_list = manager.list()

    init_imsi = int(ue_config['supi'][-10:])

    # If the imsi doesn't start from 0, the list will be larger than needed
    for i in range(init_imsi + args.number + 1):
        ue_list.append(UE())

    logger_queue = manager.Queue(-1)
    logger = logging.getLogger('__app__')

    # Start the logging process
    logging_process = LoggingProcess(logger_queue)
    logging_process.start()

    # add a handler that uses the shared queue
    logger.addHandler(QueueHandler(logger_queue))
    # log all messages, debug and up
    logger.setLevel(logging.INFO)

    # Create multi process
    multi_process = MultiProcess(
        logger_queue, server_config, nas_dl_queue, nas_ul_queue, ues_queue, ue_list)
    multi_process.run()

    # Wait for GNB to be ready
    time.sleep(5)

    # Start registering UEs
    util = threading.Thread(target=util_add_ue_process, args=(
        ue_list, ues_queue, ue_config, args.number, args.interval))
    util.daemon = True
    util.start()
     
    # Wait for UE to be added
    time.sleep(args.duration - 5)

    multi_process.stop()
    logger_queue.put(None)
    logging_process.join()
    logger.removeHandler(logger_queue)
    # logger_queue.close()
    manager.shutdown()

    # End multi process
    logger.debug("Ending multi process")


# Define parser arguments
parser = ArgumentParser(description='Run TRex client API and send DNS packet')
parser.add_argument('-t', '--duration', type=int, default=10,
                    help='Duration of test in seconds, minimum 10 seconds')
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
args = parser.parse_args()

if args.duration and args.duration < 10:
    parser.error("Minimum duration is 10 seconds")

arguments = Arguments(False, False, False, False, '.', args.duration,
                      args.interval, args.number, args.ue_config_file, args.gnb_config_file)
main(arguments)
