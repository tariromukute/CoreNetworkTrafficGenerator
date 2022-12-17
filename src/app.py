import logging
import json
import threading
import time
import array
import os
import yaml
from UE import UE, FGMMState
from NAS import NAS
from SCTP import SCTPClient, SCTPServer
from NAS import process_nas_procedure, RegistrationProc
from NGAP import NGAPProcDispatcher, NGAPProc, GNB
from multiprocessing import Process, Array
from multiprocessing import Manager, current_process
from logging.handlers import QueueHandler
import logging
from argparse import ArgumentParser

logger = logging.getLogger('__app__')

# Multi process GNB class
class GNBProcess(Process):
    def __init__(self, logger_queue, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array):
        Process.__init__(self)
        self.gNB = GNB(logger_queue, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array)

    def run(self):
        logger.debug("Starting GNB process")
        self.gNB.run()

# Multi process NAS class
class NASProcess(Process):
    def __init__(self, logger_queue, nas_dl_queue, nas_ul_queue, ue_list):
        Process.__init__(self)
        self.nas = NAS(logger_queue, nas_dl_queue, nas_ul_queue, ue_list)

    def run(self):
        logger.debug("Starting NAS process")
        self.nas.run()

# Multi process SCTP class
class SCTPProcess(Process):
    def __init__(self, logger_queue, server_config, ngap_dl_queue, ngap_ul_queue):
        Process.__init__(self)
        self.sctp = SCTPClient(logger_queue, server_config, ngap_dl_queue, ngap_ul_queue)

    def run(self):
        logger.debug("Starting SCTP client process")
        self.sctp.run()

# Logging process
class LoggingProcess(Process):
    def __init__(self, queue, filepath=".", filename="core-tg.log", name="core-tg", level=logging.DEBUG, format="%(asctime)s : %(levelname)s:%(name)s:%(message)s"):
        Process.__init__(self)
        self.queue = queue
        self._logger = self.generate_logger(filepath)

    def generate_logger(self, path=".", filename="core-tg.log", name="core-tg", level=logging.DEBUG, format="%(asctime)s : %(levelname)s:%(name)s:%(message)s"):
        import logging
        LOG_FILENAME = "{}/{}".format(path, filename)
        FORMAT = "%(asctime)s : %(levelname)s:%(name)s:%(message)s"
        _logger = logging.getLogger()
        _logger.setLevel(logging.ERROR)
        # Reset the logger.handlers if it already exists.
        if _logger.handlers:
            _logger.handlers = []
        # # configure a stream handler
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter(FORMAT))
        # configure a file handler
        file_handler = logging.FileHandler(LOG_FILENAME)
        file_handler.setFormatter(logging.Formatter(FORMAT))
        # add the handlers to the logger
        _logger.addHandler(stream_handler)
        _logger.addHandler(file_handler)

        return _logger

    # TODO: Check how its working without this method, readin the queue
    # def _load_logging_thread(self):
    #     logger_thread = threading.Thread(target=self.logger_process_function)
    #     logger_thread.start()
    #     return logger_thread

    # def logger_process_function(self):
        
    #     # run forever
    #     while True:
    #         try:
    #             print("Waiting for log message")
    #             record = self.queue.get()
    #             if record is None:  # We send this as a sentinel to tell the listener to quit.
    #                 break
    #             # skip logging if record log level is INFO
    #             # if record.levelno == logging.INFO:
    #             #     continue
    #             print("Logging process: ", record.levelno)
    #             # print("Logging process: ", record)
    #             self.logger.handle(record)  # No level or filter logic applied - just do it!
    #         except Exception:
    #             import sys, traceback
    #             print('Whoops! Problem:', file=sys.stderr)
    #             traceback.print_exc(file=sys.stderr)


    def run(self):
        print("Starting logging process")
        # self._load_logging_thread()

# Create Util process
class UtilProcess(Process):
    def __init__(self, logger_queue, ue_list, ues_queue, ue_config, number, interval):
        Process.__init__(self)
        self.ue_list = ue_list
        self.ues_queue = ues_queue
        self.number = number
        self.interval = interval
        self.ue_config = ue_config

    def run(self):
        logger.debug("Starting util process")
        self._load_util_thread()
        # Wait for GNB process to be ready before starting to add UEs
        # time.sleep(5)
        self._load_util_add_ue_thread()

    def _load_util_thread(self):
        util_thread = threading.Thread(target=self.util_process_function)
        util_thread.start()
        return util_thread

    def util_process_function(self):
        # run forever
        while True:
            try:
                # Create array of size 10
                ue_state_count = array.array('i', [0] * 10)
                for ue in self.ue_list:
                    if ue.supi:
                        if ue.state < FGMMState.FGMM_STATE_MAX:
                            ue_state_count[ue.state] += 1
                        else:
                            logging.error("UE: %s has unknown state: %s", ue.supi, ue.state)
                # Get FGMMState names
                fgmm_state_names = [FGMMState(i).name for i in range(FGMMState.FGMM_STATE_MAX)]
                logger.info("UE state count: %s", dict(zip(fgmm_state_names, ue_state_count)))
                time.sleep(1)
            except Exception:
                import sys, traceback
                print('Whoops! Problem:', file=sys.stderr)
                traceback.print_exc(file=sys.stderr)

    def _load_util_add_ue_thread(self):
        util_add_ue_thread = threading.Thread(target=self.util_add_ue_process_function)
        util_add_ue_thread.start()
        return util_add_ue_thread

    def util_add_ue_process_function(self):
        base_imsi = self.ue_config['supi'][:-10]
        init_imsi = int(self.ue_config['supi'][-10:])
        for i in range(0, self.number):
            imsi = '{}{}'.format(base_imsi, format(init_imsi + i, '010d'))
            config = self.ue_config
            config['supi'] = imsi
            ue = UE(config)
            logger.debug("Adding to Queue UE: %s", ue)
            self.ues_queue.put(ue)
            if self.interval > 0:
                time.sleep(self.interval)

# Multi process class
class MultiProcess:
    def __init__(self, logger_queue, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_list):
        self.sctp = SCTPProcess(logger_queue, server_config, ngap_dl_queue, ngap_ul_queue)
        self.gNB = GNBProcess(logger_queue, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_list)
        self.nas = NASProcess(logger_queue, nas_dl_queue, nas_ul_queue, ue_list)

        # add a handler that uses the shared queue
        logger.addHandler(QueueHandler(logger_queue))
        # log all messages, debug and up
        logger.setLevel(logging.INFO)

        # Set the processes to daemon to exit when main process exits
        self.sctp.daemon = True
        self.gNB.daemon = True
        self.nas.daemon = True
        
    def run(self):
        self.sctp.start()
        self.gNB.start()
        self.nas.start()
        logger.debug("Started processes")

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
            server_config=yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)

    with open(args.ue_config_file, 'r') as stream:
        try:
            ue_config=yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)

    with Manager() as manager:
        # create the shared queue
        ngap_dl_queue = manager.Queue()
        ngap_ul_queue = manager.Queue()
        nas_dl_queue = manager.Queue()
        nas_ul_queue = manager.Queue()
        ues_queue = manager.Queue()
        # Create ctype array of object to store UEs
        ue_list = manager.list()

        logger_queue = manager.Queue(-1)

        # Start the logging process
        logging = LoggingProcess(logger_queue, args.file)
        logging.daemon = True
        logging.start()
        # Initialise ue_list with 1000 UEs
        for i in range(args.number + 1):
            ue_list.append(UE())

        # Create multi process
        multi_process = MultiProcess(logger_queue, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_list)
        multi_process.run()

        # Wait for GNB to be ready
        time.sleep(5)

        # Start registering UEs
        util = UtilProcess(logger_queue, ue_list, ues_queue, ue_config, args.number, args.interval)
        util.daemon = True
        util.start()

        # Wait for UE to be added
        time.sleep(args.duration - 5)
        
    # End multi process
    logger.debug("Ending multi process")

# Main
if __name__ == "__main__":
    # Get program arguments
    parser = ArgumentParser(description = 'Run TRex client API and send DNS packet',
        usage = """stl_dns_debug.py [options]""" )

    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug output')
    parser.add_argument('-l', '--log', action='store_true', help='Log output')
    parser.add_argument('-c', '--console', action='store_true', help='Console output')
    parser.add_argument('-f', '--file', type=str, default='.', help='Log file directory')
    parser.add_argument('-t', '--duration', type=int, default=10, help='Duration of test in seconds, minimum 10 seconds')
    parser.add_argument('-i', '--interval', type=float, default=0, help='Interval of adding UEs in seconds')
    parser.add_argument('-n', '--number', type=int, default=1, help='Number of UEs to add')
    parser.add_argument('-u', '--ue_config_file', type=str, default='config/open5gs-ue.yaml', help='UE configuration file')
    parser.add_argument('-g', '--gnb_config_file', type=str, default='config/open5gs-gnb.yaml', help='GNB configuration file')
    
    args = parser.parse_args()

    if args.duration and args.duration < 10:
        parser.error("Minimum duration is 10 seconds")

    # Create file directory if it doesn't exist
    if not os.path.exists(args.file):
        os.makedirs(args.file)

    # Create arguments object
    arguments = Arguments(args.verbose, args.debug, args.log, args.console, args.file, args.duration, args.interval, args.number, args.ue_config_file, args.gnb_config_file)

    # Run main
    main(arguments)
