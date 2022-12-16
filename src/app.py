import logging
import json
import threading
import time
import array
from UE import UE, FGMMState
from NAS import NAS
from SCTP import SCTPClient, SCTPServer
from NAS import process_nas_procedure, RegistrationProc
from NGAP import NGAPProcDispatcher, NGAPProc, GNB
from multiprocessing import Process, Array
from multiprocessing import Manager, current_process
from logging.handlers import QueueHandler
import logging

logger = logging.getLogger('__app__')

# Multi process GNB class
class GNBProcess(Process):
    def __init__(self, logger_queue, client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array):
        Process.__init__(self)
        config = {
            'mcc': '999',
            'mnc': '70',
            'nci': '0x000000010',
            'idLength': 32,
            'tac': 1,
            'slices': { 'sst': 1 }
        }
        self.gNB = GNB(logger_queue, config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array)

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
    def __init__(self, logger_queue, config, server_config, ngap_dl_queue, ngap_ul_queue):
        Process.__init__(self)
        self.sctp = SCTPClient(logger_queue, config, server_config, ngap_dl_queue, ngap_ul_queue)

    def run(self):
        logger.debug("Starting SCTP client process")
        self.sctp.run()

# Logging process
class LoggingProcess(Process):
    def __init__(self, queue):
        Process.__init__(self)
        self.queue = queue
        self._logger = self.generate_logger()

    def generate_logger(self):
        import logging
        LOG_FILENAME = "core-tg.log"
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
    def __init__(self, logger_queue, ue_list):
        Process.__init__(self)
        self.ue_list = ue_list

    def run(self):
        logger.debug("Starting util process")
        self._load_util_thread()

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

# Multi process class
class MultiProcess:
    def __init__(self, logger_queue, client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_list):
        self.logging = LoggingProcess(logger_queue)
        self.sctp = SCTPProcess(logger_queue, client_config, server_config, ngap_dl_queue, ngap_ul_queue)
        self.gNB = GNBProcess(logger_queue, client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_list)
        self.nas = NASProcess(logger_queue, nas_dl_queue, nas_ul_queue, ue_list)
        self.util = UtilProcess(logger_queue, ue_list)

        # add a handler that uses the shared queue
        logger.addHandler(QueueHandler(logger_queue))
        # log all messages, debug and up
        logger.setLevel(logging.INFO)

        # Set the processes to daemon to exit when main process exits
        self.logging.daemon = True
        self.sctp.daemon = True
        self.gNB.daemon = True
        self.nas.daemon = True
        self.util.daemon = True
        
    def run(self):
        self.logging.start()
        self.sctp.start()
        self.gNB.start()
        self.nas.start()
        self.util.start()
        logger.debug("Started processes")


# Main function
def main():
     # Read server configuration
    with open('server.json', 'r') as server_config_file:
        server_config = json.load(server_config_file)

    # Read client configuration
    with open('client.json', 'r') as client_config_file:
        client_config = json.load(client_config_file)

    with Manager() as manager:
        # create the shared queue
        ngap_dl_queue = manager.Queue()
        ngap_ul_queue = manager.Queue()
        nas_dl_queue = manager.Queue()
        nas_ul_queue = manager.Queue()
        ues_queue = manager.Queue()
        # Create ctype array of object to store UEs
        # ue_array = Array(UE, 1000)
        ue_list = manager.list()

        logger_queue = manager.Queue(-1)

        # Create UE config
        # ue_config = {
        #     'supi': '208950000000031',
        #     'mcc': '208',
        #     'mnc': '95',
        #     'key': '0C0A34601D4F07677303652C0462535B',
        #     'op': '63bfa50ee6523365ff14c1f45f88737d',
        #     'op_type': 'OPC',
        #     'amf': '8000',
        #     'imei': '356938035643803',
        #     'imeiSv': '0035609204079514',
        #     'tac': '0001'
        # }
        ue_config = {
            'supi': '999700000000001',
            'mcc': '999',
            'mnc': '70',
            'key': '465B5CE8B199B49FAA5F0A2EE238A6BC',
            'op': 'E8ED289DEBA952E4283B54E88E6183CA',
            'op_type': 'OPC',
            'amf': '8000',
            'imei': '356938035643803',
            'imeiSv': '4370816125816151',
            'tac': '0001',
            'sst': 1
        }

        # Initialise ue_list with 1000 UEs
        for i in range(1000):
            ue_list.append(UE())

        # Create multi process
        # logger.debug("Creating multi process")
        multi_process = MultiProcess(logger_queue, client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_list)
        # Run multi process
        multi_process.run()
        # logger.debug("Created multi process")

        # Wait for GNB to be ready
        time.sleep(5)

        # Initialise ue_list with 1000 UEs
        # for starting at 31
        # for i in range(31, 1031):
        base_imsi = ue_config['supi'][:-10]
        init_imsi = int(ue_config['supi'][-10:])
        for i in range(0, 1):
            imsi = '{}{}'.format(base_imsi, format(init_imsi + i, '010d'))
            config = ue_config
            config['supi'] = imsi
            ue = UE(config)
            logger.debug("Adding to Queue UE: %s", ue)
            ues_queue.put(ue)

        # Wait for UE to be added
        time.sleep(15)
        
    # End multi process
    logger.debug("Ending multi process")
    
# Main
if __name__ == "__main__":
    # Run main
    main()
