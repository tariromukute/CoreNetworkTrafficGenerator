import logging
import json
import threading
import time
from UE import UE
from NAS import NAS
from SCTP import SCTPClient, SCTPServer
from NAS import process_nas_procedure, RegistrationProc
from NGAP import NGAPProcDispatcher, NGAPProc, GNB
from multiprocessing import Process, Queue, Array

# Set logging level
logging.basicConfig(level=logging.INFO)

# Multi process GNB class
class GNBProcess(Process):
    def __init__(self, client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array):
        Process.__init__(self)
        self.gNB = GNB(client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array)

    def run(self):
        logger.info("Starting GNB process")
        self.gNB.run()

# Multi process NAS class
class NASProcess(Process):
    def __init__(self, nas_dl_queue: Queue, nas_ul_queue: Queue):
        Process.__init__(self)
        self.nas = NAS(nas_dl_queue, nas_ul_queue)

    def run(self):
        logger.info("NAS process started")
        self.nas.run()

# Multi process SCTP class
class SCTPProcess(Process):
    def __init__(self, config, server_config, ngap_dl_queue, ngap_ul_queue):
        Process.__init__(self)
        self.sctp = SCTPClient(config, server_config, ngap_dl_queue, ngap_ul_queue)

    def run(self):
        logger.info("Starting SCTP client")
        self.sctp.run()

# Multi process class
class MultiProcess:
    def __init__(self, client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array):
        self.sctp = SCTPProcess(client_config, server_config, ngap_dl_queue, ngap_ul_queue)
        self.gNB = GNBProcess(client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array)
        self.nas = NASProcess(nas_dl_queue, nas_ul_queue)

    def run(self):
        logger.info("Starting processes")
        self.sctp.start()
        self.gNB.start()
        self.nas.start()

        # self.sctp.join()
        # self.gNB.join()
        # self.nas.join()

# Main function
def main():
     # Read server configuration
    with open('server.json', 'r') as server_config_file:
        server_config = json.load(server_config_file)

    # Read client configuration
    with open('client.json', 'r') as client_config_file:
        client_config = json.load(client_config_file)

    # Create queues
    ngap_dl_queue = Queue()
    ngap_ul_queue = Queue()
    nas_dl_queue = Queue()
    nas_ul_queue = Queue()
    ues_queue = Queue()
    # Create ctype array of object to store UEs
    # ue_array = Array(UE, 1000)
    ue_array = []

    # Create multi process
    logging.info("Creating multi process")
    multi_process = MultiProcess(client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array)
    # Run multi process
    multi_process.run()
    logging.info("Created multi process")
    
    # Add UE
    # Create UE config
    ue_config = {
        'supi': '208950000000031',
        'mcc': '208',
        'mnc': '95',
        'key': '0C0A34601D4F07677303652C0462535B',
        'op': '63bfa50ee6523365ff14c1f45f88737d',
        'op_type': 'OPC',
        'amf': '8000',
        'imei': '356938035643803',
        'imeiSv': '0035609204079514',
        'tac': '0001'
    }

    # Create UE
    ue = UE(ue_config)

    ues_queue.put(ue)

    # Wait for UE to be added
    time.sleep(10)

# Main
if __name__ == "__main__":
    # Create logger
    logger = logging.getLogger(__name__)

    # Run main
    main()