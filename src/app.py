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
from multiprocessing import Manager

# Set logging level
logging.basicConfig(level=logging.INFO)

# Multi process GNB class
class GNBProcess(Process):
    def __init__(self, client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array):
        Process.__init__(self)
        self.gNB = GNB(client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array)
        logger = logging.getLogger('__GNBProcess__')

    def run(self):
        logger.info("Starting GNB process")
        self.gNB.run()

# Multi process NAS class
class NASProcess(Process):
    def __init__(self, nas_dl_queue, nas_ul_queue, ue_list):
        Process.__init__(self)
        self.nas = NAS(nas_dl_queue, nas_ul_queue, ue_list)
        logger = logging.getLogger('__NASProcess__')

    def run(self):
        logger.info("NAS process started")
        self.nas.run()

# Multi process SCTP class
class SCTPProcess(Process):
    def __init__(self, config, server_config, ngap_dl_queue, ngap_ul_queue):
        Process.__init__(self)
        self.sctp = SCTPClient(config, server_config, ngap_dl_queue, ngap_ul_queue)
        logger = logging.getLogger('__SCTPProcess__')

    def run(self):
        logger.info("Starting SCTP client")
        self.sctp.run()

# Multi process class
class MultiProcess:
    def __init__(self, client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_list):
        self.sctp = SCTPProcess(client_config, server_config, ngap_dl_queue, ngap_ul_queue)
        self.gNB = GNBProcess(client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_list)
        self.nas = NASProcess(nas_dl_queue, nas_ul_queue, ue_list)
        # Set the processes to daemon to exit when main process exits
        self.sctp.daemon = True
        self.gNB.daemon = True
        self.nas.daemon = True
        logger = logging.getLogger(__name__)

    def run(self):
        logger.info("Starting processes")
        self.sctp.start()
        self.gNB.start()
        self.nas.start()

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

        # Initialise ue_list with 1000 UEs
        for i in range(1000):
            ue_list.append(UE())

        # Create multi process
        logging.info("Creating multi process")
        multi_process = MultiProcess(client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_list)
        # Run multi process
        multi_process.run()
        logging.info("Created multi process")

        # Wait for GNB to be ready
        time.sleep(5)

        # Initialise ue_list with 1000 UEs
        # for starting at 31
        # for i in range(31, 1031):
        base_imsi = ue_config['supi'][:-10]
        init_imsi = int(ue_config['supi'][-10:])
        for i in range(0, 500):
            imsi = '{}{}'.format(base_imsi, format(init_imsi + i, '010d'))
            config = ue_config
            config['supi'] = imsi
            ue = UE(config)
            logging.info("Adding to Queue UE: %s", ue)
            ues_queue.put(ue)

        # Wait for UE to be added
        time.sleep(60*5)
        # Create array of size 10
        ue_state_count = array.array('i', [0] * 10)
        for ue in ue_list:
            if ue.supi:
                if ue.state < FGMMState.FGMM_STATE_MAX:
                    ue_state_count[ue.state] += 1
                else:
                    logger.error("UE: %s has unknown state: %s", ue.supi, ue.state)
        # Get FGMMState names
        fgmm_state_names = [FGMMState(i).name for i in range(FGMMState.FGMM_STATE_MAX)]
        for i in range(FGMMState.FGMM_STATE_MAX):
            logger.info("UE state: %s count: %s", fgmm_state_names[i], ue_state_count[i])

    # End multi process
    logging.info("Ending multi process")
    
# Main
if __name__ == "__main__":
    # Create logger
    logger = logging.getLogger(__name__)

    # Run main
    main()
