import logging
import json
import threading
import time
from UE import UE
from SCTP import SCTPClient, SCTPServer
from NAS import process_nas_procedure, RegistrationProc
from NGAP import NGAPProcDispatcher, NGAPProc, GNB
from multiprocessing import Process, Queue, Array

# Create shared mp queues
ngap_dl_queue = Queue()
ngap_ul_queue = Queue()
nas_dl_queue = Queue()
nas_ul_queue = Queue()
ues_queue = Queue()
# Create ctype array of object to store UEs
ue_array = Array(UE, 1000)

# Multi process GNB class
class GNBProcess(Process):
    def __init__(self, client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array):
        Process.__init__(self)
        self.gNB = GNB(client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ue_array)

    def run(self):
        self.gNB.run()

# Set logging level
logging.basicConfig(level=logging.INFO)

# Multi process NGAP class
class NGAPProcess(Process):
    def __init__(self, gNB, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue):
        Process.__init__(self)
        self.gNB = gNB
        self.ngap_dl_queue = ngap_dl_queue
        self.ngap_ul_queue = ngap_ul_queue
        self.nas_dl_queue = nas_dl_queue
        self.nas_ul_queue = nas_ul_queue

    def run(self):
        while True:
            # Check if there is data in the queue
            if not self.ngap_dl_queue.empty():
                # Get data from queue
                data = self.ngap_dl_queue.get()
                # Decode data
                pdu = NGAP.NGAP_PDU.from_aper(data)
                # Get message type
                message_type = pdu['value'][0]
                # Get procedure code
                procedure_code = message_type['procedureCode']
                # Get initiating message
                initiating_message = message_type['value'][0]
                # Get ran_ue_ngap_id
                ran_ue_ngap_id = initiating_message['value']['RAN-UE-NGAP-ID']['value']
                # Get ue
                ue = self.gNB.get_ue(ran_ue_ngap_id)
                # Get procedure
                procedure = NGAPProcDispatcher[procedure_code](data, ue)
                # Run procedure
                procedure.run()

# Multi process NAS class
class NASProcess(Process):
     def __init__(self, nas_dl_queue: Queue, nas_ul_queue: Queue):
        self.nas_dl_queue = nas_dl_queue
        self.nas_ul_queue = nas_ul_queue

    def process_nas_dl(self):
        while True:
            ue, data = self.nas_dl_queue.get()
            if data is None:
                break
            else:
                tx_nas_pdu = process_nas_procedure(data, ue)
                if tx_nas_pdu is not None:
                    self.nas_ul_queue.put((ue.supi, tx_nas_pdu))
    
    def run(self):
        nas_dl_thread = Thread(target=self.process_nas_dl)
        nas_dl_thread.start()

        nas_dl_thread.join()

# Multi process SCTP class
class SCTPProcess(Process):
    def __init__(self, gNB, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue):
        Process.__init__(self)
        self.gNB = gNB
        self.ngap_dl_queue = ngap_dl_queue
        self.ngap_ul_queue = ngap_ul_queue
        self.nas_dl_queue = nas_dl_queue
        self.nas_ul_queue = nas_ul_queue

    def run(self):
        # Create SCTP client
        client = SCTPClient(self.gNB.client_config, self.gNB.server_config, self.ngap_dl_queue, self.ngap_ul_queue, self.nas_dl_queue, self.nas_ul_queue)
        # Create SCTP server
        server = SCTPServer(self.gNB.client_config, self.gNB.server_config, self.ngap_dl_queue, self.ngap_ul_queue, self.nas_dl_queue, self.nas_ul_queue)
        # Create SCTP client thread
        client_thread = threading.Thread(target=client.run)
        # Create SCTP server thread
        server_thread = threading.Thread(target=server.run)
        # Start SCTP client thread
        client_thread.start()
        # Start SCTP server thread
        server_thread.start()

# Multi process UE class
class UEProcess(Process):
    def __init__(self, gNB, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue):
        Process.__init__(self)
        self.gNB = gNB
        self.ngap_dl_queue = ngap_dl_queue
        self.ngap_ul_queue = ngap_ul_queue
        self.nas_dl_queue = nas_dl_queue
        self.nas_ul_queue = nas_ul_queue

    def run(self):
        # Create UE
        ue = UE(self.gNB, self.ngap_dl_queue, self.ngap_ul_queue, self.nas_dl_queue, self.nas_ul_queue)
        # Create UE thread
        ue_thread = threading.Thread(target=ue.run)
        # Start UE thread
        ue_thread.start()

# Multi process class
class MultiProcess:
    def __init__(self, client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue):
        self.gNB = GNBProcess(client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue)
        self.ngap = NGAPProcess(self.gNB.gNB, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue)
        self.nas = NASProcess(self.gNB.gNB, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue)
        self.sctp = SCTPProcess(self.gNB.gNB, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue)
        self.ue = UEProcess(self.gNB.gNB, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue)

    def run(self):
        # Start gNB process
        self.gNB.start()
        # Start NGAP process
        self.ngap.start()
        # Start NAS process
        self.nas.start()
        # Start SCTP process
        self.sctp.start()
        # Start UE process
        self.ue.start()

# Main function
def main():
    # Create queues
    ngap_dl_queue = Queue()
    ngap_ul_queue = Queue()
    nas_dl_queue = Queue()
    nas_ul_queue = Queue()
    # Create multi process
    multi_process = MultiProcess(client_config, server_config, ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue)
    # Run multi process
    multi_process.run()
