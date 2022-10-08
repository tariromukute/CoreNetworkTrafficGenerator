from binascii import unhexlify
import logging
import json
import threading
import time
from SCTP import SCTPClient, SCTPServer
from NGAP import NGAPProcDispatcher, NGAPProc
from pycrate_asn1dir import NGAP
# Set logging level
logging.basicConfig(level=logging.INFO)

print("Connecting to 5G Core")

# Read server configuration
with open('server.json', 'r') as server_config_file:
    server_config = json.load(server_config_file)

# Read client configuration
with open('client.json', 'r') as client_config_file:
    client_config = json.load(client_config_file)

gNBcp = SCTPClient(client_config)

# Get NGSetupRequest message. Creates the InitiatingMessage with default values
nGSetup = NGAPProcDispatcher[21]()
# Get NGSetupRequest PDU
nGSetupPDU = nGSetup.get_pdu()
# Get NGSetupRequest PDU APER
nGSetupPDU_APER = nGSetupPDU.to_aper()

# Connect to 5G Core
gNBcp.connect(server_config['sctp']['address'], server_config['sctp']['port'])

# Send NGSetupRequest message to 5G Core)
gNBcp._sctp_queue.put(nGSetupPDU_APER)

print("Sending nGInitialUEMessage")
# Get NGInitialUEMessage message. Creates the InitiatingMessage with default values
nGInitialUEMessage = NGAPProcDispatcher[15]()
# Get NGInitialUEMessage PDU
nGInitialUEMessagePDU = nGInitialUEMessage.get_pdu()
# Get NGInitialUEMessage PDU APER
nGInitialUEMessagePDU_APER = nGInitialUEMessagePDU.to_aper()

# Send NGInitialUEMessage message to 5G Core)
gNBcp._sctp_queue.put(nGInitialUEMessagePDU_APER)



# Create function to read SCTP queue
def read_sctp_queue(gNBcp):
    # Loop forever
    while True:
        # Check if SCTP queue is not empty
        if not gNBcp._rcv_queue.empty():
            # Fetch data from SCTP recv queue
            data = gNBcp._rcv_queue.get()
            # Create NGAP PDU from APER data
            PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
            PDU.from_aper(data)
            # Get procedure code
            procedureCode = PDU.get_val()[1]['procedureCode']
            # Create procedure
            Proc = NGAPProcDispatcher[procedureCode]()
            # Process procedure
            pdu_res = Proc.process(data)
            print(pdu_res)
            if pdu_res:
                logging.info(pdu_res.to_aper())
                # Put data in SCTP queue
                gNBcp._sctp_queue.put(pdu_res.to_aper())


# Create thread to read SCTP queue
process_pdu_thread = threading.Thread(target=read_sctp_queue, args=(gNBcp,))
# Start thread
process_pdu_thread.start()

# Create function to add IntialUEMessage to SCTP queue
# def add_initial_ue_message(gNBcp):
#     i = 31
#     while True:
#         # Get msin from i and add 0s to the left
#         msin = str(i).zfill(10)
#         nGInitialUEMessage = NGAPProcDispatcher[15]()
#         # Get NGInitialUEMessage PDU
#         nGInitialUEMessagePDU = nGInitialUEMessage.get_pdu()
#         # Get NGInitialUEMessage PDU APER
#         nGInitialUEMessagePDU_APER = nGInitialUEMessagePDU.to_aper()

#         # Send NGInitialUEMessage message to 5G Core)
#         gNBcp._sctp_queue.put(nGInitialUEMessagePDU_APER)
#         time.sleep(1)

# # Create thread to add IntialUEMessage to SCTP queue
# intial_ue_thread = threading.Thread(target=add_initial_ue_message, args=(gNBcp,))
# # Start thread
# intial_ue_thread.start()

# # Receive NGDownlink message
# time.sleep(1)

# print("===== Sending uplinkNASTransportMessagePDU =====")
# # Send NGUplinkNASTransportProc
# uplinkNASTransportMessage = NGAPUEAssociatedProcDispatcher[46]()
# # Get NGInitialUEMessage PDU
# uplinkNASTransportMessagePDU = uplinkNASTransportMessage.get_pdu()
# # Get NGInitialUEMessage PDU APER
# uplinkNASTransportMessagePDU_APER = uplinkNASTransportMessagePDU.to_aper()
# # Send NGInitialUEMessage message to 5G Core)
# gNBcp._sctp_queue.put(uplinkNASTransportMessagePDU_APER)






# Wait for 5 seconds
time.sleep(30)

# Disconnect from 5G Core
gNBcp.disconnect()
time.sleep(5)
