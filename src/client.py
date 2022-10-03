from binascii import unhexlify
import logging
import json
import time
from SCTP import SCTPClient, SCTPServer
from NGAP import NGAPNonUEProcRANDispatcher, NGAPProc
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
nGSetup = NGAPNonUEProcRANDispatcher[21]()
# Get NGSetupRequest PDU
nGSetupPDU = nGSetup.get_pdu()
# Get NGSetupRequest PDU APER
nGSetupPDU_APER = nGSetupPDU.to_aper()

# Connect to 5G Core
gNBcp.connect(server_config['sctp']['address'], server_config['sctp']['port'])

# Send NGSetupRequest message to 5G Core)
gNBcp._sctp_queue.put(nGSetupPDU_APER)

# Wait for 5 seconds
time.sleep(5)

# Disconnect from 5G Core
gNBcp.disconnect()
time.sleep(5)
