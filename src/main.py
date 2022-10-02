from binascii import unhexlify
import logging
import json
import time
from SCTP import SCTPClient, SCTPServer
from NGAP import NGAPNonUEProcRANDispatcher, NGAPProc
# Set logging level
logging.basicConfig(level=logging.INFO)

print("Running server and client in the same process")

# Read server configuration
with open('server.json', 'r') as server_config_file:
    server_config = json.load(server_config_file)

# Read client configuration
with open('client.json', 'r') as client_config_file:
    client_config = json.load(client_config_file)

sctp_server = SCTPServer(server_config)
sctp_client = SCTPClient(client_config)

sctp_client.connect(server_config['sctp']['address'], server_config['sctp']['port'])

data = unhexlify('00150044000004001b00090002f8595000000001005240170a00554552414e53494d2d676e622d3230382d39352d3100660010000000a0000002f859000016f000007b0015400140')
Proc = NGAPNonUEProcRANDispatcher[21](data)
print(Proc.get_pdu().to_aper())
# Loop forever
# while True:
for i in range(5):
    logging.info('Sending SCTP data')
    # Put data in SCTP queue
    sctp_client._sctp_queue.put(Proc.get_pdu().to_aper())
    # Sleep for 1 second
    time.sleep(1)

# Disconnect SCTP client from SCTP server
sctp_client.disconnect()
time.sleep(5)