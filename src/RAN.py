import struct
import time
import logging
import threading
from SCTP import SCTPClient
from pycrate_asn1dir import NGAP
from binascii import unhexlify, hexlify
from logging.handlers import QueueHandler

# Util functions
def extract_nas_pdu(PDU):
    # Extract IE values
    IEs = PDU.get_val()[1]['value'][1]['protocolIEs']
    # Extract AMF-UE-NGAP-ID
    amf_ue_ngap_id = next((ie['value'][1] for ie in IEs if ie['id'] == 10), None)
    # Extract RAN-UE-NGAP-ID
    ran_ue_ngap_id = next((ie['value'][1] for ie in IEs if ie['id'] == 85), None)
    # Extract the NAS PDU
    nas_pdu = next((ie['value'][1] for ie in IEs if ie['id'] == 38), None)
   
    return nas_pdu, ran_ue_ngap_id, amf_ue_ngap_id

# Functions for processing procedures
def ng_setup_request(IEs) -> bytes:
    return None

def ue_initial(data, IEs) -> bytes:
    return None

# More procedure functions

class NGAPRAN:
    def __init__(self, sctp: SCTPClient, config) -> None:
        """
            Instantiate the RAN
            1. Get config parameters
            2. Create the common IEs
            3. Create thread and dispatcher messages received from 5G Core network
            4. Create thread and dispatcher from messages received from UEs
        """
        self.sctp = sctp
        self.conn = None
        self.config_params = self.get_config_params(config)
        self.common_ies = self.create_common_ies()
        self.core_network_thread = threading.Thread(target=self.handle_core_network_messages)
        self.core_network_dispatcher = self.cn_message_dispatcher()
        self.ues_thread = threading.Thread(target=self.handle_ue_messages)
        self.ue_dispatcher = self.ue_message_dispatcher()
    
    def handle_core_network_messages(self):
        """
            Method to handle messages received from 5G Core network
        """
        while True:
            data = self.sctp.recv()
            if not data:
                # Exit loop if recv returns an empty byte string (remote end closed the connection)
                break
            PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
            PDU.from_aper(data)
            procedureCode = PDU.get_val()[1]['procedureCode']
            IEs = []
            IEs.append(self.common_ies)
            self.core_network_dispatcher.get(procedureCode, lambda *args: logging.info("Procedure not supported: ", args))(IEs)
    
    def handle_ue_messages(self):
        """
            Method to handle messages received from UEs
        """
        while True:
            ue, data = self.sctp.recv()
            if not data:
                # Exit loop if recv returns an empty byte string (remote end closed the connection)
                break
            Msg, err = parse_NAS5G(data)
            IEs = []
            IEs.append(self.common_ies)
            self.ue_dispatcher.get(Msg._name, lambda *args: logging.info("Procedure not supported: ", args))(Msg.to_bytes(), IEs)
    
    def get_config_params(self, config):
        """
            Function to retrieve configuration parameters
        """
        pass

    def create_common_ies(self):
        """
            Function to create common IEs
        """
        pass

    def cn_message_dispatcher(self):
        """
            Function to create a message dispatcher for messages received from 
            the 5G Core Network
        """
        return {
            0: ng_setup_request
        }
    
    def ue_message_dispatcher(self):
        """
            Function to create a message dispatcher for messages received from UEs
        """
        return {
            0: ue_initial
        }

    # Additional methods for processing messages and performing procedures go here
