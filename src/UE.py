from enum import IntEnum
from binascii import unhexlify, hexlify
import time

# Define enum
class FGMMState(IntEnum):
    """ 5GMM State: 3GPP TS 24.501 version 16.9.0 Release 16, Section 5. """
    NULL = 0
    DEREGISTERED = 1
    REGISTERED_INITIATED = 2
    REGISTERED = 3
    DEREGISTERED_INITIATED = 4
    SERVICE_REQUEST_INITIATED = 5
    # Not in 3GPP TS 24.501 version 16.9.0 Release 16, Section 5.
    AUTHENTICATED_INITIATED = 6
    AUTHENTICATED = 7
    SECURITY_MODE_INITIATED = 8
    SECURITY_MODE_COMPLETED = 9
    # Last state indicate number of states
    FGMM_STATE_MAX = 10


class UE():
    """ UE class """

    def __init__(self, config = None) -> None:
        """ Initiate the UE. """
        # Set several instance variables to None
        self.ue_capabilities = self.ue_security_capabilities = self.ue_network_capability = \
            self.nas_proc = self.nas_pdu = None
        
        # Set values for empty variables to all zeros in bytes
        empty_values = ['k_nas_int', 'k_nas_enc', 'k_amf', 'k_ausf', 'k_seaf', 'sqn', 'autn',
                        'mac_a', 'mac_s', 'xres_star', 'xres', 'res_star', 'res', 'rand']
        for var_name in empty_values:
            setattr(self, var_name, b'\x00' * 32)
        
        # Initialize other variables to default values or values from config
        self.nas_key_set, self.amf_ue_ngap_id = set(), None
        if config is None:
            # If config is None, set some variables to None and others to default values
            self.supi = self.amf_ue_ngap_id = None
            self.state = FGMMState.NULL
            self.op_type, self.state_time = 'OPC', time.time()
        else:
            # Otherwise, set variables based on values from config
            self.supi = config['supi']
            self.mcc = config['mcc']
            self.mnc = config['mnc']
            self.msin = config['supi'][-10:]
            self.key = config['key']
            self.op = config['op']
            self.op_type = config['opType']
            self.amf = config['amf']
            self.imei = config['imei']
            self.imeiSv = config['imeiSv']
            sn_name = "5G:mnc{:03d}.mcc{:03d}.3gppnetwork.org".format(int(config['mnc']), int(config['mcc']))
            self.sn_name = sn_name.encode()
            self.nssai = [{'SST': int(a['sst']), 'SD': int(a['sd'])} 
             if 'sd' in a else {'SST': int(a['sst'])}  # Create dictionaries for each item in defaultNssai list
             for a in config['defaultNssai']]
            self.state, self.state_time = FGMMState.NULL, time.time()

    def send(self, data: bytes) -> bytes:
        # Put data on quene
        if data:
            # Send object with data and supi
            self._nas_queue.put((data, self.supi))

    def set_nas_queue(self, nas_queue):
        """ Set the NAS queue. """
        self._nas_queue = nas_queue

    def set_k_nas_int(self, k_nas_int):
        self.k_nas_int = k_nas_int

    def set_state(self, state):
        self.state_time = time.time()
        self.state = state
        
    # Print object
    def __str__(self) -> str:
        return f'UE( SUPI: {self.supi}, AMF UE NGAP ID: {self.amf_ue_ngap_id} )'
    def __repr__(self) -> str:
        return f'UE( SUPI: {self.supi}, AMF UE NGAP ID: {self.amf_ue_ngap_id}, k_nas_int: {hexlify(self.k_nas_int)}, k_nas_enc: {hexlify(self.k_nas_enc)}, k_amf: {hexlify(self.k_amf)}, k_ausf: {hexlify(self.k_ausf)}, k_seaf: {hexlify(self.k_seaf)}, k_nas_int: {hexlify(self.k_nas_int)}, k_nas_enc: {hexlify(self.k_nas_enc)} )'
    def __format__(self, format_spec: str) -> str:
        return f'UE( SUPI: {self.supi}, AMF UE NGAP ID: {self.amf_ue_ngap_id}, k_nas_int: {hexlify(self.k_nas_int)}, k_nas_enc: {hexlify(self.k_nas_enc)}, k_amf: {hexlify(self.k_amf)}, k_ausf: {hexlify(self.k_ausf)}, k_seaf: {hexlify(self.k_seaf)}, k_nas_int: {hexlify(self.k_nas_int)}, k_nas_enc: {hexlify(self.k_nas_enc)} )'

    
    

