from enum import IntEnum
from binascii import unhexlify, hexlify

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
        # if config is None set all values to None
        if config is None:
            self.supi = None
            self.amf_ue_ngap_id = None
            # initialise to zero in bytes
            self.k_nas_int = b'\x00' * 32
            self.k_nas_enc = b'\x00' * 32
            self.k_amf = b'\x00' * 32
            self.k_ausf = b'\x00' * 32
            self.k_seaf = b'\x00' * 32
            self.k_nas_int = b'\x00' * 32
            self.k_nas_enc = b'\x00' * 32
            self.mac_a = b'\x00' * 32
            self.mac_s = b'\x00' * 32
            self.xres_star = b'\x00' * 32
            self.xres = b'\x00' * 32
            self.res_star = b'\x00' * 32
            self.ue_capabilities = None
            self.ue_security_capabilities = None
            self.ue_network_capability = None
            self.nas_proc = None
            self.state = FGMMState.NULL
        else:   
            self.supi = config['supi']
            self.mcc = config['mcc']
            self.mnc = config['mnc']
            self.msin = config['supi'][-10:]
            self.key = config['key']
            self.op = config['op']
            self.op_type = config['op_type']
            self.amf = config['amf']
            self.imei = config['imei']
            self.imeiSv = config['imeiSv']
            self.tac = config['tac']
            self.sst = config['sst']
            sn_name = "5G:mnc{}.mcc{}.3gppnetwork.org".format(format(int(config['mnc']), '003d'), format(int(config['mcc']), '003d'))
            self.sn_name = sn_name.encode()
            self.nas_key_set = set()
            self.amf_ue_ngap_id = None
            self.sqn = b'\x00' * 32
            self.rand = b'\x00' * 32
            self.autn = b'\x00' * 32
            self.res = b'\x00' * 32
            self.k_amf = b'\x00' * 32
            self.k_ausf = b'\x00' * 32
            self.k_seaf = b'\x00' * 32
            self.k_nas_int = b'\x00' * 32
            self.k_nas_enc = b'\x00' * 32
            self.mac_a = b'\x00' * 32
            self.mac_s = b'\x00' * 32
            self.xres_star = b'\x00' * 32
            self.xres = b'\x00' * 32
            self.res_star = b'\x00' * 32
            self.ue_capabilities = None
            self.ue_security_capabilities = None
            self.ue_network_capability = None
            self.nas_proc = None
            self.nas_pdu = None
            self.state = FGMMState.NULL
    
    def initiate(self):
        """ Initiate the UE. """
        # Create NAS Registration Request
        self.nas_proc = 'REGISTRATION_REQUEST'

        tx_nas_pduprocess_nas_procedure(None, self)

    def process(self, data: bytes) -> bytes:
        """ Process the NAS message. """
        return process_nas_procedure(data, self)

    def send(self, data: bytes) -> bytes:
        # Put data on quene
        if data:
            # Send object with data and supi
            self._nas_queue.put((data, self.supi))

    def recv(self, data: bytes) -> bytes:
        """ Receive data from the socket. """
        pass

    def set_nas_queue(self, nas_queue):
        """ Set the NAS queue. """
        self._nas_queue = nas_queue

    def set_k_nas_int(self, k_nas_int):
        self.k_nas_int = k_nas_int
        
    # Print object
    def __str__(self) -> str:
        return f'UE( SUPI: {self.supi}, AMF UE NGAP ID: {self.amf_ue_ngap_id} )'
    def __repr__(self) -> str:
        return f'UE( SUPI: {self.supi}, AMF UE NGAP ID: {self.amf_ue_ngap_id}, k_nas_int: {hexlify(self.k_nas_int)}, k_nas_enc: {hexlify(self.k_nas_enc)}, k_amf: {hexlify(self.k_amf)}, k_ausf: {hexlify(self.k_ausf)}, k_seaf: {hexlify(self.k_seaf)}, k_nas_int: {hexlify(self.k_nas_int)}, k_nas_enc: {hexlify(self.k_nas_enc)} )'
    def __format__(self, format_spec: str) -> str:
        return f'UE( SUPI: {self.supi}, AMF UE NGAP ID: {self.amf_ue_ngap_id}, k_nas_int: {hexlify(self.k_nas_int)}, k_nas_enc: {hexlify(self.k_nas_enc)}, k_amf: {hexlify(self.k_amf)}, k_ausf: {hexlify(self.k_ausf)}, k_seaf: {hexlify(self.k_seaf)}, k_nas_int: {hexlify(self.k_nas_int)}, k_nas_enc: {hexlify(self.k_nas_enc)} )'

    
    

