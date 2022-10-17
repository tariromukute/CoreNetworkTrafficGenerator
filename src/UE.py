from typing import Set
from NAS import process_nas_procedure, RegistrationProc

class UE():
    """ UE class """

    def __init__(self, config) -> None:
        self.supi = config['supi']
        self.mcc = config['mcc']
        self.mnc = config['mnc']
        self.key = config['key']
        self.op = config['op']
        self.op_type = config['op_type']
        self.amf = config['amf']
        self.imei = config['imei']
        self.imeiSv = config['imeiSv']
        self.tac = config['tac']
        self.nas_key_set = Set()
        self.amf_ue_ngap_id = None
        self.sqn = None
        self.rand = None
        self.autn = None
        self.res = None
        self.k_amf = None
        self.k_ausf = None
        self.k_seaf = None
        self.k_nas_int = None
        self.k_nas_enc = None
        self.ck = None
        self.ik = None
        self.ak = None
        self.mac_a = None
        self.mac_s = None
        self.xres_star = None
        self.xres = None
        self.res_star = None
        self.ue_capabilities = None
        self.ue_security_capabilities = None
        self.ue_network_capability = None
        self.nas_proc = None
        self.nas_pdu = None
    
    def process(self, data: bytes) -> bytes:
        """ Process the NAS message. """
        return process_nas_procedure(data, self)

    def send(self, data: bytes) -> bytes:
        """ Send data to the socket. """
        pass

    def recv(self, data: bytes) -> bytes:
        """ Receive data from the socket. """
        pass

    
    

