from NAS import process_nas_procedure

class UE():
    """ UE class """

    def __init__(self, config) -> None:
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
        self.nas_key_set = set()
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
        self._nas_queue = None
    
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
    def __repr__(self) -> str:
        return f'UE( SUPI: {self.supi}, AMF UE NGAP ID: {self.amf_ue_ngap_id}, k_nas_int: {self.k_nas_int}, k_nas_enc: {self.k_nas_enc}, k_amf: {self.k_amf}, k_ausf: {self.k_ausf}, k_seaf: {self.k_seaf}, k_nas_int: {self.k_nas_int}, k_nas_enc: {self.k_nas_enc}, ck: {self.ck}, ik: {self.ik}, ak: {self.ak}, mac_a: {self.mac_a}, mac_s: {self.mac_s}, xres_star: {self.xres_star}, xres: {self.xres}, res_star: {self.res_star}, ue_capabilities: {self.ue_capabilities}, ue_security_capabilities: {self.ue_security_capabilities}, ue_network_capability: {self.ue_network_capability} )'

    
    

