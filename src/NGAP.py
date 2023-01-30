import struct
import time
from UE import UE
import logging
import threading
from SCTP import SCTPClient, SCTPServer
from NAS import process_nas_procedure, RegistrationProc
from pycrate_asn1dir import NGAP
from binascii import unhexlify, hexlify
from abc import ABC, ABCMeta, abstractmethod
from pycrate_mobile.NAS import *
from logging.handlers import QueueHandler
# import queue

from Proc import Proc

logger = logging.getLogger('__NGAP__')

def plmn_buf_to_str(buf):
    d = []
    [d.extend([0x30 + (b&0xf), 0x30+(b>>4)]) for b in buf]
    if d[3] == 0x3f:
        # filler, 5 digits MCC MNC
        del d[3]
    return bytes(d).decode()

def plmn_str_to_buf(s):
    s = s.encode()
    if len(s) == 5:
        return bytes([
            ((s[1]-0x30)<<4) + (s[0]-0x30),
                        0xf0 + (s[2]-0x30),
            ((s[4]-0x30)<<4) + (s[3]-0x30)])
    else:
        return bytes([
            ((s[1]-0x30)<<4) + (s[0]-0x30),
            ((s[3]-0x30)<<4) + (s[2]-0x30),
            ((s[5]-0x30)<<4) + (s[4]-0x30)])

# pLMNIdentity
# taC
# sST
class GNB():
    def __init__(self, logger_queue, server_config: dict,  ngap_dl_queue, ngap_ul_queue, nas_dl_queue, nas_ul_queue, ues_queue, ues) -> None:
        self.ues = ues # [None for i in range(100)] # A ctypes array contain the UEs that have been initialized
        self.ngap_dl_queue = ngap_dl_queue
        self.ngap_ul_queue = ngap_ul_queue
        self.nas_dl_queue = nas_dl_queue
        self.nas_ul_queue = nas_ul_queue
        self.ues_queue = ues_queue
        self.mcc = server_config['mcc']
        self.mnc = server_config['mnc']
        self.nci = server_config['nci']
        self.idLength = server_config['idLength']
        self.tac = server_config['tac'].to_bytes(3, 'big')
        self.slices = server_config['slices']
        self.pLMNIdentity = plmn_str_to_buf(server_config['mcc'] + server_config['mnc'])
        self.tAISliceSupportList = [{ 'sST': int(a['sst']).to_bytes(1, 'big'), 'sD': int(a['sd']).to_bytes(3, 'big') } for a in server_config['slices']]
        # add a handler that uses the shared queue
        logger.addHandler(QueueHandler(logger_queue))
        # log all messages, debug and up
        logger.setLevel(logging.INFO)

    def run(self) -> None:
        """ Run the gNB """
        logger.debug("Starting gNB")
        self.ngap_dl_thread = self._load_ngap_dl_thread(self._ngap_dl_thread_function)
        self.nas_dl_thread = self._load_nas_ul_thread(self._nas_ul_thread_function)
        self.ues_thread = self._load_ues_thread(self._ues_thread_function)
        # Wait for SCTP to be connected
        time.sleep(2)
        self.initiate()

    def initiate(self) -> None:
        # Send NGSetupRequest
        obj = {'plmn_identity': self.pLMNIdentity, 'tac': self.tac, 'nci': self.nci, 'tai_slice_support_list': self.tAISliceSupportList }
        ngSetupRequest = NGSetupProc()
        ngSetupRequest.initiate(obj)
        nGSetupPDU_APER = ngSetupRequest.get_pdu().to_aper()
        logger.debug("Sending NGSetupRequest to 5G Core with size: %d", len(nGSetupPDU_APER))
        self.ngap_ul_queue.put(nGSetupPDU_APER)
    
    def select_ngap_dl_procedure(self, procedure_code: int) -> Proc:
        return NGAPProcDispatcher[procedure_code](self)

    def select_ngap_ul_procedure(self, nas_name: int) -> Proc:
        logger.debug("Selecting NAS procedure: %s", nas_name)
        if nas_name == '5GMMRegistrationRequest':
            return NGInitialUEMessageProc(self)
        else:
            return NGUplinkNASTransportProc(self)

    def _load_ngap_dl_thread(self, ngap_dl_thread_function):
        """ Load the thread that will handle NGAP DownLink messages from 5G Core """
        ngap_dl_thread = threading.Thread(target=ngap_dl_thread_function)
        ngap_dl_thread.start()
        return ngap_dl_thread

    def _ngap_dl_thread_function(self) -> None:
        """ This thread function will read from queue and handle NGAP DownLink messages from 5G Core 
        
            It will then select the appropriate NGAP procedure to handle the message. Where the procedure
            returns an NAS PDU, it will be put in the queue to be sent to the UE
        """
        while True:
            if not self.ngap_dl_queue.empty():
                data = self.ngap_dl_queue.get()
                PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
                PDU.from_aper(data)
                procedureCode = PDU.get_val()[1]['procedureCode']
                ngap_proc = self.select_ngap_dl_procedure(procedureCode)
                ngap_pdu, nas_pdu, ue = ngap_proc.receive(PDU)
                if ue:
                    self.ues[int(ue.supi[-10:])] = ue
                if ngap_pdu:
                    self.ngap_ul_queue.put(ngap_pdu)
                if nas_pdu:
                    self.nas_dl_queue.put((nas_pdu, ue))
    
    def _load_nas_ul_thread(self, nas_ul_thread_function):
        """ Load the thread that will handle NAS UpLink messages from UE """
        nas_ul_thread = threading.Thread(target=nas_ul_thread_function)
        nas_ul_thread.start()
        return nas_ul_thread

    def _nas_ul_thread_function(self) -> None:
        """ This thread function will read from queue NAS UpLink messages from UE 

            It will then select the appropriate NGAP procedure to put the NAS message in
            and put the NGAP message in the queue to be sent to 5G Core
        """
        while True:
            if not self.nas_ul_queue.empty():
                data, ue = self.nas_ul_queue.get()
                ran_ue_ngap_id = int(ue.supi[-10:])
                PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
                Msg, err = parse_NAS5G(data)
                if err:
                    logger.error("Error parsing NAS message: %s", err)
                    continue
                amf_ue_ngap_id = self.get_ue(ran_ue_ngap_id).amf_ue_ngap_id
                obj = {'amf_ue_ngap_id': amf_ue_ngap_id, 'ran_ue_ngap_id': ran_ue_ngap_id, 'nas_pdu': Msg.to_bytes(), 'plmn_identity': self.pLMNIdentity, 'tac': self.tac, 'nci': self.nci }
                ngap_proc = self.select_ngap_ul_procedure(Msg._name)
                ngap_pdu = ngap_proc.send(Msg.to_bytes(), obj)
                if ngap_pdu:
                    # logging.info("Sent NAS message to 5G Core with size: %d", len(ngap_pdu))
                    self.ngap_ul_queue.put(ngap_pdu, block=False)
    
    def _load_ues_thread(self, ues_thread_function):
        """ Load the thread that will handle new UEs being added to gNB """
        ues_thread = threading.Thread(target=ues_thread_function)
        ues_thread.start()
        return ues_thread

    def _ues_thread_function(self) -> None:
        """ This thread function will read from queue and handle new UEs being added to gNB 
        
            It will then initiate the UE to start the registration procedure
        """
        while True:
            if not self.ues_queue.empty():
                ue = self.ues_queue.get()
                ran_ue_ngap_id = int(ue.supi[-10:])
                # TODO: Check if UE is already registered
                # if self.ues[ran_ue_ngap_id]:
                #     continue
                self.ues[ran_ue_ngap_id] = ue
                logger.debug("Registering UE: %s", ue)
                self.nas_dl_queue.put((None, ue))

    def get_ue(self, ran_ue_ngap_id):
        return self.ues[ran_ue_ngap_id]

    def get_ran_ue_ngap_id(self, ue):
        for ran_ue_ngap_id, ue in self.ues.items():
            if ue == ue:
                return ran_ue_ngap_id
        return None
    
    def remove_ue(self, ran_ue_ngap_id):
        del self.ues[ran_ue_ngap_id]

    def get_ues(self):
        return self.ues

    
# Create NGAP Procedure class
class NGAPProc(Proc, metaclass=ABCMeta):
    """ This class is the base class for all NGAP procedures."""
    def __init__(self, gNB: GNB, data: bytes = None):
        self.gNB = gNB
        super().__init__(data)

    def initiate(self, data: bytes = None) -> None:
        if data:
            self.PDU.from_aper(data)
        # TODO: Implement else clause

    def _load_procedure(self):
        return NGAP.NGAP_PDU_Descriptions.NGAP_PDU

    def get_procedure(self):
        return self.PDU.to_asn1()
    
    def set_pdu(self, data: bytes):
        if data:
            self.PDU.from_aper(unhexlify(data))

    def get_pdu(self):
        return self.PDU
    
    def get_procedure(self):
        return self.PDU.to_asn1()

    def set_pdu(self, data: bytes):
        if data:
            self.PDU.from_aper(unhexlify(data))

    def get_pdu(self):
        return self.PDU


# Create Non-UE Associated NGAP Procedure class
class NonUEAssociatedNGAPProc(NGAPProc, metaclass=ABCMeta):
    """ This class is the base class for all Non-UE Associated NGAP procedures."""
    def __init__(self, data: bytes = None):
        super().__init__(data)

    def _load_procedure(self):
        return NGAP.NGAP_PDU_Descriptions.NGAP_PDU

    def get_procedure(self):
        return self.PDU.to_asn1()

    def set_pdu(self, data: bytes):
        if data:
            self.PDU.from_aper(unhexlify(data))

    def get_pdu(self):
        return self.PDU

# Create UE Associated NGAP Procedure class
class UEAssociatedNGAPProc(NGAPProc, metaclass=ABCMeta):
    """ This class is the base class for all UE Associated NGAP procedures."""
    def __init__(self, data: bytes = None):
        super().__init__(data)

    def _load_procedure(self):
        return NGAP.NGAP_PDU_Descriptions.NGAP_PDU

    def get_procedure(self):
        return self.PDU.to_asn1()

    def set_pdu(self, data: bytes):
        if data:
            self.PDU.from_aper(unhexlify(data))

    def get_pdu(self):
        return self.PDU

# Create NG Setup Request class
class NGSetupProc(NonUEAssociatedNGAPProc):
    """NG Setup : TS 38.413, section 8.7.1
    
    gNB-initiated
    request-response
    non-UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 21: PagingDRX (M)
      - 27: GlobalRANNodeID (M)
      - 82: RANNodeName (O)
      - 102: SupportedTAList (M)
      - 147: UERetentionInformation (O)
    SuccessfulOutcome:
      IEs:
      - 1: AMFName (M)
      - 19: CriticalityDiagnostics (O)
      - 80: PLMNSupportList (M)
      - 86: RelativeAMFCapacity (M)
      - 96: ServedGUAMIList (M)
      - 147: UERetentionInformation (O)
    UnsuccessfulOutcome:
      IEs:
      - 15: Cause (M)
      - 19: CriticalityDiagnostics (O)
      - 107: TimeToWait (O)

    NG Setup Request: 
        IEs: (for ie in NGAP.NGAP_PDU_Contents.NGSetupRequestIEs().root: print(ie))
        {'id': 27, 'criticality': 'reject', 'Value': <Value ([GlobalRANNodeID] CHOICE)>, 'presence': 'mandatory'}
        {'id': 82, 'criticality': 'ignore', 'Value': <Value ([RANNodeName] PrintableString)>, 'presence': 'optional'}
        {'id': 102, 'criticality': 'reject', 'Value': <Value ([SupportedTAList] SEQUENCE OF)>, 'presence': 'mandatory'}
        {'id': 21, 'criticality': 'ignore', 'Value': <Value ([PagingDRX] ENUMERATED)>, 'presence': 'mandatory'}
        {'id': 147, 'criticality': 'ignore', 'Value': <Value ([UERetentionInformation] ENUMERATED)>, 'presence': 'optional'}
        {'id': 204, 'criticality': 'ignore', 'Value': <Value ([NB-IoT-DefaultPagingDRX] ENUMERATED)>, 'presence': 'optional'}
        {'id': 273, 'criticality': 'ignore', 'Value': <Value ([Extended-RANNodeName] SEQUENCE)>, 'presence': 'optional'}
    """
    def __init__(self, data: bytes = None):
        super().__init__(data)

    def initiate(self, obj, data: bytes = None) -> None:
        if data:
            self.PDU.from_aper(data)
        else:
            IEs = []
            IEs.append({'id': 27, 'criticality': 'reject', 'value': ('GlobalRANNodeID', ('globalGNB-ID', {'pLMNIdentity': obj['plmn_identity'], 'gNB-ID': ('gNB-ID', (1, 32))}))})
            IEs.append({'id': 82, 'criticality': 'ignore', 'value': ('RANNodeName', 'UERANSIM-gnb-208-95-1')})
            IEs.append({'id': 102, 'criticality': 'reject', 'value': ('SupportedTAList', [{'tAC': obj['tac'], 'broadcastPLMNList': [{'pLMNIdentity': obj['plmn_identity'], 'tAISliceSupportList': [ {'s-NSSAI': s } for s in obj['tai_slice_support_list'] ]}]}])})
            IEs.append({'id': 21, 'criticality': 'ignore', 'value': ('PagingDRX', 'v128')})
            val = ('initiatingMessage', {'procedureCode': 21, 'criticality': 'reject', 'value': ('NGSetupRequest', {'protocolIEs': IEs})})
            self.PDU.set_val(val)

    def receive(self, data: bytes = None) -> None:
        if data:
            # self.PDU.from_aper(data)
            # logging.debug(self.PDU.to_asn1())
            return None, None, None
        else:
            logger.error('No data received')
            return None, None, None

    def process(self, data) -> bytes:
        # TODO: Implement this method
        return b''


class NGInitialUEMessageProc(UEAssociatedNGAPProc):
    """Initial UE Message: TS 38.413, section 8.6.1
    
    RAN-initiatied
    request only
    UE-associated signalling procedure
    
    InitiatingMessage:
      IEs:
      - 0: AllowedNSSAI (O)
      - 3: AMFSetID (O)
      - 26: FiveG_S_TMSI (O)
      - 38: NAS_PDU (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 90: RRCEstablishmentCause (M)
      - 112: UEContextRequest (O)
      - 121: UserLocationInformation (M)
      - 171: SourceToTarget_AMFInformationReroute (O)

    Initial UE Message:
        IEs:
        {'id': 85, 'criticality': 'reject', 'Value': <Value ([RAN-UE-NGAP-ID] INTEGER)>, 'presence': 'mandatory'}
        {'id': 38, 'criticality': 'reject', 'Value': <Value ([NAS-PDU] OCTET STRING)>, 'presence': 'mandatory'}
        {'id': 121, 'criticality': 'reject', 'Value': <Value ([UserLocationInformation] CHOICE)>, 'presence': 'mandatory'}
        {'id': 90, 'criticality': 'ignore', 'Value': <Value ([RRCEstablishmentCause] ENUMERATED)>, 'presence': 'mandatory'}
        {'id': 26, 'criticality': 'reject', 'Value': <Value ([FiveG-S-TMSI] SEQUENCE)>, 'presence': 'optional'}
        {'id': 3, 'criticality': 'ignore', 'Value': <Value ([AMFSetID] BIT STRING)>, 'presence': 'optional'}
        {'id': 112, 'criticality': 'ignore', 'Value': <Value ([UEContextRequest] ENUMERATED)>, 'presence': 'optional'}
        {'id': 0, 'criticality': 'reject', 'Value': <Value ([AllowedNSSAI] SEQUENCE OF)>, 'presence': 'optional'}
        {'id': 171, 'criticality': 'ignore', 'Value': <Value ([SourceToTarget-AMFInformationReroute] SEQUENCE)>, 'presence': 'optional'}
        {'id': 174, 'criticality': 'ignore', 'Value': <Value ([PLMNIdentity] OCTET STRING)>, 'presence': 'optional'}
        {'id': 201, 'criticality': 'reject', 'Value': <Value ([IABNodeIndication] ENUMERATED)>, 'presence': 'optional'}
        {'id': 224, 'criticality': 'reject', 'Value': <Value ([CEmodeBSupport-Indicator] ENUMERATED)>, 'presence': 'optional'}
        {'id': 225, 'criticality': 'ignore', 'Value': <Value ([LTEM-Indication] ENUMERATED)>, 'presence': 'optional'}
        {'id': 227, 'criticality': 'ignore', 'Value': <Value ([EDT-Session] ENUMERATED)>, 'presence': 'optional'}
        {'id': 245, 'criticality': 'ignore', 'Value': <Value ([AuthenticatedIndication] ENUMERATED)>, 'presence': 'optional'}
        {'id': 259, 'criticality': 'reject', 'Value': <Value ([NPN-AccessInformation] CHOICE)>, 'presence': 'optional'}
    """

    def initiate(self, nas_pdu, id) -> None:
        # TODO: check if this is still needed
        IEs = []
        curTime = int(time.time()) + 2208988800 #1900 instead of 1970
        IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', id)}) # RAN-UE-NGAP-ID must be unique for each UE
        IEs.append({'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', nas_pdu) })
        IEs.append({'id': 121, 'criticality': 'reject', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': obj['plmn_identity'], 'nRCellIdentity': (16, 36)}, 'tAI': {'pLMNIdentity': obj['plmn_identity'], 'tAC': obj['tac']}, 'timeStamp': struct.pack("!I",curTime)}))})
        IEs.append({'id': 90, 'criticality': 'ignore', 'value': ('RRCEstablishmentCause', 'mo-Signalling')})
        IEs.append({'id': 112, 'criticality': 'ignore', 'value': ('UEContextRequest', 'requested')})
        val = ('initiatingMessage', {'procedureCode': 15, 'criticality': 'ignore', 'value': ('InitialUEMessage', {'protocolIEs': IEs})})
        self.PDU.set_val(val)

    def receive(self, data) -> None:
        """ Receive a message from the network """
        pass

    def send(self, data, obj) -> None:
        """ Send a message to the network """

        IEs = []
        curTime = int(time.time()) + 2208988800 #1900 instead of 1970
        IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', obj['ran_ue_ngap_id'])}) # RAN-UE-NGAP-ID must be unique for each UE
        IEs.append({'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', data) })
        IEs.append({'id': 121, 'criticality': 'reject', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': obj['plmn_identity'], 'nRCellIdentity': (16, 36)}, 'tAI': {'pLMNIdentity': obj['plmn_identity'], 'tAC': obj['tac']}, 'timeStamp': struct.pack("!I",curTime)}))})
        IEs.append({'id': 90, 'criticality': 'ignore', 'value': ('RRCEstablishmentCause', 'mo-Signalling')})
        IEs.append({'id': 112, 'criticality': 'ignore', 'value': ('UEContextRequest', 'requested')})
        val = ('initiatingMessage', {'procedureCode': 15, 'criticality': 'ignore', 'value': ('InitialUEMessage', {'protocolIEs': IEs})})
        
        PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        PDU.set_val(val)
        return PDU.to_aper()

    def process(self, data) -> bytes:
        # TODO: Implement this method
        return b''

class NGDownlinkNASTransportProc(UEAssociatedNGAPProc):
    """Downlink NAS Transport: TS 38.413, section 8.6.2

    CN-initiated
    request only
    UE-associated signalling procedure

    InitiatingMessage: (for ie in NGAP.NGAP_PDU_Contents.DownlinkNASTransport_IEs().root: print(ie))
      IEs:
      - 0: AllowedNSSAI (O)
      - 10: AMF_UE_NGAP_ID (M)
      - 31: IndexToRFSP (O)
      - 36: MobilityRestrictionList (O)
      - 38: NAS_PDU (M)
      - 48: AMFName (O)
      - 83: RANPagingPriority (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 110: UEAggregateMaximumBitRate (O)
    
    IEs:
        
    """

    def initiate(self, data: bytes = None) -> None:
        if data:
            self.PDU.from_aper(data)
        else:
            IEs = []
            curTime = int(time.time()) + 2208988800 #1900 instead of 1970
            IEs.append({'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', 1)})
            IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', 1)})
            IEs.append({'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', b'~\x00V\x02\x02\x00\x00!x\xc5\xaaS\xd1L*\xf6U\x97\n\x08\xacS\x88\xca \x10\xb5J\xbf[\x06\x88\x80\x00\x08\x88\xd4\xe3\xe4<!\xae')})
            val = ('initiatingMessage', {'procedureCode': 4, 'criticality': 'ignore', 'value': ('DownlinkNASTransport', {'protocolIEs': IEs})})
            self.PDU.set_val(val)

    def create_request(self, data) -> bytes:
        """ This is not applicable for the network traffic generator """
        pass

    def create_response(self, data) -> bytes:
        """ This is not applicable for the network traffic generator """
        pass
    
    def receive(self, PDU) -> None:
        # PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        # PDU.from_aper(data)
        # Extract IE values
        IEs = PDU.get_val()[1]['value'][1]['protocolIEs']
        # Extract AMF-UE-NGAP-ID
        amf_ue_ngap_id = next((ie['value'][1] for ie in IEs if ie['id'] == 10), None)
        # Extract RAN-UE-NGAP-ID
        ran_ue_ngap_id = next((ie['value'][1] for ie in IEs if ie['id'] == 85), None)
        # Extract the NAS PDU
        nas_pdu = next((ie['value'][1] for ie in IEs if ie['id'] == 38), None)
        if not nas_pdu:
            return None, None, None
        
        # Get UE
        ue = self.gNB.get_ue(ran_ue_ngap_id)
        # Set amf_ue_ngap_id
        ue.amf_ue_ngap_id = amf_ue_ngap_id
        # Send the NAS PDU to UE
        return None, nas_pdu, ue

class NGUplinkNASTransportProc(UEAssociatedNGAPProc):
    """Uplink NAS Transport: TS 38.413, section 8.6.3

    RAN-initiatied
    request only
    UE-associated signalling procedure
    
    InitiatingMessage: (for ie in NGAP.NGAP_PDU_Contents.NGSetupRequestIEs().root: print(ie))
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 38: NAS_PDU (M)
      - 85: RAN_UE_NGAP_ID (M)
      - 121: UserLocationInformation (M)

    IEs:

    """

    def initiate(self, data: bytes = None) -> None:
        # TODO: check if this is still needed
        if data:
            self.PDU.from_aper(data)
        else:
            IEs = []
            curTime = int(time.time()) + 2208988800 #1900 instead of 1970
            IEs.append({'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', 1)})
            IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', 1)})
            IEs.append({'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', b'~\x00W-\x10\xb3\x98--KE\x8b\xa3:\xe5\t\xf5\x00A\x10\xc5')})
            IEs.append({'id': 121, 'criticality': 'ignore', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': obj['plmn_identity'], 'nRCellIdentity': (16, 36)}, 'tAI': {'pLMNIdentity': obj['plmn_identity'], 'tAC': obj['tac']}, 'timeStamp': struct.pack("!I",curTime)}))})
            val = ('initiatingMessage', {'procedureCode': 46, 'criticality': 'ignore', 'value': ('UplinkNASTransport', {'protocolIEs': IEs})})
            self.PDU.set_val(val)

    def create_request(self, obj = None,  data: bytes = None) -> bytes:
        IEs = []
        curTime = int(time.time()) + 2208988800 #1900 instead of 1970
        amf_ue_ngap_id = obj['amf_ue_ngap_id'] if 'amf_ue_ngap_id' in obj else 1
        ran_ue_ngap_id = obj['ran_ue_ngap_id'] if 'ran_ue_ngap_id' in obj else 1
        nas_pdu = obj['nas_pdu'] if 'nas_pdu' in obj else b'~\x00W-\x10\xb3\x98--KE\x8b\xa3:\xe5\t\xf5\x00A\x10\xc5'
        IEs.append({'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', amf_ue_ngap_id)})
        IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', ran_ue_ngap_id)})
        IEs.append({'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', nas_pdu)})
        IEs.append({'id': 121, 'criticality': 'ignore', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': obj['plmn_identity'], 'nRCellIdentity': (16, 36)}, 'tAI': {'pLMNIdentity': obj['plmn_identity'], 'tAC': obj['tac']}, 'timeStamp': struct.pack("!I",curTime)}))})
        val = ('initiatingMessage', {'procedureCode': 46, 'criticality': 'ignore', 'value': ('UplinkNASTransport', {'protocolIEs': IEs})})
        PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        PDU.set_val(val)
        return PDU

    def receive(self, data):
        """ This is not applicable for the network traffic generator """
        return None, None, None
        
    def send(self, data, obj):
        IEs = []
        curTime = int(time.time()) + 2208988800 #1900 instead of 1970
        amf_ue_ngap_id = obj['amf_ue_ngap_id'] if 'amf_ue_ngap_id' in obj else 1
        ran_ue_ngap_id = obj['ran_ue_ngap_id'] if 'ran_ue_ngap_id' in obj else 1
        nas_pdu = obj['nas_pdu'] if 'nas_pdu' in obj else b'~\x00W-\x10\xb3\x98--KE\x8b\xa3:\xe5\t\xf5\x00A\x10\xc5'
        IEs.append({'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', amf_ue_ngap_id)})
        IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', ran_ue_ngap_id)})
        IEs.append({'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', nas_pdu)})
        IEs.append({'id': 121, 'criticality': 'ignore', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': { 'pLMNIdentity': obj['plmn_identity'], 'nRCellIdentity': (16, 36)}, 'tAI': {'pLMNIdentity': obj['plmn_identity'], 'tAC': obj['tac']}, 'timeStamp': struct.pack("!I",curTime)}))})
        val = ('initiatingMessage', {'procedureCode': 46, 'criticality': 'ignore', 'value': ('UplinkNASTransport', {'protocolIEs': IEs})})
        PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        PDU.set_val(val)
        return PDU.to_aper()
        
    def create_response(self, data: bytes = None) -> None:
        """ This is not applicable for the network traffic generator """
        pass

    def process(self, data) -> bytes:
        return b''

class NGInitialContextSetupProc(UEAssociatedNGAPProc):
    """Initial Context Setup: TS 38.413, section 8.3.1
    
    CN-initiated
    request-reponse
    UE-associated signalling procedure
    
    InitiatingMessage: (for ie in NGAP.NGAP_PDU_Contents.NGSetupRequestIEs().root: print(ie))
      IEs:
      - 0: AllowedNSSAI (M)
      - 10: AMF_UE_NGAP_ID (M)
      - 18: CoreNetworkAssistanceInformationForInactive (O)
      - 24: EmergencyFallbackIndicator (O)
      - 28: GUAMI (M)
      - 31: IndexToRFSP (O)
      - 33: LocationReportingRequestType (O)
      - 34: MaskedIMEISV (O)
      - 36: MobilityRestrictionList (O)
      - 38: NAS_PDU (O)
      - 48: AMFName (O)
      - 71: PDUSessionResourceSetupListCxtReq (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 91: RRCInactiveTransitionReportRequest (O)
      - 94: SecurityKey (M)
      - 108: TraceActivation (O)
      - 110: UEAggregateMaximumBitRate (C)
      - 117: UERadioCapability (O)
      - 118: UERadioCapabilityForPaging (O)
      - 119: UESecurityCapabilities (M)
      - 146: RedirectionVoiceFallback (O)
      - 165: CNAssistedRANTuning (O)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 55: PDUSessionResourceFailedToSetupListCxtRes (O)
      - 72: PDUSessionResourceSetupListCxtRes (O)
      - 85: RAN_UE_NGAP_ID (M)
    UnsuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 15: Cause (M)
      - 19: CriticalityDiagnostics (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 132: PDUSessionResourceFailedToSetupListCxtFail (O)
    """

    def initiate(self, data: bytes = None) -> None:
        if data:
            self.PDU.from_aper(data)
        else:
            IEs = []
            curTime = int(time.time()) + 2208988800 #1900 instead of 1970
            IEs.append({'id': 10, 'criticality': 'ignore', 'value': ('AMF-UE-NGAP-ID', 1)})
            IEs.append({'id': 85, 'criticality': 'ignore', 'value': ('RAN-UE-NGAP-ID', 1)})
            val = ('successfulOutcome', {'procedureCode': 14, 'criticality': 'reject', 'value': ('InitialContextSetupResponse', {'protocolIEs': IEs})})
            self.PDU.set_val(val)

    def create_request(self, data: bytes = None) -> None:
        """ This is not applicable for the core network traffic generator """
        pass

    def create_response(self, obj = None, data: bytes = None):
        amf_ue_ngap_id = obj['amf_ue_ngap_id'] if 'amf_ue_ngap_id' in obj else 1
        ran_ue_ngap_id = obj['ran_ue_ngap_id'] if 'ran_ue_ngap_id' in obj else 1
        PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        IEs = []
        curTime = int(time.time()) + 2208988800 #1900 instead of 1970
        IEs.append({'id': 10, 'criticality': 'ignore', 'value': ('AMF-UE-NGAP-ID', amf_ue_ngap_id)})
        IEs.append({'id': 85, 'criticality': 'ignore', 'value': ('RAN-UE-NGAP-ID', ran_ue_ngap_id)})
        val = ('successfulOutcome', {'procedureCode': 14, 'criticality': 'reject', 'value': ('InitialContextSetupResponse', {'protocolIEs': IEs})})
        PDU.set_val(val)
        return PDU.to_aper()

    def receive(self, PDU) -> bytes:
        # PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        # PDU.from_aper(data)
        # Extract IE values
        IEs = PDU.get_val()[1]['value'][1]['protocolIEs']
        # Extract AMF-UE-NGAP-ID
        amf_ue_ngap_id = next((ie['value'][1] for ie in IEs if ie['id'] == 10), None)
        # Extract RAN-UE-NGAP-ID
        ran_ue_ngap_id = next((ie['value'][1] for ie in IEs if ie['id'] == 85), None)
        # Extract the NAS PDU
        nas_pdu = next((ie['value'][1] for ie in IEs if ie['id'] == 38), None)
        ue = self.gNB.get_ue(ran_ue_ngap_id)
        
        ue.amf_ue_ngap_id = amf_ue_ngap_id
        
        obj = {'amf_ue_ngap_id': amf_ue_ngap_id, 'ran_ue_ngap_id': ran_ue_ngap_id }
        pdu = self.create_response(obj)
        return pdu, nas_pdu, ue

class NGPDUSessionResourceSetupProc(UEAssociatedNGAPProc):
    """PDU Session Resource Setup: TS 38.413, section 8.2.1
    
    CN-initiated
    request-response
    UE-associated signalling procedure
    
    InitiatingMessage: (for ie in NGAP.NGAP_PDU_Contents.NGSetupRequestIEs().root: print(ie))
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 38: NAS_PDU (O)
      - 74: PDUSessionResourceSetupListSUReq (M)
      - 83: RANPagingPriority (O)
      - 85: RAN_UE_NGAP_ID (M)
      - 110: UEAggregateMaximumBitRate (O)
    SuccessfulOutcome:
      IEs:
      - 10: AMF_UE_NGAP_ID (M)
      - 19: CriticalityDiagnostics (O)
      - 58: PDUSessionResourceFailedToSetupListSURes (O)
      - 75: PDUSessionResourceSetupListSURes (O)
      - 85: RAN_UE_NGAP_ID (M)
    """

    def initiate(self, data: bytes = None) -> None:
        if data:
            self.PDU.from_aper(data)
        else:
            IEs = []
            curTime = int(time.time()) + 2208988800 #1900 instead of 1970
            IEs.append({'id': 10, 'criticality': 'ignore', 'value': ('AMF-UE-NGAP-ID', 1)})
            IEs.append({'id': 85, 'criticality': 'ignore', 'value': ('RAN-UE-NGAP-ID', 1)})
            IEs.append({'id': 75, 'criticality': 'ignore', 'value': ('PDUSessionResourceSetupListSURes', [{'pDUSessionID': 1, 'pDUSessionResourceSetupResponseTransfer': ('PDUSessionResourceSetupResponseTransfer', {'dLQosFlowPerTNLInformation': {'uPTransportLayerInformation': ('gTPTunnel', {'transportLayerAddress': (3232292368, 32), 'gTP-TEID': b'\x00\x00\x00\x01'}), 'associatedQosFlowList': [{'qosFlowIdentifier': 8}]}})}])})
            val = ('successfulOutcome', {'procedureCode': 29, 'criticality': 'reject', 'value': ('PDUSessionResourceSetupResponse', {'protocolIEs': IEs})})
            self.PDU.set_val(val)
    def create_request(self, data: bytes = None) -> None:
        """ This is not applicable for the core network traffic generator """
        pass

    def create_response(self, data: bytes = None) -> None:
        IEs = []
        IEs.append({'id': 10, 'criticality': 'ignore', 'value': ('AMF-UE-NGAP-ID', 1)})
        IEs.append({'id': 85, 'criticality': 'ignore', 'value': ('RAN-UE-NGAP-ID', 1)})
        IEs.append({'id': 75, 'criticality': 'ignore', 'value': ('PDUSessionResourceSetupListSURes', [{'pDUSessionID': 1, 'pDUSessionResourceSetupResponseTransfer': ('PDUSessionResourceSetupResponseTransfer', {'dLQosFlowPerTNLInformation': {'uPTransportLayerInformation': ('gTPTunnel', {'transportLayerAddress': (3232292368, 32), 'gTP-TEID': b'\x00\x00\x00\x01'}), 'associatedQosFlowList': [{'qosFlowIdentifier': 8}]}})}])})
        val = ('successfulOutcome', {'procedureCode': 29, 'criticality': 'reject', 'value': ('PDUSessionResourceSetupResponse', {'protocolIEs': IEs})})
        self.PDU.set_val(val)

    def process(self, data) -> bytes:
        return b''

# Create Dispatcher for NGAP procedures
NGAPNonUEProcRANDispatcher = {
   
}

NGAPNonUEProcAMFDispatcher = {

}


NGAPProcDispatcher = {
    4 : NGDownlinkNASTransportProc,
    14 : NGInitialContextSetupProc,
    15 : NGInitialUEMessageProc,
    21 : NGSetupProc,
    29 : NGPDUSessionResourceSetupProc,
    46 : NGUplinkNASTransportProc,
}
