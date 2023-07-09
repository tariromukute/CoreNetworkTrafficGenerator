from multiprocessing import current_process
import struct
import time
from UE import UE
import logging
import threading
from SCTP import SCTPClient
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

def ng_setup_request(PDU, IEs, gNB):
    IEs.append({'id': 27, 'criticality': 'reject', 'value': ('GlobalRANNodeID', ('globalGNB-ID', {'pLMNIdentity': gNB.plmn_identity, 'gNB-ID': ('gNB-ID', (1, 32))}))})
    IEs.append({'id': 82, 'criticality': 'ignore', 'value': ('RANNodeName', 'UERANSIM-gnb-208-95-1')})
    IEs.append({'id': 102, 'criticality': 'reject', 'value': ('SupportedTAList', [{'tAC': gNB.tac, 'broadcastPLMNList': [{'pLMNIdentity': gNB.plmn_identity, 'tAISliceSupportList': [ {'s-NSSAI': s } for s in gNB.tai_slice_support_list ]}]}])})
    IEs.append({'id': 21, 'criticality': 'ignore', 'value': ('PagingDRX', 'v128')})
    val = ('initiatingMessage', {'procedureCode': 21, 'criticality': 'reject', 'value': ('NGSetupRequest', {'protocolIEs': IEs})})
    PDU.set_val(val)

def uplink_nas_transport(PDU, IEs, ue):
    IEs.append({'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', ue['amf_ue_ngap_id'])})
    IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', ue['ran_ue_ngap_id'])})
    val = ('initiatingMessage', {'procedureCode': 46, 'criticality': 'ignore', 'value': ('UplinkNASTransport', {'protocolIEs': IEs})})
    PDU.set_val(val)

def initial_ue_message(PDU, IEs, ue):
    IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', ue['ran_ue_ngap_id'])})
    IEs.append({'id': 90, 'criticality': 'ignore', 'value': ('RRCEstablishmentCause', 'mo-Signalling')})
    IEs.append({'id': 112, 'criticality': 'ignore', 'value': ('UEContextRequest', 'requested')})
    val = ('initiatingMessage', {'procedureCode': 15, 'criticality': 'ignore', 'value': ('InitialUEMessage', {'protocolIEs': IEs})})
    PDU.set_val(val)

def initial_context_setup_uplink(PDU, IEs, ue):
    IEs.append({'id': 10, 'criticality': 'ignore', 'value': ('AMF-UE-NGAP-ID', ue['amf_ue_ngap_id'])})
    IEs.append({'id': 85, 'criticality': 'ignore', 'value': ('RAN-UE-NGAP-ID', ue['ran_ue_ngap_id'])})
    val = ('successfulOutcome', {'procedureCode': 14, 'criticality': 'reject', 'value': ('InitialContextSetupResponse', {'protocolIEs': IEs})})
    PDU.set_val(val)

def initial_context_setup(PDU):
    # Extract IE values
    IEs = PDU.get_val()[1]['value'][1]['protocolIEs']
    # Extract AMF-UE-NGAP-ID
    amf_ue_ngap_id = next((ie['value'][1] for ie in IEs if ie['id'] == 10), None)
    # Extract RAN-UE-NGAP-ID
    ran_ue_ngap_id = next((ie['value'][1] for ie in IEs if ie['id'] == 85), None)
    # Extract the NAS PDU
    nas_pdu = next((ie['value'][1] for ie in IEs if ie['id'] == 38), None)
    IEs = []
    initial_context_setup_uplink(PDU, IEs, {'amf_ue_ngap_id': amf_ue_ngap_id, 'ran_ue_ngap_id': ran_ue_ngap_id })
    return PDU, nas_pdu, { 'ran_ue_ngap_id': ran_ue_ngap_id, 'amf_ue_ngap_id': amf_ue_ngap_id }

def downlink_nas_transport(PDU):
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

    return None, nas_pdu, { 'ran_ue_ngap_id': ran_ue_ngap_id, 'amf_ue_ngap_id': amf_ue_ngap_id }

def uplink_nas_transport(PDU, IEs, ue):
    IEs.append({'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', ue['amf_ue_ngap_id'])})
    IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', ue['ran_ue_ngap_id'])})
    val = ('initiatingMessage', {'procedureCode': 46, 'criticality': 'ignore', 'value': ('UplinkNASTransport', {'protocolIEs': IEs})})
    PDU.set_val(val)

downlink_mapper = {
    4: downlink_nas_transport,
    14: initial_context_setup,
}

# nonue_uplink_mapper = {
#     '5GMMAuthenticationRequest': authentication_response,
#     '5GMMRegistrationAccept': registration_complete,
#     '5GMMSecurityModeCommand': security_mode_complete
# }

ue_uplink_mapper = {
    '5GMMRegistrationRequest': initial_ue_message,
}


class GNB():
    def __init__(self, sctp: SCTPClient, server_config: dict, ngap_to_ue, ue_to_ngap) -> None:
        self.ues = {} # key -> ran_ue_ngap_id = ue.supi[-10:], value -> amf_ue_ngap_id assigned by core network
        self.sctp = sctp
        self.ngap_to_ue = ngap_to_ue
        self.ue_to_ngap = ue_to_ngap
        self.mcc = server_config['mcc']
        self.mnc = server_config['mnc']
        self.nci = server_config['nci']
        self.id_length = server_config['idLength']
        self.tac = server_config['tac'].to_bytes(3, 'big')
        self.slices = server_config['slices']
        self.plmn_identity = plmn_str_to_buf(server_config['mcc'] + server_config['mnc'])
        # Foe each slice, create a list of TAI Slice Support. sd is optional
        self.tai_slice_support_list = []
        for a in server_config['slices']:
            tAISliceSupport = {}
            tAISliceSupport['sST'] = int(a['sst']).to_bytes(1, 'big')
            if 'sd' in a:
                tAISliceSupport['sD'] = int(a['sd']).to_bytes(3, 'big')
            self.tai_slice_support_list.append(tAISliceSupport)

    def run(self) -> None:
        """ Run the gNB """
        logger.debug("Starting gNB")
        self.ngap_to_ue_thread = self._load_ngap_to_ue_thread(self._ngap_to_ue_thread_function)
        self.nas_dl_thread = self._load_ue_to_ngap_thread(self._ue_to_ngap_thread_function)
        # Wait for SCTP to be connected
        time.sleep(2)
        self.initiate()

    def initiate(self) -> None:
        # Send NGSetupRequest
        IEs = []
        PDU = PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        ng_setup_request(PDU, IEs, self)
        ng_setup_pdu_aper = PDU.to_aper()
        logger.debug("Sending NGSetupRequest to 5G Core with size: %d", len(ng_setup_pdu_aper))
        self.sctp.send(ng_setup_pdu_aper)
    
    def _load_ngap_to_ue_thread(self, ngap_to_ue_thread_function):
        """ Load the thread that will handle NGAP DownLink messages from 5G Core """
        ngap_to_ue_thread = threading.Thread(target=ngap_to_ue_thread_function)
        ngap_to_ue_thread.start()
        return ngap_to_ue_thread

    def _ngap_to_ue_thread_function(self) -> None:
        """ This thread function will read from queue and handle NGAP DownLink messages from 5G Core 
        
            It will then select the appropriate NGAP procedure to handle the message. Where the procedure
            returns an NAS PDU, it will be put in the queue to be sent to the UE
        """
        
        while True:
            data = self.sctp.recv()
            if data:
                PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
                PDU.from_aper(data)
                procedureCode = PDU.get_val()[1]['procedureCode']
                procedure_func = downlink_mapper.get(procedureCode)
                if not procedure_func:
                    logger.info(f"Received downlink procedure {procedureCode} without handler mapped to it")
                    continue
                ngap_pdu, nas_pdu, ue_ = procedure_func(PDU)
                if ue_:
                    self.ues[ue_['ran_ue_ngap_id']] = ue_['amf_ue_ngap_id']
                if ngap_pdu:
                    self.sctp.send(ngap_pdu.to_aper())
                if nas_pdu:
                    self.ngap_to_ue.send((nas_pdu, ue_['ran_ue_ngap_id']))
    
    def _load_ue_to_ngap_thread(self, ue_to_ngap_thread_function):
        """ Load the thread that will handle NAS UpLink messages from UE """
        ue_to_ngap_thread = threading.Thread(target=ue_to_ngap_thread_function)
        ue_to_ngap_thread.start()
        return ue_to_ngap_thread

    def _ue_to_ngap_thread_function(self) -> None:
        """ This thread function will read from queue NAS UpLink messages from UE 

            It will then select the appropriate NGAP procedure to put the NAS message in
            and put the NGAP message in the queue to be sent to 5G Core
        """
        while True:
            data, ran_ue_ngap_id = self.ngap_to_ue.recv()
            if data:
                # ran_ue_ngap_id = int(ue.supi[-10:])
                Msg, err = parse_NAS5G(data)
                if err:
                    logger.error("Error parsing NAS message: %s", err)
                    continue
                amf_ue_ngap_id = self.ues.get(ran_ue_ngap_id)
                PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
                IEs = []
                curTime = int(time.time()) + 2208988800 #1900 instead of 1970
                IEs.append({'id': 121, 'criticality': 'ignore', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': self.plmn_identity, 'nRCellIdentity': (16, 36)}, 'tAI': {'pLMNIdentity': self.plmn_identity, 'tAC': self.tac }, 'timeStamp': struct.pack("!I",curTime)}))})
                IEs.append({'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', Msg.to_bytes())})
                procedure_func = ue_uplink_mapper.get(Msg._name)
                if not procedure_func:
                    procedure_func = uplink_nas_transport
                procedure_func(PDU, IEs, {'amf_ue_ngap_id': amf_ue_ngap_id, 'ran_ue_ngap_id': ran_ue_ngap_id })

                self.sctp.send(PDU.to_aper())

    def get_ue(self, ran_ue_ngap_id):
        return self.ues[ran_ue_ngap_id]
    
    def remove_ue(self, ran_ue_ngap_id) -> None:
        del self.ues[ran_ue_ngap_id]

    def get_ues(self):
        return self.ues