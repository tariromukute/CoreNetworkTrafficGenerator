import struct
import time
import logging
import threading
import sys
import socket
from src.SCTP import SCTPClient
from src.GTPU import GTPU
from pycrate_asn1dir import NGAP
from pycrate_mobile.NAS import parse_NAS5G
from pycrate_core import utils_py3

logger = logging.getLogger('__NGAPSim__')

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
gtpIp = '127.0.0.1'
def ng_setup_request(PDU, IEs, gNB):
    IEs.append({'id': 27, 'criticality': 'reject', 'value': ('GlobalRANNodeID', ('globalGNB-ID', {'pLMNIdentity': gNB.plmn_identity, 'gNB-ID': ('gNB-ID', (1, 32))}))})
    IEs.append({'id': 82, 'criticality': 'ignore', 'value': ('RANNodeName', 'CNTG-gnb-208-95-1')})
    IEs.append({'id': 102, 'criticality': 'reject', 'value': ('SupportedTAList', [{'tAC': gNB.tac, 'broadcastPLMNList': [{'pLMNIdentity': gNB.plmn_identity, 'tAISliceSupportList': [ {'s-NSSAI': s } for s in gNB.tai_slice_support_list ]}]}])})
    IEs.append({'id': 21, 'criticality': 'ignore', 'value': ('PagingDRX', 'v128')})
    val = ('initiatingMessage', {'procedureCode': 21, 'criticality': 'reject', 'value': ('NGSetupRequest', {'protocolIEs': IEs})})
    PDU.set_val(val)

def uplink_nas_transport(PDU, IEs, ue, gnb):
    curTime = int(time.time()) + 2208988800 #1900 instead of 1970
    IEs.append({'id': 121, 'criticality': 'ignore', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': gnb.plmn_identity, 'nRCellIdentity': (16, 36)}, 'tAI': {'pLMNIdentity': gnb.plmn_identity, 'tAC': gnb.tac }, 'timeStamp': struct.pack("!I",curTime)}))})
    IEs.append({'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', ue['amf_ue_ngap_id'])})
    IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', ue['ran_ue_ngap_id'])})
    val = ('initiatingMessage', {'procedureCode': 46, 'criticality': 'ignore', 'value': ('UplinkNASTransport', {'protocolIEs': IEs})})
    PDU.set_val(val)

def initial_ue_message(PDU, IEs, ue, gnb):
    curTime = int(time.time()) + 2208988800 #1900 instead of 1970
    IEs.append({'id': 121, 'criticality': 'reject', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': gnb.plmn_identity, 'nRCellIdentity': (16, 36)}, 'tAI': {'pLMNIdentity': gnb.plmn_identity, 'tAC': gnb.tac }, 'timeStamp': struct.pack("!I",curTime)}))})
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

def pdu_session_resource_response(PDU, IEs, ue):
    IEs.append({'id': 10, 'criticality': 'ignore', 'value': ('AMF-UE-NGAP-ID', ue['amf_ue_ngap_id'])})
    IEs.append({'id': 85, 'criticality': 'ignore', 'value': ('RAN-UE-NGAP-ID', ue['ran_ue_ngap_id'])})
    pdu = {'pDUSessionID': ue['pdu_session_id'], 'pDUSessionResourceSetupResponseTransfer': ('PDUSessionResourceSetupResponseTransfer', {'dLQosFlowPerTNLInformation': {'uPTransportLayerInformation': ue['up_transport_layer_information'], 'associatedQosFlowList': [{'qosFlowIdentifier': ue['qos_identifier']}] }} ) }
    IEs.append({ 'id': 75, 'criticality': 'ignore', 'value': ('PDUSessionResourceSetupListSURes', [ pdu ])})
    val = ('successfulOutcome', {'procedureCode': 29, 'criticality': 'reject', 'value': ('PDUSessionResourceSetupResponse', {'protocolIEs': IEs})})
    PDU.set_val(val)

def ue_connection_release_complete(PDU, IEs, ue):
    IEs.append({'id': 10, 'criticality': 'ignore', 'value': ('AMF-UE-NGAP-ID', ue['amf_ue_ngap_id'])})
    IEs.append({'id': 85, 'criticality': 'ignore', 'value': ('RAN-UE-NGAP-ID', ue['ran_ue_ngap_id'])})
    val = ('successfulOutcome', {'procedureCode': 41, 'criticality': 'reject', 'value': ('UEContextReleaseComplete', {'protocolIEs': IEs})})
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

def pdu_session_resource_setup(PDU):
    IEs = PDU.get_val()[1]['value'][1]['protocolIEs']
    # Extract AMF-UE-NGAP-ID
    amf_ue_ngap_id = next((ie['value'][1] for ie in IEs if ie['id'] == 10), None)
    # Extract RAN-UE-NGAP-ID
    ran_ue_ngap_id = next((ie['value'][1] for ie in IEs if ie['id'] == 85), None)
    # Extract the NAS PDU
    pdu_session_resource_setup_list_su_req = next((ie['value'][1] for ie in IEs if ie['id'] == 74), None)
    # TODO: handle multple pdu_session_nas_pdu 
    pduIEs = pdu_session_resource_setup_list_su_req[0]['pDUSessionResourceSetupRequestTransfer'][1]['protocolIEs']
    ul_up_transport_layer_information = next((ie['value'][1] for ie in pduIEs if ie['id'] == 139), None)
    # TODO: handle mulitple QOS identifiers
    qos_identifiers = next((ie['value'][1] for ie in pduIEs if ie['id'] == 136), None)
    pdu_session_nas_pdu = pdu_session_resource_setup_list_su_req[0]['pDUSessionNAS-PDU']
    dl_up_transport_layer_information = ('gTPTunnel', {'transportLayerAddress': (utils_py3.bytes_to_uint(socket.inet_aton(gtpIp), 32), 32), 'gTP-TEID': utils_py3.uint_to_bytes(ran_ue_ngap_id, 32) })
    IEs = []
    # TODO: compose up_transport_layer_information
    pdu_session_resource_response(PDU, IEs, {'amf_ue_ngap_id': amf_ue_ngap_id, 'ran_ue_ngap_id': ran_ue_ngap_id,
                                             'pdu_session_id': pdu_session_resource_setup_list_su_req[0]['pDUSessionID'],
                                            'up_transport_layer_information': dl_up_transport_layer_information,
                                            'qos_identifier': qos_identifiers[0]['qosFlowIdentifier'] })
    # # TODO: implement the setup logic

    return PDU, pdu_session_nas_pdu, { 'ran_ue_ngap_id': ran_ue_ngap_id, 'amf_ue_ngap_id': amf_ue_ngap_id,
                                      'qos_identifier': qos_identifiers[0]['qosFlowIdentifier'],
                                       'ul_up_transport_layer_information': ul_up_transport_layer_information,
                                        'dl_up_transport_layer_information': dl_up_transport_layer_information }

def ue_connection_release_command(PDU):
    IEs = PDU.get_val()[1]['value'][1]['protocolIEs']
    # Extract AMF-UE-NGAP-ID and RAN-UE-NGAP-ID
    # TODO: handle multiple ids
    ue_ngap_ids = next((ie['value'][1] for ie in IEs if ie['id'] == 114), None)
    amf_ue_ngap_id = ue_ngap_ids[1]['aMF-UE-NGAP-ID']
    ran_ue_ngap_id = ue_ngap_ids[1]['rAN-UE-NGAP-ID']

    IEs = []
    ue_connection_release_complete(PDU, IEs, {'amf_ue_ngap_id': amf_ue_ngap_id, 'ran_ue_ngap_id': ran_ue_ngap_id})
    return PDU, b'F', { 'ran_ue_ngap_id': ran_ue_ngap_id, 'amf_ue_ngap_id': amf_ue_ngap_id }

# The procedure codes are defined in pycrate_asn1dir/3GPP_NR_NGAP_38413/NGAP-Constants.asn
downlink_mapper = {
    4: downlink_nas_transport,
    14: initial_context_setup,
    29: pdu_session_resource_setup,
    41: ue_connection_release_command,
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
    exit_flag = False

    def __init__(self, sctp: SCTPClient, server_config: dict, ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, verbose) -> None:
        global logger
        # Set logging level based on the verbose argument
        if verbose == 0:
            logging.basicConfig(level=logging.ERROR)
        elif verbose == 1:
            logging.basicConfig(level=logging.WARNING)
        elif verbose == 2:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.DEBUG)
        global gtpIp
        gtpIp = server_config['gtpIp']
        self.gtpu = GTPU({ 'gtpIp': gtpIp, 'fgcMac': server_config['fgcMac'] }, upf_to_ue, verbose=verbose >= 2)
        self.ues = {} # key -> ran_ue_ngap_id = { amf_ue_ngap_id: ue.supi[-10:], qfi,  ul_teid, dl_teid }, value -> amf_ue_ngap_id assigned by core network
        self.sctp = sctp
        self.ngap_to_ue = ngap_to_ue
        self.ue_to_ngap = ue_to_ngap
        self.upf_to_ue = upf_to_ue
        self.ue_to_upf = ue_to_upf
        self.verbose = verbose
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
        self.ue_up_thread = self._load_ue_to_upf_thread(self._ue_to_upf_thread_function)
        # Wait for SCTP to be connected
        time.sleep(2)
        self.initiate()

    def initiate(self) -> None:
        # Send NGSetupRequest
        IEs = []
        PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        ng_setup_request(PDU, IEs, self)
        ng_setup_pdu_aper = PDU.to_aper()
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
        
        while not GNB.exit_flag:
            try:
                data = self.sctp.recv()
                if data:
                    PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
                    PDU.from_aper(data)
                    procedureCode = PDU.get_val()[1]['procedureCode']
                    procedure_func = downlink_mapper.get(procedureCode)
                    if not procedure_func:
                        logger.debug(f"Received downlink procedure {procedureCode} without handler mapped to it")
                        continue
                    ngap_pdu, nas_pdu, ue_ = procedure_func(PDU)
                        
                    if ue_:
                        if not ue_['ran_ue_ngap_id'] in self.ues:
                            self.ues[ue_['ran_ue_ngap_id']] = { 'amf_ue_ngap_id': ue_['amf_ue_ngap_id'] }
                        self.ues[ue_['ran_ue_ngap_id']]['amf_ue_ngap_id'] = ue_['amf_ue_ngap_id']
                        if ue_.get('qos_identifier'):
                            ul_teid = utils_py3.bytes_to_uint(ue_['ul_up_transport_layer_information'][1]['gTP-TEID'], 32)
                            dl_teid = utils_py3.bytes_to_uint(ue_['dl_up_transport_layer_information'][1]['gTP-TEID'], 32)
                            upf_address = socket.inet_ntoa(utils_py3.uint_to_bytes(ue_['ul_up_transport_layer_information'][1]['transportLayerAddress'][0], 32))
                            logger.info(f"UE {ue_['ran_ue_ngap_id']} PDU resource setup QOS id: {ue_['qos_identifier']} UL Address: {upf_address} UL teid {ul_teid} DL teid {dl_teid}")
                            self.ues[ue_['ran_ue_ngap_id']]['qfi'] = ue_['qos_identifier']
                            self.ues[ue_['ran_ue_ngap_id']]['ul_teid'] = ul_teid
                            self.ues[ue_['ran_ue_ngap_id']]['dl_teid'] = dl_teid
                            self.ues[ue_['ran_ue_ngap_id']]['upf_address'] = upf_address
                    if ngap_pdu:
                        self.sctp.send(ngap_pdu.to_aper())
                    if nas_pdu:
                        self.ngap_to_ue.send((nas_pdu, ue_['ran_ue_ngap_id']))
            except:
                # IF error occurs, likely from SCTP end program
                GNB.exit_flag = True
    
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
        while not GNB.exit_flag:
            try:
                data, ran_ue_ngap_id = self.ngap_to_ue.recv()
                if data:
                    # ran_ue_ngap_id = int(ue.supi[-10:])
                    Msg, err = parse_NAS5G(data)
                    if err:
                        logger.error("Error parsing NAS message: %s", err)
                        continue
                    amf_ue_ngap_id = self.ues.get(ran_ue_ngap_id).get('amf_ue_ngap_id') if self.ues.get(ran_ue_ngap_id) else None
                    PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
                    IEs = []
                    IEs.append({'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', Msg.to_bytes())})
                    procedure_func = ue_uplink_mapper.get(Msg._name)
                    if not procedure_func:
                        procedure_func = uplink_nas_transport
                    procedure_func(PDU, IEs, {'amf_ue_ngap_id': amf_ue_ngap_id, 'ran_ue_ngap_id': ran_ue_ngap_id }, self)

                    self.sctp.send(PDU.to_aper())
            except:
                # IF error occurs, likely from SCTP end program
                GNB.exit_flag = True

    def _load_ue_to_upf_thread(self, ue_to_upf_thread_function):
        """ Load the thread that will handle NAS UpLink messages from UE """
        ue_to_upf_thread = threading.Thread(target=ue_to_upf_thread_function)
        ue_to_upf_thread.start()
        return ue_to_upf_thread
    
    def _ue_to_upf_thread_function(self) -> None:
        """ This thread function will read from queue NAS UpLink messages from UE 

            It will then select the appropriate NGAP procedure to put the NAS message in
            and put the NGAP message in the queue to be sent to 5G Core
        """
        while not GNB.exit_flag:
            try:
                data, ran_ue_ngap_id = self.upf_to_ue.recv()
                if data:
                    # ran_ue_ngap_id = int(ue.supi[-10:])
                    ue = self.ues.get(ran_ue_ngap_id)
                    
                    self.gtpu.send(ue, data)
            except:
                GNB.exit_flag = True

    def get_ue(self, ran_ue_ngap_id):
        return self.ues[ran_ue_ngap_id]
    
    def remove_ue(self, ran_ue_ngap_id) -> None:
        del self.ues[ran_ue_ngap_id]

    def get_ues(self):
        return self.ues

    def stop(self):
        print("Stopping gnb")

    def __str__(self):
        return f"<NGAP mcc={self.mcc}, mnc={self.mnc}, nci={self.nci}, id_length={self.id_length}>"