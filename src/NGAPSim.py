import struct
import time
import logging
import threading
import sys
import socket
from src import ngapfast
from src.SCTP import SCTPClient
from src.userplane import Session
from src.ranlink import (CONNECT, DL_NAS, KIND_NAMES, RELEASE, UL_NAS, UP_CONTROL, UP_SESSION, LinkClosed,
                         LinkStopped, parse_connect, parse_up_control)
# The UE simulator now picks CONNECT (an Initial UE Message) or UL_NAS with this predicate
from src.ranlink import FGMM_EPD, FGMM_REGISTRATION_REQUEST, is_plain_registration_request  # noqa: F401
from pycrate_asn1dir import NGAP
from pycrate_core import utils_py3
import os
import psutil
import multiprocessing

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

def nr_cell_identity(gnb):
    """ The gNB's one cell: a 36-bit NR Cell Identity whose leftmost 32 bits are the gNB ID (TS 38.413 §9.3.1.7) """
    return gnb.gnb_id << 4

def ng_setup_request(PDU, IEs, gNB):
    IEs.append({'id': 27, 'criticality': 'reject', 'value': ('GlobalRANNodeID', ('globalGNB-ID', {'pLMNIdentity': gNB.plmn_identity, 'gNB-ID': ('gNB-ID', (gNB.gnb_id, 32))}))})
    IEs.append({'id': 82, 'criticality': 'ignore', 'value': ('RANNodeName', f'CNTG-gnb-{gNB.mcc}-{gNB.mnc}-{gNB.gnb_id}')})
    IEs.append({'id': 102, 'criticality': 'reject', 'value': ('SupportedTAList', [{'tAC': gNB.tac, 'broadcastPLMNList': [{'pLMNIdentity': gNB.plmn_identity, 'tAISliceSupportList': [ {'s-NSSAI': s } for s in gNB.tai_slice_support_list ]}]}])})
    IEs.append({'id': 21, 'criticality': 'ignore', 'value': ('PagingDRX', 'v128')})
    val = ('initiatingMessage', {'procedureCode': 21, 'criticality': 'reject', 'value': ('NGSetupRequest', {'protocolIEs': IEs})})
    PDU.set_val(val)

def uplink_nas_transport(PDU, IEs, ue, gnb):
    curTime = int(time.time()) + 2208988800 #1900 instead of 1970
    IEs.append({'id': 121, 'criticality': 'ignore', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': gnb.plmn_identity, 'nRCellIdentity': (nr_cell_identity(gnb), 36)}, 'tAI': {'pLMNIdentity': gnb.plmn_identity, 'tAC': gnb.tac }, 'timeStamp': struct.pack("!I",curTime)}))})
    IEs.append({'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', ue['amf_ue_ngap_id'])})
    IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', ue['ran_ue_ngap_id'])})
    val = ('initiatingMessage', {'procedureCode': 46, 'criticality': 'ignore', 'value': ('UplinkNASTransport', {'protocolIEs': IEs})})
    PDU.set_val(val)

# RRCEstablishmentCause (TS 38.413 §9.3.1.111), in the order of its enumeration: the cause in a CONNECT
RRC_ESTABLISHMENT_CAUSES = ('emergency', 'highPriorityAccess', 'mt-Access', 'mo-Signalling', 'mo-Data',
                            'mo-VoiceCall', 'mo-VideoCall', 'mo-SMS', 'mps-PriorityAccess', 'mcs-PriorityAccess')

def initial_ue_message(PDU, IEs, ue, gnb):
    """ ue: the UE's RAN UE NGAP ID, and from its CONNECT the establishment cause (an index into
    RRC_ESTABLISHMENT_CAUSES, mo-Signalling if none) and its 5G-S-TMSI (6 octets) if it has one """
    curTime = int(time.time()) + 2208988800 #1900 instead of 1970
    IEs.append({'id': 121, 'criticality': 'reject', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': gnb.plmn_identity, 'nRCellIdentity': (nr_cell_identity(gnb), 36)}, 'tAI': {'pLMNIdentity': gnb.plmn_identity, 'tAC': gnb.tac }, 'timeStamp': struct.pack("!I",curTime)}))})
    IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', ue['ran_ue_ngap_id'])})
    IEs.append({'id': 90, 'criticality': 'ignore', 'value': ('RRCEstablishmentCause', RRC_ESTABLISHMENT_CAUSES[ue.get('cause', 3)])})
    s_tmsi = ue.get('s_tmsi')
    if s_tmsi:
        # AMF Set ID (10 bits), AMF Pointer (6 bits), 5G-TMSI (TS 23.003 §2.11)
        set_pointer = int.from_bytes(s_tmsi[:2], 'big')
        IEs.append({'id': 26, 'criticality': 'reject', 'value': ('FiveG-S-TMSI', {
            'aMFSetID': (set_pointer >> 6, 10), 'aMFPointer': (set_pointer & 0x3F, 6), 'fiveG-TMSI': bytes(s_tmsi[2:6])})})
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
                                      'pdu_session_id': pdu_session_resource_setup_list_su_req[0]['pDUSessionID'],
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
    # No NAS PDU: the gNB tells the UE simulator with a RELEASE
    return PDU, None, { 'ran_ue_ngap_id': ran_ue_ngap_id, 'amf_ue_ngap_id': amf_ue_ngap_id }

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

import threading

# Create a lock object
ngap_to_ue_lock = threading.Lock()
# NGAP.NGAP_PDU_Descriptions.NGAP_PDU is one shared, stateful ASN.1 object: setting or decoding a
# value and encoding it must not interleave between threads, or one thread encodes the other's
# message (one UE's message is sent twice, another's never).
ngap_pdu_lock = threading.Lock()
# One thread per direction keeps each UE's NGAP messages in order (NAS COUNT, procedure order);
# encoding and decoding are serialised by ngap_pdu_lock and the GIL anyway.
num_threads = 1
class GNB():
    """ The gNB adapter: NGAP towards the AMF for the UEs of one or more UE simulators, each on a
    UE-RAN link of its own (src/ranlink.py). A UE's id on its link is its RAN UE NGAP ID.

    With ngap_fastpath (the default), the NGAP messages of a registration and a UE context release
    are built from byte templates and the downlink ones parsed without pycrate (src/ngapfast.py);
    what the fast path does not cover, and every message when messages are logged (debug), goes
    through pycrate as before. """

    ngap_fastpath = True

    def __init__(self, gnb_exit_flag, sctp: SCTPClient, userplane, server_config: dict, links, verbose, gnb_index=0,
                 ngap_fastpath=True) -> None:
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
        self.exit_flag = gnb_exit_flag
        self.ngap_fastpath = ngap_fastpath
        global gtpIp
        gtpIp = server_config['gtpIp']
        self.userplane = userplane  # src.userplane.UserPlane: the sessions' traffic
        self.ues = {} # key -> ran_ue_ngap_id = { amf_ue_ngap_id: ue.supi[-10:], qfi,  ul_teid, dl_teid }, value -> amf_ue_ngap_id assigned by core network
        # A UE's uplink send times not yet returned to the UE simulator: [(message code, time), ...]
        self.ul_sent = {}
        self.ul_sent_lock = threading.Lock()
        self.sctp = sctp
        # The gNB's ends (UeLinks) of the links to its UE simulators, and the link each UE came on: a
        # RAN UE NGAP ID belongs to one link, so the UE's downlink messages go back on it
        self.links = list(links) if isinstance(links, (list, tuple)) else [links]
        self.ue_links = {}
        self.clashes = set()   # RAN UE NGAP IDs that came on two links
        self.waiter = None
        self.verbose = verbose
        self.mcc = server_config['mcc']
        self.mnc = server_config['mnc']
        # Each gNB process is a gNB of its own on its own association: gNB IDs 1, 2, ...
        self.gnb_id = 1 + gnb_index
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

    def run(self, cpu_core) -> None:
        """ Run the gNB """
        if cpu_core is not None:
            os.sched_setaffinity(0, {cpu_core})
        logger.debug("Starting gNB")
        for link in self.links:
            link.attach()
        self.waiter = self.links[0].waiter(self.links)
        self.ngap_to_ue_thread = self._load_ngap_to_ue_thread(self._ngap_to_ue_thread_function)
        self.nas_dl_thread = self._load_ue_to_ngap_thread(self._ue_to_ngap_thread_function)
        # Wait for SCTP to be connected
        time.sleep(2)
        self.initiate()

    def initiate(self) -> None:
        # Send NGSetupRequest
        IEs = []
        with ngap_pdu_lock:
            PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
            ng_setup_request(PDU, IEs, self)
            ng_setup_pdu_aper = PDU.to_aper()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"\n|----------------------------------------------------------------------------------------------------------------|\n\
                gNB sending message to 5GC\n\
|----------------------------------------------------------------------------------------------------------------|\n\
{PDU.show()}\n\
|----------------------------------------------------------------------------------------------------------------|\n\n")
        self.sctp.send(ng_setup_pdu_aper)
    
    def _load_ngap_to_ue_thread(self, ngap_to_ue_thread_function):
        """ Load the thread that will handle NGAP DownLink messages from 5G Core """
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=ngap_to_ue_thread_function)
            t.daemon = True
            threads.append(t)

        # start all threads
        for t in threads:
            t.start()
        # ngap_to_ue_thread = threading.Thread(target=ngap_to_ue_thread_function)
        # ngap_to_ue_thread.start()
        # return ngap_to_ue_thread
        return threads

    def _ngap_to_ue_thread_function(self) -> None:
        """ This thread function will read from queue and handle NGAP DownLink messages from 5G Core 
        
            It will then select the appropriate NGAP procedure to handle the message. Where the procedure
            returns an NAS PDU, it will be put in the queue to be sent to the UE
        """
        
        while not self.exit_flag.value:
            try:
                data = None
                with ngap_to_ue_lock:
                    data = self.sctp.recv()
                if data:
                    # The time the gNB has the message: the UE simulator records it as the NAS message's
                    # arrival, so its own queueing does not count as the 5GC's latency
                    received_at = time.time()
                    handled = self._downlink(data)
                    if handled is None:
                        continue
                    procedureCode, ngap_aper, nas_pdu, ue_ = handled
                    if procedureCode == 41 and ue_:
                        # UE Context Release: its sessions' traffic stops
                        self.userplane.release_ue(ue_['ran_ue_ngap_id'])
                        
                    if ue_:
                        if not ue_['ran_ue_ngap_id'] in self.ues:
                            self.ues[ue_['ran_ue_ngap_id']] = { 'amf_ue_ngap_id': ue_['amf_ue_ngap_id'] }
                        self.ues[ue_['ran_ue_ngap_id']]['amf_ue_ngap_id'] = ue_['amf_ue_ngap_id']
                        if ue_.get('qos_identifier'):
                            ul_teid = utils_py3.bytes_to_uint(ue_['ul_up_transport_layer_information'][1]['gTP-TEID'], 32)
                            dl_teid = utils_py3.bytes_to_uint(ue_['dl_up_transport_layer_information'][1]['gTP-TEID'], 32)
                            upf_address = socket.inet_ntoa(utils_py3.uint_to_bytes(ue_['ul_up_transport_layer_information'][1]['transportLayerAddress'][0], 32))
                            logger.debug(f"UE {ue_['ran_ue_ngap_id']} PDU resource setup QOS id: {ue_['qos_identifier']} UL Address: {upf_address} UL teid {ul_teid} DL teid {dl_teid}")
                            self.ues[ue_['ran_ue_ngap_id']]['qfi'] = ue_['qos_identifier']
                            self.ues[ue_['ran_ue_ngap_id']]['ul_teid'] = ul_teid
                            self.ues[ue_['ran_ue_ngap_id']]['dl_teid'] = dl_teid
                            self.ues[ue_['ran_ue_ngap_id']]['upf_address'] = upf_address
                            self.ues[ue_['ran_ue_ngap_id']]['pdu_session_id'] = ue_.get('pdu_session_id')
                    if ngap_aper:
                        self.sctp.send(ngap_aper)
                    if procedureCode == 41 and ue_:
                        self._to_ue(RELEASE, ue_['ran_ue_ngap_id'], b'', received_at)
                    elif nas_pdu:
                        self._to_ue(DL_NAS, ue_['ran_ue_ngap_id'], nas_pdu, received_at)
            except Exception as e:
                logger.error(f"Error sending message to UESim: {e}")
                # IF error occurs, likely from SCTP end program
                # self.exit_flag.value = True
    
    def _fast(self) -> bool:
        """ Whether to use the NGAP fast path: not when messages are logged, which needs pycrate objects """
        return self.ngap_fastpath and not logger.isEnabledFor(logging.DEBUG)

    def _downlink(self, data):
        """ A downlink NGAP message handled: (procedure code, the gNB's NGAP answer encoded or None,
        NAS PDU, the UE's NGAP IDs), or None for a procedure the gNB does not handle """
        handled = self._downlink_fast(data) if self._fast() else None
        return handled if handled is not None else self._downlink_pycrate(data)

    def _downlink_pycrate(self, data):
        """ _downlink() with pycrate: the message decoded, and handled by its procedure in downlink_mapper """
        with ngap_pdu_lock:
            PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
            PDU.from_aper(data)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"\n|----------------------------------------------------------------------------------------------------------------|\n\
                gNB received message from 5GC\n\
|----------------------------------------------------------------------------------------------------------------|\n\
{PDU.show()}\n\
|----------------------------------------------------------------------------------------------------------------|\n\n")
            procedureCode = PDU.get_val()[1]['procedureCode']
            procedure_func = downlink_mapper.get(procedureCode)
            if not procedure_func:
                # logger.debug(f"Received downlink procedure {procedureCode} without handler mapped to it")
                return None
            ngap_pdu, nas_pdu, ue_ = procedure_func(PDU)
            ngap_aper = None
            if ngap_pdu:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"\n|----------------------------------------------------------------------------------------------------------------|\n\
                gNB sending message to 5GC\n\
|----------------------------------------------------------------------------------------------------------------|\n\
{ngap_pdu.show()}\n\
|----------------------------------------------------------------------------------------------------------------|\n\n")
                ngap_aper = ngap_pdu.to_aper()
            if self._fast():
                # The IEs the fast path does not read, now that pycrate has decoded them
                ngapfast.learn(data)
        return procedureCode, ngap_aper, nas_pdu, ue_

    def _downlink_fast(self, data):
        """ What _downlink_pycrate() gives for a DownlinkNASTransport, InitialContextSetupRequest or
        UEContextReleaseCommand, from src/ngapfast.py's parser and templates; None for a message to
        decode with pycrate """
        parsed = ngapfast.downlink(data)
        if parsed is None:
            return None
        procedureCode, amf_ue_ngap_id, ran_ue_ngap_id, nas_pdu = parsed
        ue_ = {'ran_ue_ngap_id': ran_ue_ngap_id, 'amf_ue_ngap_id': amf_ue_ngap_id}
        if procedureCode == ngapfast.DOWNLINK_NAS_TRANSPORT:
            # as downlink_nas_transport(): nothing without a NAS PDU
            return (procedureCode, None, nas_pdu, ue_) if nas_pdu else (procedureCode, None, None, None)
        if procedureCode == ngapfast.INITIAL_CONTEXT_SETUP:
            return procedureCode, ngapfast.initial_context_setup_response(amf_ue_ngap_id, ran_ue_ngap_id), nas_pdu, ue_
        if procedureCode == ngapfast.UE_CONTEXT_RELEASE:
            return procedureCode, ngapfast.ue_context_release_complete(amf_ue_ngap_id, ran_ue_ngap_id), None, ue_
        return None

    def _uplink_fast(self, kind, ue, data):
        """ The Initial UE Message (CONNECT) or Uplink NAS Transport from src/ngapfast.py's templates,
        or None for one to build with pycrate """
        templates = self.__dict__.get('_uplink_templates')
        if templates is None:
            try:
                templates = ngapfast.Uplink(self.plmn_identity, nr_cell_identity(self), self.tac)
            except Exception:
                templates = False          # pycrate's path for every message, as before
            self._uplink_templates = templates
        if not templates:
            return None
        if kind == CONNECT:
            return templates.initial_ue_message(ue['ran_ue_ngap_id'], data, ue.get('cause', 3), ue.get('s_tmsi'))
        return templates.uplink_nas_transport(ue['amf_ue_ngap_id'], ue['ran_ue_ngap_id'], data)

    def _load_ue_to_ngap_thread(self, ue_to_ngap_thread_function):
        """ Load the thread that will handle the UE simulators' events

            Not a daemon: it keeps the gNB process (and its association) until run.py ends it.
        """
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=ue_to_ngap_thread_function)
            t.daemon = False
            threads.append(t)

        # start all threads
        for t in threads:
            t.start()
        # ue_to_ngap_thread = threading.Thread(target=ue_to_ngap_thread_function)
        # ue_to_ngap_thread.start()
        # return ue_to_ngap_thread
        return threads

    def _ue_to_ngap_thread_function(self) -> None:
        """ This thread function reads the UE simulators' events, waiting on all the links at once

            A CONNECT becomes an Initial UE Message and an UL_NAS an Uplink NAS Transport, with the NAS
            PDU as the UE simulator built it; an UP_CONTROL hands a PDU session to the user plane.
            It runs until the process ends: at the end of a run, run.py stops the sessions' traffic
            before it ends the gNB processes, and with them their associations.
        """
        while True:
            if not len(self.waiter):    # every UE simulator has gone: wait for the end of the run
                time.sleep(0.5)
                continue
            for link in self.waiter.wait(0.5):
                try:
                    event = link.recv()
                except LinkClosed:
                    logger.info("A UE simulator has closed its link")
                    self.waiter.remove(link)
                    continue
                except Exception as e:
                    logger.error(f"Error receiving message from UESim: {e}")
                    continue
                try:
                    self._handle_uplink(link, event)
                except Exception as e:
                    logger.error(f"Error receiving message from UESim: {e}")
                    # IF error occurs, likely from SCTP end program
                    # self.exit_flag.value = True

    def _handle_uplink(self, link, event) -> None:
        ran_ue_ngap_id = event.ue_id
        if not self._claim(link, ran_ue_ngap_id):
            return
        if event.kind == CONNECT:
            cause, s_tmsi, data = parse_connect(event.payload)
            procedure_func = initial_ue_message
            ue = {'ran_ue_ngap_id': ran_ue_ngap_id, 'cause': cause, 's_tmsi': s_tmsi}
        elif event.kind == UL_NAS:
            data = event.payload
            procedure_func = uplink_nas_transport
            ue = {'ran_ue_ngap_id': ran_ue_ngap_id}
        elif event.kind == UP_CONTROL:
            return self._up_control(ran_ue_ngap_id, event.payload)
        else:
            logger.debug(f"UE {ran_ue_ngap_id}: {KIND_NAMES[event.kind]} from the UE simulator ignored")
            return
        if not data:
            return
        # The UE simulator's bytes go out as they are: no parse and re-encode here
        ue['amf_ue_ngap_id'] = self.ues.get(ran_ue_ngap_id).get('amf_ue_ngap_id') if self.ues.get(ran_ue_ngap_id) else None
        ngap_aper = self._uplink_fast(event.kind, ue, data) if self._fast() else None
        if ngap_aper is None:
            IEs = []
            IEs.append({'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', data)})
            with ngap_pdu_lock:
                PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
                procedure_func(PDU, IEs, ue, self)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"\n|----------------------------------------------------------------------------------------------------------------|\n\
                gNB sending message to 5GC\n\
|----------------------------------------------------------------------------------------------------------------|\n\
{PDU.show()}\n\
|----------------------------------------------------------------------------------------------------------------|\n\n")
                ngap_aper = PDU.to_aper()
        if event.code:
            # Stamped before the send, so the stamp is in place before the 5GC's answer
            self._stamp_uplink(ran_ue_ngap_id, event.code)
        self.sctp.send(ngap_aper)

    def _up_control(self, ran_ue_ngap_id, payload) -> None:
        """ A UE's PDU session is up at the address the UE simulator sends (with the UE's SUPI): its
        traffic goes to the user plane """
        try:
            request, address, supi = parse_up_control(payload)
            if request == UP_SESSION and address:
                ue = self.ues.get(ran_ue_ngap_id)
                self.userplane.add_session(Session(
                    supi=supi, ue_ip=socket.inet_ntoa(address),
                    pdu_session_id=ue.get('pdu_session_id'), ul_teid=ue['ul_teid'], qfi=ue['qfi'],
                    upf_address=ue.get('upf_address'), dl_teid=ue.get('dl_teid'), gnb_address=gtpIp,
                    ran_ue_ngap_id=ran_ue_ngap_id, amf_ue_ngap_id=ue.get('amf_ue_ngap_id'), t=time.time()))
        except Exception as e:
            # self.exit_flag.value = True
            logger.error(f"Error receive DP message from UESim: {e}")

    def _claim(self, link, ran_ue_ngap_id) -> bool:
        """ The UE's events come on this link: the first link a RAN UE NGAP ID comes on owns it. One that
        comes on another link as well is a clash: reported, and its events there are dropped. """
        owner = self.ue_links.setdefault(ran_ue_ngap_id, link)
        if owner is link:
            return True
        if ran_ue_ngap_id not in self.clashes:
            self.clashes.add(ran_ue_ngap_id)
            logger.error(f"RAN UE NGAP ID {ran_ue_ngap_id} comes from two UE simulators: the UE ids of a "
                         f"gNB's UE simulators must differ; the second one's messages are dropped")
        return False

    def _link_of(self, ran_ue_ngap_id):
        """ The link a UE's downlink messages go on: the one it came on (the only one, with one) """
        link = self.ue_links.get(ran_ue_ngap_id)
        if link is None and len(self.links) == 1:
            return self.links[0]
        return link

    def _to_ue(self, kind, ran_ue_ngap_id, payload, received_at) -> None:
        """ A DL_NAS or RELEASE to the UE's simulator, with the time the gNB received the NGAP message
        and the UE's uplink send times not yet returned """
        link = self._link_of(ran_ue_ngap_id)
        if link is None:
            logger.error(f"UE {ran_ue_ngap_id}: no UE simulator has this RAN UE NGAP ID; its {KIND_NAMES[kind]} is dropped")
            return
        stamps = self._take_uplink_stamps(ran_ue_ngap_id)
        try:
            link.send(kind, ran_ue_ngap_id, payload, 0, received_at, stamps)
        except LinkStopped:
            logger.debug(f"UE {ran_ue_ngap_id}: the run ended before the link took its {KIND_NAMES[kind]}")
        except LinkClosed as e:
            logger.warning(f"UE {ran_ue_ngap_id}: its UE simulator's link has ended ({e})")

    def _stamp_uplink(self, ran_ue_ngap_id, code, t=None):
        """ Record when the UE's uplink message (its message code) leaves for the 5GC

            The UE simulator gets the time with the UE's next downlink message and records it as the
            message's send time, so its own queueing and the pipe to the gNB do not count as the
            5GC's latency.
        """
        with self.ul_sent_lock:
            self.ul_sent.setdefault(ran_ue_ngap_id, []).append((code, t if t is not None else time.time()))

    def _take_uplink_stamps(self, ran_ue_ngap_id):
        """ The UE's uplink send times not yet returned to the UE simulator, oldest first """
        with self.ul_sent_lock:
            return self.ul_sent.pop(ran_ue_ngap_id, [])

    def get_ue(self, ran_ue_ngap_id):
        return self.ues[ran_ue_ngap_id]
    
    def remove_ue(self, ran_ue_ngap_id) -> None:
        del self.ues[ran_ue_ngap_id]

    def get_ues(self):
        return self.ues

    def stop(self):
        if ngap_to_ue_lock.locked():
            ngap_to_ue_lock.release()

        self.sctp.disconnect()
        sys.exit(0)

    def __str__(self):
        return f"<NGAP mcc={self.mcc}, mnc={self.mnc}, nci={self.nci}, id_length={self.id_length}>"