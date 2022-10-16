import struct
import time
from NAS import process_nas_procedure, RegistrationProc
from pycrate_asn1dir import NGAP
from binascii import unhexlify
from abc import ABC, ABCMeta, abstractmethod

from Proc import Proc
# Create NGAP Procedure class
class NGAPProc(Proc, metaclass=ABCMeta):
    """ This class is the base class for all NGAP procedures."""
    def __init__(self, data: bytes = None):
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

    def initiate(self, data: bytes = None) -> None:
        if data:
            self.PDU.from_aper(data)
        else:
            IEs = []
            IEs.append({'id': 27, 'criticality': 'reject', 'value': ('GlobalRANNodeID', ('globalGNB-ID', {'pLMNIdentity': b'\x02\xf8Y', 'gNB-ID': ('gNB-ID', (1, 32))}))})
            IEs.append({'id': 82, 'criticality': 'ignore', 'value': ('RANNodeName', 'UERANSIM-gnb-208-95-1')})
            IEs.append({'id': 102, 'criticality': 'reject', 'value': ('SupportedTAList', [{'tAC': b'\x00\xa0\x00', 'broadcastPLMNList': [{'pLMNIdentity': b'\x02\xf8Y', 'tAISliceSupportList': [{'s-NSSAI': {'sST': b'\xde', 'sD': b'\x00\x00{'}}]}]}])})
            IEs.append({'id': 21, 'criticality': 'ignore', 'value': ('PagingDRX', 'v128')})
            val = ('initiatingMessage', {'procedureCode': 21, 'criticality': 'reject', 'value': ('NGSetupRequest', {'protocolIEs': IEs})})
            self.PDU.set_val(val)

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

    def initiate(self, data: bytes = None) -> None:
        if data:
            self.PDU.from_aper(data)
        else:
            NAS_PDU = RegistrationProc().create_req()
            IEs = []
            curTime = int(time.time()) + 2208988800 #1900 instead of 1970
            IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', 1)}) # RAN-UE-NGAP-ID must be unique for each UE
            IEs.append({'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', NAS_PDU) })
            IEs.append({'id': 121, 'criticality': 'reject', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': b'\x02\xf8Y', 'nRCellIdentity': (16, 36)}, 'tAI': {'pLMNIdentity': b'\x02\xf8Y', 'tAC': b'\x00\xa0\x00'}, 'timeStamp': struct.pack("!I",curTime)}))})
            IEs.append({'id': 90, 'criticality': 'ignore', 'value': ('RRCEstablishmentCause', 'mo-Signalling')})
            IEs.append({'id': 112, 'criticality': 'ignore', 'value': ('UEContextRequest', 'requested')})
            val = ('initiatingMessage', {'procedureCode': 15, 'criticality': 'ignore', 'value': ('InitialUEMessage', {'protocolIEs': IEs})})
            self.PDU.set_val(val)

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
    
    def process(self, data) -> bytes:
        # TODO: Implement this method
        PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        PDU.from_aper(data)
        # Extract IE values
        IEs = PDU.get_val()[1]['value'][1]['protocolIEs']
        # Extract AMF-UE-NGAP-ID
        amf_ue_ngap_id = next((ie['value'][1] for ie in IEs if ie['id'] == 10), None)
        # Extract RAN-UE-NGAP-ID
        ran_ue_ngap_id = next((ie['value'][1] for ie in IEs if ie['id'] == 85), None)
        # Extract the NAS PDU
        nas_pdu = next((ie['value'][1] for ie in IEs if ie['id'] == 38), None)
        if not nas_pdu:
            return None
        
        # Send the NAS PDU to UE
        uplink_nas_pdu = process_nas_procedure(nas_pdu)

        # Create the Uplink NAS Transport procedure
        if uplink_nas_pdu:
            print("Sending Uplink NAS Transport")
            uplink_nas_transport_proc = NGUplinkNASTransportProc()
            # Create obj for the Uplink NAS Transport procedure
            obj = {'amf_ue_ngap_id': amf_ue_ngap_id, 'ran_ue_ngap_id': ran_ue_ngap_id, 'nas_pdu': uplink_nas_pdu}
            uplink_nas_transport_pdu = uplink_nas_transport_proc.create_request(obj)
            return uplink_nas_transport_pdu
        return b''

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
        if data:
            self.PDU.from_aper(data)
        else:
            IEs = []
            curTime = int(time.time()) + 2208988800 #1900 instead of 1970
            IEs.append({'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', 1)})
            IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', 1)})
            IEs.append({'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', b'~\x00W-\x10\xb3\x98--KE\x8b\xa3:\xe5\t\xf5\x00A\x10\xc5')})
            IEs.append({'id': 121, 'criticality': 'ignore', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': b'\x02\xf8Y', 'nRCellIdentity': (16, 36)}, 'tAI': {'pLMNIdentity': b'\x02\xf8Y', 'tAC': b'\x00\xa0\x00'}, 'timeStamp': struct.pack("!I",curTime)}))})
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
        IEs.append({'id': 121, 'criticality': 'ignore', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': b'\x02\xf8Y', 'nRCellIdentity': (16, 36)}, 'tAI': {'pLMNIdentity': b'\x02\xf8Y', 'tAC': b'\x00\xa0\x00'}, 'timeStamp': struct.pack("!I",curTime)}))})
        val = ('initiatingMessage', {'procedureCode': 46, 'criticality': 'ignore', 'value': ('UplinkNASTransport', {'protocolIEs': IEs})})
        PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        PDU.set_val(val)
        return PDU

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

    def create_response(self, data: bytes = None) -> None:
        IEs = []
        curTime = int(time.time()) + 2208988800 #1900 instead of 1970
        IEs.append({'id': 10, 'criticality': 'ignore', 'value': ('AMF-UE-NGAP-ID', 1)})
        IEs.append({'id': 85, 'criticality': 'ignore', 'value': ('RAN-UE-NGAP-ID', 1)})
        val = ('successfulOutcome', {'procedureCode': 14, 'criticality': 'reject', 'value': ('InitialContextSetupResponse', {'protocolIEs': IEs})})
        self.PDU.set_val(val)

    def process(self, data) -> bytes:
        return b''

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
