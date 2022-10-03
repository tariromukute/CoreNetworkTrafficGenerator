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
            IEs.append({'id': 82, 'criticality': 'ignore', 'value': ('RANNodeName', 'TGRANSIM-gnb-208-95-1')})
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
            IEs = []
            IEs.append({'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', 1)})
            IEs.append({'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', b'~\x00Ay\x00\r\x01\x02\xf8Y\x00\x00\x00\x00\x00\x00\x00\x00\x13.\x04\xf0\xf0\xf0\xf0')})
            IEs.append({'id': 121, 'criticality': 'reject', 'value': ('UserLocationInformation', ('userLocationInformationNR', {'nR-CGI': {'pLMNIdentity': b'\x02\xf8Y', 'nRCellIdentity': (16, 36)}, 'tAI': {'pLMNIdentity': b'\x02\xf8Y', 'tAC': b'\x00\xa0\x00'}, 'timeStamp': b'\xe6\xe1\x13\xe9'}))})
            IEs.append({'id': 90, 'criticality': 'ignore', 'value': ('RRCEstablishmentCause', 'mo-Signalling')})
            IEs.append({'id': 112, 'criticality': 'ignore', 'value': ('UEContextRequest', 'requested')})
            val = ('initiatingMessage', {'procedureCode': 15, 'criticality': 'reject', 'value': ('InitialUEMessage', {'protocolIEs': IEs})})
            self.PDU.set_val(val)

    def process(self, data) -> bytes:
        # TODO: Implement this method
        return b''
        
# Create Dispatcher for NGAP procedures
NGAPNonUEProcRANDispatcher = {
    21 : NGSetupProc,
}

NGAPNonUEProcAMFDispatcher = {

}

NGAPUEAssociatedProcDispatcher = {
    15 : NGInitialUEMessageProc,
}