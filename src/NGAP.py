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

    @abstractmethod
    def get_procedure(self):
        """ This method returns the procedure. """
        pass
    
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

    @abstractmethod
    def get_procedure(self):
        """ This method returns the procedure. """
        pass

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

    @abstractmethod
    def get_procedure(self):
        """ This method returns the procedure. """
        pass

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
            PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
            IEs = []
            IEs.append({'id': 27, 'criticality': 'reject', 'value': ('GlobalRANNodeID', ('globalGNB-ID', {'pLMNIdentity': b'\x02\xf8Y', 'gNB-ID': ('gNB-ID', (1, 32))}))})
            IEs.append({'id': 82, 'criticality': 'ignore', 'value': ('RANNodeName', 'TGRANSIM-gnb-208-95-1')})
            IEs.append({'id': 102, 'criticality': 'reject', 'value': ('SupportedTAList', [{'tAC': b'\x00\xa0\x00', 'broadcastPLMNList': [{'pLMNIdentity': b'\x02\xf8Y', 'tAISliceSupportList': [{'s-NSSAI': {'sST': b'\xde', 'sD': b'\x00\x00{'}}]}]}])})
            IEs.append({'id': 21, 'criticality': 'ignore', 'value': ('PagingDRX', 'v128')})
            val = ('initiatingMessage', {'procedureCode': 21, 'criticality': 'reject', 'value': ('NGSetupRequest', {'protocolIEs': IEs})})
            PDU.set_val(val)
            self.PDU = PDU

    def _load_procedure(self):
        return NGAP.NGAP_PDU_Descriptions.NGAP_PDU

    def get_procedure(self):
        return self.PDU.to_asn1()

    def set_pdu(self, data: bytes):
        if data:
            self.PDU.from_aper(unhexlify(data))

    def get_pdu(self):
        return self.PDU

    def process(self, data) -> bytes:
        # TODO: Implement this method
        return b''

# Create Dispatcher for NGAP procedures
NGAPNonUEProcRANDispatcher = {
    21 : NGSetupProc,
}