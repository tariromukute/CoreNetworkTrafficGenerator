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
    """
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

    def process(self, data) -> bytes:
        # TODO: Implement this method
        return b''

# Create Dispatcher for NGAP procedures
NGAPNonUEProcRANDispatcher = {
    21 : NGSetupProc,
}