from binascii import unhexlify

from abc import ABC, ABCMeta, abstractmethod

# Create abstact class for procedures
class Proc(metaclass=ABCMeta):
    """ This class is the base class for all procedures """
    def __init__(self, data: bytes = None):
        # Create PDU instance that will be instatiated by the _____PDU_Descriptions.____ class
        self.PDU = self._load_procedure()
        # self.initiate(data)

    @abstractmethod
    def initiate(self, data: bytes = None) -> None:
        if data:
            self.PDU.from_aper(unhexlify(data))

    @abstractmethod
    def _load_procedure(self):
        """ This method loads the procedure. """
        pass

    @abstractmethod
    def get_procedure(self):
        """ This method returns the procedure. """
        pass

    @abstractmethod
    def set_pdu(self, data: bytes):
        """ This method sets the PDU. """
        pass

    @abstractmethod
    def get_pdu(self):
        """ This method returns the PDU. """
        return self._PDU

    
