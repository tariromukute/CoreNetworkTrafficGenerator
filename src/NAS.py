from binascii import unhexlify
from pycrate_mobile import *
from abc import ABC, ABCMeta, abstractmethod

# Add classes for NAS Procedures

class NASProc(metaclass=ABCMeta):
    """ Base class for NAS Procedures. """
    def __init__(self, data: bytes = None):
        print("NASProc.__init__")

    def recv(self, data: bytes) -> bytes:
        """ Receive data from the socket. """
        pass

    def send(self, data: bytes) -> bytes:
        """ Send data to the socket. """
        pass

    def process(self):
        """ Run the sequence. """
        pass

class AuthenticationProc(NASProc):
    """ Authentication Procedure TS 23.502 Section

    """
    def __init__(self):
        super().__init__()

    def recv(self, data: bytes) -> bytes:
        b = process(data)
        return send(b)

    def send(self, data: bytes) -> int:
        """ Send data to the socket. """
        return b''

    def process(self, data: bytes) -> bytes:
        Msg = NAS.FGMMAuthenticationResponse()
        return unhexlify('7e00572d10b3982d2d4b458ba33ae509f5004110c5')

class SecProtNASMessageProc(NASProc):
    """ 5GMM Security Protected NAS Message Procedure TS 23.502 Section

    """
    def __init__(self):
        super().__init__()

    def recv(self, data: bytes) -> bytes:
        b = process(data)
        return send(b)

    def send(self, data: bytes) -> int:
        """ Send data to the socket. """
        return b''

    def process(self, data: bytes) -> bytes:
        return unhexlify('7e04c82f8d0600a03c57f5d1de4dd86f51f78670b4e3327da292e84eb075b9dc9584c3c7a80e4ed2ab303dd2fa949bed96dd43cffa7b59298c5f0dda155cb6')

# Function to process NAS procedure
def process_nas_procedure(data: bytes) -> bytes:
    """ Process NAS procedure. """
    # Create NAS object
    NAS_PDU, err = NAS.parse_NAS5G(data)
    print(NAS_PDU)
    # Print NAS PDU name
    print(NAS_PDU._name)
    if NAS_PDU._name == '5GMMAuthenticationRequest':
        print("Received 5GMMAuthenticationRequest")
        return AuthenticationProc().process(data)
    elif NAS_PDU._name == '5GMMSecProtNASMessage':
        return SecProtNASMessageProc().process(data)
    return None

