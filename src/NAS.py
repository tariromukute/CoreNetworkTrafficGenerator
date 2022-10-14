from binascii import unhexlify, hexlify
from pycrate_mobile import *
from pycrate_mobile.NAS import *
from abc import ABC, ABCMeta, abstractmethod
from CryptoMobile.Milenage import Milenage
from CryptoMobile.Milenage import make_OPc
from CryptoMobile.conv import conv_501_A4

def byte_xor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

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

        3GPP TS 33.501 version 15.2.0 Release 15: Figure 6.1.3.2-1: Authentication procedure for 5G AKA
    """
    def __init__(self):
        super().__init__()

    def extract_req_parameters(msg):
        # Msg, err = parse_NAS_MO(unhexlify('7e0056020200002178c5aa53d14c2af655970a08ac5388ca2010b54abf5b068880000888d4e3e43c21ae'))
        sqn_xor_ak, amf, mac = Msg['AUTN']['AUTN'].get_val()
        
    def recv(self, data: bytes) -> bytes:
        Msg, err = parse_NAS_MO(data)
        if err:
            return
        OP = unhexlify('63bfa50ee6523365ff14c1f45f88737d')
        key = unhexlify('0C0A34601D4F07677303652C0462535B')

        sqn_xor_ak, amf, mac = Msg['AUTN']['AUTN'].get_val()
        _, rand = Msg['RAND'].get_val()

        Mil = Milenage(OP)
        AK = Mil.f5star(key, rand)
        SQN = byte_xor(AK, sqn_xor_ak)
        Mil.set_opc(make_OPc(key, OP))
        Mil.f1(key, rand, SQN=SQN, AMF=amf)
        R = Mil.f2345(key, rand)
        sn_name = b"5G:mnc095.mcc208.3gppnetwork.org"
        Res = conv_501_A4(R[1], R[2], sn_name, rand, R[0])

        IEs = {}
        IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 87 }
        IEs['RES'] = unhexlify('b3982d2d4b458ba33ae509f5004110c5')
        Msg = FGMMAuthenticationResponse(val=IEs)
        
        return Msg.to_bytes()

    def send(self, data: bytes) -> int:
        """ Send data to the socket. """
        return b''

    def process_ie(self) ->bytes:
        IEs = {}
        IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 87 }
        Msg = NAS.FGMMAuthenticationResponse(val=IEs)
        Msg.r

    def process(self, data: bytes) -> bytes:
        
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
        return AuthenticationProc().recv(data)
    elif NAS_PDU._name == '5GMMSecProtNASMessage':
        return SecProtNASMessageProc().process(data)
    return None

