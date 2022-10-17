from binascii import unhexlify, hexlify
from pycrate_mobile import *
from pycrate_mobile.NAS import *
from UE import UE
from abc import ABC, ABCMeta, abstractmethod
from CryptoMobile.Milenage import Milenage
from CryptoMobile.Milenage import make_OPc
from CryptoMobile.conv import conv_501_A4
from CryptoMobile.ECIES import *

def byte_xor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

# Add classes for NAS Procedures

class NASProc(metaclass=ABCMeta):
    """ Base class for NAS Procedures. """
    def __init__(self, ue: UE) -> None:
        print("NASProc.__init__")
        self.ue = ue

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
    def __init__(self, ue: UE) -> None:
        super().__init__(ue)

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
        abba = Msg['ABBA'].get_val()

        Mil = Milenage(OP)
        AK = Mil.f5star(key, rand)
        SQN = byte_xor(AK, sqn_xor_ak)
        Mil.set_opc(make_OPc(key, OP))
        Mil.f1(key, rand, SQN=SQN, AMF=amf)
        RES, CK, IK, _  = Mil.f2345(key, rand)
        sn_name = b"5G:mnc095.mcc208.3gppnetwork.org"
        Res = conv_501_A4(CK, IK, sn_name, rand, RES)

        IEs = {}
        IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 87 }
        IEs['RES'] = unhexlify('b3982d2d4b458ba33ae509f5004110c5')
        Msg = FGMMAuthenticationResponse(val=IEs)
        
        # Get K_AUSF
        self.ue.k_ausf = conv_501_A2(CK, IK, sn_name, sqn_xor_ak)
        # Get K_SEAF
        self.ue.k_seaf = conv_501_A6(self.ue.k_ausf, sn_name)
        # Get K_AMF
        self.ue.k_amf = conv_501_A7(self.ue.k_seaf, self.ue.supi, abba)
        # Get K_NAS_ENC
        self.ue.k_nas_enc = conv_501_A8(self.ue.k_amf, alg_type=1, alg_id=1)
        # Get K_NAS_INT
        self.ue.k_nas_int = conv_501_A8(self.ue.k_amf, alg_type=1, alg_id=2)

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
    def __init__(self, ue: UE) -> None:
        super().__init__(ue)

    def recv(self, data: bytes) -> bytes:
        b = process(data)
        return send(b)

    def send(self, data: bytes) -> int:
        """ Send data to the socket. """
        return b''

    def create_req(self):
        IEs = {}
        IEs['5GMMHeaderSec'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 4 }
        Msg = FGMMSecProtNASMessage(val=IEs)
        return Msg

    def process(self, data: bytes) -> bytes:
        Msg, err = parse_NAS_MO(unhexlify('7e034fe5375f007e005d110204f0f0f0f0e1360102'))
        Ms, e = parse_NAS_MO(unhexlify('7e04c82f8d0600a03c57f5d1de4dd86f51f78670b4e3327da292e84eb075b9dc9584c3c7a80e4ed2ab303dd2fa949bed96dd43cffa7b59298c5f0dda155cb6'))
        M = FGMMSecProtNASMessage()
        Mx = FGMMSecurityModeCommand()
        return unhexlify('7e04c82f8d0600a03c57f5d1de4dd86f51f78670b4e3327da292e84eb075b9dc9584c3c7a80e4ed2ab303dd2fa949bed96dd43cffa7b59298c5f0dda155cb6')


class SecurityModeProc(NASProc):

    def __init__(self, ue: UE) -> None:
        super().__init__(ue)

    def recv(self, data: bytes) -> bytes:
        print("==== SecurityModeProc.recv")
        b = process(data)
        return send(b)

    def send(self, data: bytes) -> bytes:
        """ Send data to the socket. """
        return b''

    def process(self, data: bytes) -> bytes:
        Msg, err = parse_NAS5G(data)

        if not self.verify_security_capabilities(Msg):
            return b''

        if not self.verify_integrity_protection(Msg):
            return b''

        # Send Security Mode Complete
        IEs = {}
        IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0 }
        IEs['NASContainer'] = { 'V': b'7e004179000d0102f8590000000000000000132e04f0f0f0f0' }
        Msg = FGMMSecurityModeComplete(val=IEs)

        # Encrypt NAS message
        SecMsg = SecProtNASMessageProc(self.ue).create_req()
        SecMsg['NASMessage'].set_val(Msg.to_bytes())
        k = unhexlify('0C0A34601D4F07677303652C0462535B')
        SecMsg.encrypt(key=self.ue.key, dir=0, fgea=1, seqnoff=0, bearer=1)
        return SecMsg.to_bytes()

    def verify_security_capabilities(self, msg) -> bool:
        # algo = msg['5GMMSecurityModeCommand']['NASSecAlgo'].get_val()
        return True

    def verify_integrity_protection(self, msg) -> bool:
        nas_integrity_protected = True
        nas_integrity_algorithm = None
        nas_integrity_key = None

        # TODO: Check if NAS integrity protected
        return nas_integrity_protected

class RegistrationProc():

    def initiate(self):
        IEs = {}
        IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65 }
        IEs['NAS_KPI'] = { 'TSC': 0, 'Value': 7 }
        IEs['5GSRegType'] = { 'FOR': 1, 'Value': 1 }
        IEs['5GSID'] = { 'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': { 'PLMN': '20895', 'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': b'\x00\x00\x00\x00\x13'} }
        IEs['UESecCap'] = { '5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0, '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0, '5G-IA6': 0, '5G-IA7': 0, 'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0, 'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0 }
        Msg = FGMMRegistrationRequest(val=IEs)
        return Msg.to_bytes()

# Function to process NAS procedure
def process_nas_procedure(data: bytes, ue: UE) -> bytes:
    """ Process NAS procedure. """
    # Create NAS object
    NAS_PDU, err = NAS.parse_NAS5G(data)
    print(NAS_PDU)
    print("--------------- Uplink NAS message ---------------")
    print("-------- NAS message: %s --------" % NAS_PDU._name)
    # Print NAS PDU name

    if NAS_PDU._name == '5GMMAuthenticationRequest':
        print("Received 5GMMAuthenticationRequest")
        return AuthenticationProc().recv(data, ue)
    elif NAS_PDU._name == '5GMMSecProtNASMessage':
        if NAS_PDU._by_name.count('5GMMSecurityModeCommand') > 0:
            print("Received 5GMMSecurityModeCommand")
            smc = NAS_PDU['5GMMSecurityModeCommand'].to_bytes()
            return SecurityModeProc().process(smc, ue)
    return None