from binascii import unhexlify, hexlify
from pycrate_mobile import *
from pycrate_mobile.NAS import *
import UE
from abc import ABC, ABCMeta, abstractmethod
from CryptoMobile.Milenage import Milenage
from CryptoMobile.Milenage import make_OPc
from CryptoMobile.conv import *
from CryptoMobile.ECIES import *
from pycrate_mobile.TS24501_IE import *

def byte_xor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

# Add classes for NAS Procedures

class NASProc(metaclass=ABCMeta):
    """ Base class for NAS Procedures. """
    def __init__(self, ue: UE, queue = None) -> None:
        print("NASProc.__init__")
        self.ue = ue
        self._queue = queue

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
        print("AUTN: ",  Msg['AUTN'])
        print("sqn_xor_ak: ", hexlify(sqn_xor_ak))
        print("amf: ", hexlify(amf))
        print("mac: ", hexlify(mac))

        _, rand = Msg['RAND'].get_val()
        print("rand: ", hexlify(rand))

        abba = Msg['ABBA']['V'].get_val()
        print("abba: ", hexlify(abba))

        Mil = Milenage(OP)
        Mil.set_opc(OP)
        AK = Mil.f5star(key, rand)
        print("AK: ", hexlify(AK))

        SQN = byte_xor(AK, sqn_xor_ak)
        print("SQN: ", hexlify(SQN))

        Mil.f1(unhexlify(self.ue.key), rand, SQN=SQN, AMF=amf)
        RES, CK, IK, _  = Mil.f2345(key, rand)
        print("RES: ", hexlify(RES))
        print("CK: ", hexlify(CK))
        print("IK: ", hexlify(IK))

        sn_name = b"5G:mnc095.mcc208.3gppnetwork.org"
        Res = conv_501_A4(CK, IK, sn_name, rand, RES)
        print("Res: ", hexlify(Res))

        IEs = {}
        IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 87 }
        IEs['RES'] = Res
        Msg = FGMMAuthenticationResponse(val=IEs)
        
        # Get K_AUSF
        self.ue.k_ausf = conv_501_A2(CK, IK, sn_name, sqn_xor_ak)
        print("K_AUSF: ", hexlify(self.ue.k_ausf))
        # Get K_SEAF
        self.ue.k_seaf = conv_501_A6(self.ue.k_ausf, sn_name)
        print("K_SEAF: ", hexlify(self.ue.k_seaf))
        # Get K_AMF
        self.ue.k_amf = conv_501_A7(self.ue.k_seaf, self.ue.supi.encode('ascii'), abba)
        print("K_AMF: ", hexlify(self.ue.k_amf))
        # Get K_NAS_ENC
        self.ue.k_nas_enc = conv_501_A8(self.ue.k_amf, alg_type=1, alg_id=1)
        print("K_NAS_ENC 32: ", hexlify(self.ue.k_nas_enc))
        # Get least significate 16 bytes from K_NAS_ENC 32 bytes
        self.ue.k_nas_enc = self.ue.k_nas_enc[16:]
        print("K_NAS_ENC 16: ", hexlify(self.ue.k_nas_enc))
        # Get K_NAS_INT
        self.ue.k_nas_int = conv_501_A8(self.ue.k_amf, alg_type=2, alg_id=1)
        print("K_NAS_INT 32: ", hexlify(self.ue.k_nas_int))
        self.ue.k_nas_int = self.ue.k_nas_int[16:]
        print("K_NAS_INT 16: ", hexlify(self.ue.k_nas_int))
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
        Msg, err = parse_NAS5G(data)
        if err:
            return
        print(Msg.show())
        # check if message is encrypted
        print(Msg['5GMMHeaderSec']['SecHdr'].get_val())
        if Msg['5GMMHeaderSec']['SecHdr'].get_val() == 2:
            print("Encrypted")
            # decrypt message
            Msg.decrypt(self.ue.k_nas_enc, dir=1, fgea=1, seqnoff=0, bearer=1)
            Msg, err = parse_NAS5G(Msg._dec_msg)
            if err:
                print("Error decrypting message")
                return
            print(Msg.show())
            return Msg
        else:
            print("Not encrypted")
            return Msg


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

        # Create registration message
        RegIEs = {}
        RegIEs['5GSUpdateType'] = {'EPS-PNB-CIoT': 0, '5GS-PNB-CIoT': 0, 'NG-RAN-RCU': 0, 'SMSRequested': 0 }
        RegIEs['5GMMCap'] = {'SGC': 0, '5G-HC-CP-CIoT': 0, 'N3Data': 0, '5G-CP-CIoT': 0, 'RestrictEC': 0, 'LPP': 0, 'HOAttach': 0, 'S1Mode': 0 }
        # TODO: Add NSSAI to RegIEs
        
        # RegMsg = FGMMRegistrationRequest(val=RegIEs)
        RegMsg = RegistrationProc().initiate()
        # Add the RegIEs to the RegMsg

        # Send Security Mode Complete
        IEs = {}
        IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0 }
        IEs['IMEISV'] = {'Type': FGSIDTYPE_IMEISV, 'Digit1': 0, 'Digits': '035609204079514'}
        # IEs['NASContainer'] = RegistrationProc().initiate()
        # IEs['NASContainer'] = RegMsg.to_bytes()
        Msg = FGMMSecurityModeComplete(val=IEs)
        print("==== SecurityModeProc.send")
        print(Msg)
        # Encrypt NAS message
        SecMsg = SecProtNASMessageProc(self.ue).create_req()
        # SecMsg['NASMessage'].set_val(unhexlify('7e005e7700090530659002049715f47100267e004179000d0102f8590000000000000000131001002e04f0f0f0f02f0504de00007b530100'))
        EncMsg, e = parse_NAS5G(unhexlify('7e005e7700090530659002049715f47100267e004179000d0102f8590000000000000000131001002e04f0f0f0f02f0504de00007b530100'))
        SecMsg['NASMessage'].set_val(Msg.to_bytes())
        SecMsg.encrypt(key=self.ue.k_nas_enc, dir=0, fgea=1, seqnoff=0, bearer=1)
        SecMsg.mac_compute(key=self.ue.k_nas_int, dir=0, fgia=1, seqnoff=0, bearer=1)
        print(SecMsg)
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
        IEs['NAS_KSI'] = { 'TSC': 0, 'Value': 7 }
        IEs['5GSRegType'] = { 'FOR': 1, 'Value': 1 }
        IEs['5GSID'] = { 'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': { 'PLMN': '20895', 'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': b'\x00\x00\x00\x00\x13'} }
        IEs['UESecCap'] = { '5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0, '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0, '5G-IA6': 0, '5G-IA7': 0, 'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0, 'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0 }
        Msg = FGMMRegistrationRequest(val=IEs)
        return Msg.to_bytes()
        # return b'7e004179000d0102f8590000000000000000132e04f0f0f0f0'

class RegistrationAcceptProc():

    def process(self, data: bytes) -> bytes:
        Msg, err = parse_NAS5G(data)
        if not err:
            print(Msg.show())
            return None
        else:
            print(err)
            return None
    
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
        tx_nas_pdu = AuthenticationProc(ue).recv(data)
        ue.send(tx_nas_pdu)
    elif NAS_PDU._name == '5GMMSecProtNASMessage':
        # Check if NAS message is integrity protected
        DEC_PDU = SecProtNASMessageProc(ue).process(data)
        print(DEC_PDU._by_name)
        print(DEC_PDU._name)
        if DEC_PDU._by_name.count('5GMMSecurityModeCommand') > 0:
            print("Received 5GMMSecurityModeCommand")
            smc = DEC_PDU['5GMMSecurityModeCommand'].to_bytes()
            tx_nas_pdu = SecurityModeProc(ue).process(smc)
            ue.send(tx_nas_pdu)
        elif DEC_PDU._name == '5GMMRegistrationAccept':
            print("Received 5GMMRegistrationAccept")
            ra = DEC_PDU.to_bytes()
            tx_nas_pdu = RegistrationAcceptProc().process(ra)
            # Send NAS message
            ue.send(tx_nas_pdu)

    return None