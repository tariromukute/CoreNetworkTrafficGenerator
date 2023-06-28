import logging
import threading
from binascii import unhexlify, hexlify
# from pycrate_mobile.NAS import *
from UE import UE, FGMMState
from abc import ABCMeta
from CryptoMobile.Milenage import Milenage
from CryptoMobile.Milenage import make_OPc
from CryptoMobile.conv import *
# from CryptoMobile.ECIES import *
# from pycrate_mobile.TS24501_IE import *
# from pycrate_mobile.TS24008_IE import encode_bcd

from logging.handlers import QueueHandler

logger = logging.getLogger('__NAS__')

# sn_name
# imei
# alg_id = 2
# fgea = 2
# fgia = 2

def byte_xor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

# Add classes for NAS Procedures

class NASProc(metaclass=ABCMeta):
    """ Base class for NAS Procedures. """

    def receive(self, data: bytes, ue: UE) -> bytes:
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
    def __init__(self) -> None:
        super().__init__()

    def receive(self, data: bytes, ue: UE) -> bytes:
        Msg, err = parse_NAS_MO(data)
        if err:
            return
        OP = unhexlify(ue.op)
        key = unhexlify(ue.key)

        sqn_xor_ak, amf, mac = Msg['AUTN']['AUTN'].get_val()

        _, rand = Msg['RAND'].get_val()

        abba = Msg['ABBA']['V'].get_val()

        Mil = Milenage(OP)
        if ue.op_type == 'OPC':
            Mil.set_opc(OP)
        AK = Mil.f5star(key, rand)

        SQN = byte_xor(AK, sqn_xor_ak)

        Mil.f1(unhexlify(ue.key), rand, SQN=SQN, AMF=amf)
        RES, CK, IK, _  = Mil.f2345(key, rand)

        Res = conv_501_A4(CK, IK, ue.sn_name, rand, RES)

        IEs = {}
        IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 87 }
        IEs['RES'] = Res
        Msg = FGMMAuthenticationResponse(val=IEs)
        
        # Note: See CryptoMobile.conv for documentation of this function and arguments
        # Get K_AUSF
        ue.k_ausf = conv_501_A2(CK, IK, ue.sn_name, sqn_xor_ak)
        # Get K_SEAF
        ue.k_seaf = conv_501_A6(ue.k_ausf, ue.sn_name)
        # Get K_AMF
        ue.k_amf = conv_501_A7(ue.k_seaf, ue.supi.encode('ascii'), abba)
        # Get K_NAS_ENC
        ue.k_nas_enc = conv_501_A8(ue.k_amf, alg_type=1, alg_id=1)
        # Get least significate 16 bytes from K_NAS_ENC 32 bytes
        ue.k_nas_enc = ue.k_nas_enc[16:]
        # Get K_NAS_INT
        k_nas_int = conv_501_A8(ue.k_amf, alg_type=2, alg_id=1)
        ue.set_k_nas_int(k_nas_int)
        ue.k_nas_int = ue.k_nas_int[16:]
        # Set state
        ue.state = FGMMState.AUTHENTICATED_INITIATED
        return Msg.to_bytes(), ue

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
    def __init__(self) -> None:
        super().__init__()

    def receive(self, data: bytes, ue: UE) -> bytes:
        Msg, err = parse_NAS5G(data)
        if err:
            return
        # check if message is encrypted
        if Msg['5GMMHeaderSec']['SecHdr'].get_val() == 2:
            logger.debug("Processing Encrypted NAS Message")
            # decrypt message
            Msg.decrypt(ue.k_nas_enc, dir=1, fgea=1, seqnoff=0, bearer=1)
            Msg, err = parse_NAS5G(Msg._dec_msg)
            if err:
                logger.error("Error decrypting NAS Message")
                return
            return Msg, ue
        else:
            logger.debug("Processing Unencrypted NAS Message")
            return Msg, ue

    def send(self, data: bytes) -> int:
        """ Send data to the socket. """
        return b''

    def create_req(self):
        IEs = {}
        IEs['5GMMHeaderSec'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 4 }
        Msg = FGMMSecProtNASMessage(val=IEs)
        return Msg


class SecurityModeProc(NASProc):

    def __init__(self) -> None:
        super().__init__()

    def send(self, data: bytes) -> bytes:
        """ Send data to the socket. """
        return b''
    
    def receive(self, data: bytes, ue: UE) -> bytes:
        Msg, err = parse_NAS5G(data)

        if not self.verify_security_capabilities(Msg):
            return b''

        # TODO: validate integrity protection

        # Create registration message
        RegIEs = {}
        RegIEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65 }
        RegIEs['NAS_KSI'] = { 'TSC': 0, 'Value': 7 }
        RegIEs['5GSRegType'] = { 'FOR': 1, 'Value': 1 }
        RegIEs['5GSID'] = { 'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': { 'PLMN': ue.mcc + ue.mnc, 'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': encode_bcd(ue.msin) } }
        RegIEs['UESecCap'] = { '5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0, '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0, '5G-IA6': 0, '5G-IA7': 0, 'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0, 'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0 }
        RegIEs['5GSUpdateType'] = {'EPS-PNB-CIoT': 0, '5GS-PNB-CIoT': 0, 'NG-RAN-RCU': 0, 'SMSRequested': 0 }
        RegIEs['5GMMCap'] = {'SGC': 0, '5G-HC-CP-CIoT': 0, 'N3Data': 0, '5G-CP-CIoT': 0, 'RestrictEC': 0, 'LPP': 0, 'HOAttach': 0, 'S1Mode': 0 }
        RegIEs['NSSAI'] = [ {'SNSSAI': s } for s in ue.nssai ]

        RegMsg = FGMMRegistrationRequest(val=RegIEs)
        # Note: to only send specified IEs for 5GMMCap
        # RegMsg['5GMMCap']['L'].set_val(1)

        # Send Security Mode Complete
        IEs = {}
        IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0 }
        IEs['IMEISV'] = {'Type': FGSIDTYPE_IMEISV, 'Digit1': int(ue.imeiSv[0]), 'Digits': ue.imeiSv[1:]}
        IEs['NASContainer'] = { }
        
        Msg = FGMMSecurityModeComplete(val=IEs)
        Msg['NASContainer']['V'].set_val(RegMsg.to_bytes())
        # Encrypt NAS message
        SecMsg = SecProtNASMessageProc().create_req()
        SecMsg['NASMessage'].set_val(Msg.to_bytes())
        SecMsg.encrypt(key=ue.k_nas_enc, dir=0, fgea=1, seqnoff=0, bearer=1)
        SecMsg.mac_compute(key=ue.k_nas_int, dir=0, fgia=1, seqnoff=0, bearer=1)
        # Set state
        ue.state = FGMMState.SECURITY_MODE_INITIATED
        return SecMsg.to_bytes(), ue

    def verify_security_capabilities(self, msg) -> bool:
        # algo = msg['5GMMSecurityModeCommand']['NASSecAlgo'].get_val()
        return True

class RegistrationProc(NASProc):

    def __init__(self) -> None:
        super().__init__()

    def initiate(self, ue: UE) -> bytes:
        IEs = {}
        IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65 }
        IEs['NAS_KSI'] = { 'TSC': 0, 'Value': 7 }
        IEs['5GSRegType'] = { 'FOR': 1, 'Value': 1 }
        IEs['5GSID'] = { 'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': { 'PLMN': ue.mcc + ue.mnc, 'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': encode_bcd(ue.msin) } }
        IEs['UESecCap'] = { '5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0, '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0, '5G-IA6': 0, '5G-IA7': 0, 'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0, 'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0 }
        Msg = FGMMRegistrationRequest(val=IEs)
        ue.state = FGMMState.REGISTERED_INITIATED
        return Msg.to_bytes(), ue

class RegistrationAcceptProc():

    def receive(self, data: bytes, ue: UE) -> bytes:
        Msg, err = parse_NAS5G(data)
        if not err:
            ue.state = FGMMState.REGISTERED
            return None, ue
        else:
            logger.error('Error parsing NAS message: %s', err)
            return None, ue
    
# Function to process NAS procedure
def process_nas_procedure(data: bytes, ue: UE) -> bytes:
    """ Process NAS procedure. """
    
    # Print NAS PDU name

    if not ue.amf_ue_ngap_id: # If AMF UE NGAP ID is not set send registration request
        # Create Registration Request
        RegReq, _ = RegistrationProc().initiate(ue)
        # Send Registration Request
        logger.debug("Sending registration request for UE: %s", ue)
        return RegReq, ue
    # Create NAS object
    NAS_PDU, err = parse_NAS5G(data)
    if err:
        logger.error('Error parsing NAS message: %s', err)
        return b''
    if NAS_PDU._name == '5GMMAuthenticationRequest':
        tx_nas_pdu, ue = AuthenticationProc().receive(data, ue)
        logger.debug("Sending authentication response for UE: %s", ue)
        return tx_nas_pdu, ue
    elif NAS_PDU._name == '5GMMSecProtNASMessage':
        # Check if NAS message is integrity protected
        DEC_PDU, ue = SecProtNASMessageProc().receive(data, ue)
        if DEC_PDU._by_name.count('5GMMSecurityModeCommand') > 0:
            smc = DEC_PDU['5GMMSecurityModeCommand'].to_bytes()
            tx_nas_pdu, ue = SecurityModeProc().receive(smc, ue)
            logger.debug("Sending security mode complete for UE: %s", ue)
            return tx_nas_pdu, ue
        elif DEC_PDU._name == '5GMMRegistrationAccept':
            ra = DEC_PDU.to_bytes()
            tx_nas_pdu, ue = RegistrationAcceptProc().receive(ra, ue)
            logger.debug("Sending registration complete for UE: %s", ue)
            return tx_nas_pdu, ue

    return None

class NAS():
    
    def __init__(self, logger_queue, nas_dl_queue, nas_ul_queue, ue_list):
        self.nas_dl_queue = nas_dl_queue
        self.nas_ul_queue = nas_ul_queue
        self.ue_list = ue_list
        # add a handler that uses the shared queue
        logger.addHandler(QueueHandler(logger_queue))
        # log all messages, debug and up
        logger.setLevel(logging.INFO)

    def _load_nas_dl_thread(self):
        """ Load the thread that will handle NAS DownLink messages from gNB """
        nas_dl_thread = threading.Thread(target=self._nas_dl_thread_function)
        nas_dl_thread.start()
        return nas_dl_thread

    def _nas_dl_thread_function(self):
        """ Thread function that will handle NAS DownLink messages from gNB 
        
            It will select the NAS procedure to be executed based on the NAS message type.
            When the NAS procedure is completed, the NAS message will be put on a queue 
            that will be read by the gNB thread.
        """
        while True:
            if not self.nas_dl_queue.empty():
            # data is None when it's a registration request
                data, ue = self.nas_dl_queue.get()
                tx_nas_pdu, ue_ = process_nas_procedure(data, ue)
                # Update ue in list
                self.ue_list[int(ue.supi[-10:])] = ue_
                if tx_nas_pdu:
                    self.nas_ul_queue.put((tx_nas_pdu, ue_))

    def run(self):
        """ Run the NAS thread """
        self._load_nas_dl_thread()
