import logging
from enum import IntEnum
from binascii import unhexlify, hexlify
from pycrate_mobile.TS24008_IE import encode_bcd
from pycrate_mobile.TS24501_IE import FGSIDTYPE_IMEISV
from pycrate_mobile.NAS import FGMMRegistrationRequest, FGMMMODeregistrationRequest, FGMMRegistrationComplete, FGMMAuthenticationResponse, FGMMSecProtNASMessage, FGMMSecurityModeComplete
from pycrate_mobile.NAS5G import parse_NAS5G
from CryptoMobile.Milenage import Milenage, make_OPc
from CryptoMobile.conv import conv_501_A2, conv_501_A4, conv_501_A6, conv_501_A7, conv_501_A8

logger = logging.getLogger('__UESim__') 

def byte_xor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


class FGMMState(IntEnum):
    """ 5GMM State: 3GPP TS 24.501 version 16.9.0 Release 16, Section 5. """
    NULL = 0
    REGISTERED_INITIATED = 1
    REGISTERED = 2
    DEREGISTERED_INITIATED = 3
    SERVICE_REQUEST_INITIATED = 4
    # Not in 3GPP TS 24.501 version 16.9.0 Release 16, Section 5.
    AUTHENTICATED_INITIATED = 5
    AUTHENTICATED = 6
    SECURITY_MODE_INITIATED = 7
    SECURITY_MODE_COMPLETED = 8
    PDU_SESSION_REQUESTED = 9
    PDU_SESSION_ESTABLISHED = 10
    PDU_SESSION_TRANSMITTING = 11
    # 
    NO_RESPONSE = 12
    # The states below can be used to check end of session or test
    DEREGISTERED = 13 # In 3GPP TS 24.501 version 16.9.0 Release 16, Section 5.
    CONNECTION_RELEASED = 14
    # The states are for compliance test
    FAIL = 15
    PASS = 16
    # Last state indicate number of states
    FGMM_STATE_MAX = 17

def security_prot_encrypt(ue, Msg):
    if ue.CiphAlgo == 0:
        return Msg
    IEs = {}
    IEs['5GMMHeaderSec'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 4 }
    SecMsg = FGMMSecProtNASMessage(val=IEs)
    SecMsg['NASMessage'].set_val(Msg.to_bytes())
    SecMsg.encrypt(key=ue.k_nas_enc, dir=0, fgea=ue.CiphAlgo, seqnoff=0, bearer=1)
    SecMsg.mac_compute(key=ue.k_nas_int, dir=0, fgia=ue.IntegAlgo, seqnoff=0, bearer=1)
    return SecMsg

def security_prot_encrypt_ciphered(ue, Msg):
    try:
        IEs = {}
        if ue.CiphAlgo != 0:
            IEs['5GMMHeaderSec'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 2 }
        else:
            IEs['5GMMHeaderSec'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0 }
            # return Msg
        SecMsg = FGMMSecProtNASMessage(val=IEs)
        SecMsg['NASMessage'].set_val(Msg.to_bytes())
        if ue.CiphAlgo != 0:
            SecMsg.encrypt(key=ue.k_nas_enc, dir=0, fgea=ue.CiphAlgo, seqnoff=0, bearer=1)
        if ue.IntegAlgo != 0:
            SecMsg.mac_compute(key=ue.k_nas_int, dir=0, fgia=ue.IntegAlgo, seqnoff=0, bearer=1)
        return SecMsg
    except:
        # print(f"ue.CiphAlgo {ue.CiphAlgo} ue.IntegAlgo {ue.IntegAlgo} ue.state {ue}")
        return Msg

def security_prot_decrypt(Msg, ue):
    
    # check if message is encrypted
    if Msg['5GMMHeaderSec']['SecHdr'].get_val() == 2:
        # TODO: Add integrity check
        # decrypt message
        Msg.decrypt(ue.k_nas_enc, dir=1, fgea=ue.CiphAlgo, seqnoff=0, bearer=1)
        Msg, err = parse_NAS5G(Msg._dec_msg)
        if err:
            return None
        return Msg
    else:
        return Msg
    
def dl_nas_transport_extract(Msg, ue):
    return Msg['PayloadContainer'][1]
