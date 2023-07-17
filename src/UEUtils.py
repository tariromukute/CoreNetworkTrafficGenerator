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
    DEREGISTERED = 1
    REGISTERED_INITIATED = 2
    REGISTERED = 3
    DEREGISTERED_INITIATED = 4
    SERVICE_REQUEST_INITIATED = 5
    # Not in 3GPP TS 24.501 version 16.9.0 Release 16, Section 5.
    AUTHENTICATED_INITIATED = 6
    AUTHENTICATED = 7
    SECURITY_MODE_INITIATED = 8
    SECURITY_MODE_COMPLETED = 9
    PDU_SESSION_REQUESTED = 10
    PDU_SESSION_ESTABLISHED = 11
    # The states are for compliance test
    FAIL = 12
    PASS = 13
    # Last state indicate number of states
    FGMM_STATE_MAX = 14

def security_prot_encrypt(ue, Msg):
    IEs = {}
    IEs['5GMMHeaderSec'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 4 }
    SecMsg = FGMMSecProtNASMessage(val=IEs)
    SecMsg['NASMessage'].set_val(Msg.to_bytes())
    SecMsg.encrypt(key=ue.k_nas_enc, dir=0, fgea=1, seqnoff=0, bearer=1)
    SecMsg.mac_compute(key=ue.k_nas_int, dir=0, fgia=1, seqnoff=0, bearer=1)
    return SecMsg

def security_prot_decrypt(Msg, ue):
    # Msg, err = parse_NAS5G(data)
    # if err:
    #     return
    # check if message is encrypted
    if Msg['5GMMHeaderSec']['SecHdr'].get_val() == 2:
        # decrypt message
        Msg.decrypt(ue.k_nas_enc, dir=1, fgea=1, seqnoff=0, bearer=1)
        Msg, err = parse_NAS5G(Msg._dec_msg)
        if err:
            return None
        return Msg
    else:
        return Msg
    
def dl_nas_transport_extract(Msg, ue):
    return Msg['PayloadContainer'][1]