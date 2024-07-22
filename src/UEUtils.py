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

# 3GPP TS 24.501 version 16.5.1 Section 9.7 (Table 9.7.1 + Table 9.7.2)
# Maps the names defined by pycrate to the code
fg_msg_names = {
    # Message types for 5GS mobility management
    # registration
    65: "5GMMRegistrationRequest",
    66: "5GMMRegistrationAccept",
    67: "5GMMRegistrationComplete",
    68: "5GMMRegistrationReject",
    69: "5GMMMODeregistrationRequest",
    70: "5GMMMODeregistrationAccept",
    71: "5GMMMTDeregistrationRequest",
    72: "5GMMMTDeregistrationAccept",
    73: "5GMMMODeregistrationComplete",  # For internal use only, it's not a real message type
    74: "5GMMANConnectionReleaseComplete",  # For internal use only, it's not a real message type
    # # service request
    # 76: "5GMMServiceRequest",
    # 77: "5GMMServiceReject",
    # 78: "5GMMServiceAccept",
    # 79: "5GMMControlPlaneServiceRequest",
    # # slice-specific auth
    # 80: "5GMMNetworkSliceSpecificAuthenticationCommand",
    # 81: "5GMMNetworkSliceSpecificAuthenticationComplete",
    # 82: "5GMMNetworkSliceSpecificAuthenticationResult",
    # common procedures
    83: "5GMMConfigurationUpdateIgnore", # For internal use only, it's not a real message type
    84: "5GMMConfigurationUpdateCommand",
    85: "5GMMConfigurationUpdateComplete",
    86: "5GMMAuthenticationRequest",
    87: "5GMMAuthenticationResponse",
    88: "5GMMAuthenticationReject",
    89: "5GMMAuthenticationFailure",
    90: "5GMMAuthenticationResult",
    # 91: "5GMMIdentityRequest",
    # 92: "5GMMIdentityResponse",
    93: "5GMMSecurityModeCommand",
    94: "5GMMSecurityModeComplete",
    95: "5GMMSecurityModeReject",
    # misc
    # 100: "5GMM5GMMStatus",  # Already had "5GMM" at the beginning
    # 101: "5GMMNotification",
    # 102: "5GMMNotificationResponse",
    103: "5GMMULNasTransport",
    104: "5GMMDLNasTransport",

    # Message types for 5GS session management
    #
    193: "5GSMPDUSessionEstabRequest",
    194: "5GSMPDUSessionEstabAccept",
    195: "5GSMPDUSessionEstabReject",
    196: "5GSMPDUSessionTransmission", # For internal use only, it's not a real message type
    # #
    # 197: "5GSMPDUSessionAuthenticationCommand",
    # 198: "5GSMPDUSessionAuthenticationComplete",
    # 199: "5GSMPDUSessionAuthenticationResult",
    # #
    # 201: "5GSMPDUSessionModificationRequest",
    # 202: "5GSMPDUSessionModificationReject",
    # 203: "5GSMPDUSessionModificationCommand",
    # 204: "5GSMPDUSessionModificationComplete",
    # 205: "5GSMPDUSessionModificationCommandReject",
    # #
    # 209: "5GSMPDUSessionReleaseRequest",
    # 210: "5GSMPDUSessionReleaseReject",
    # 211: "5GSMPDUSessionReleaseCommand",
    # 212: "5GSMPDUSessionReleaseComplete",
    # #
    # 214: "5GSM5GSMStatus"  # Already had "5GSM" at the beginning
}
fg_msg_codes = {value: key for key, value in fg_msg_names.items()}
FGMM_MIN_TYPE = 65 # The minimum value of the 5G MM  Message types (registration request)
FGSM_MIN_TYPE = 193 # he minimum value of the 5G SM Message types (PDU session establishment request)
FGMM_MAX_TYPE = 104 # The minimum value of the 5G MM  Message types (registration request)
FGSM_MAX_TYPE = 196 # The minimum value of the 5G SM Message types (PDU session establishment request)

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
        return Msg

def security_prot_decrypt(Msg, ue):
    
    # check if message is encrypted
    if Msg['5GMMHeaderSec']['SecHdr'].get_val() == 2:
        # TODO: Add integrity check
        # decrypt message
        try:
            Msg.decrypt(ue.k_nas_enc, dir=1, fgea=ue.CiphAlgo, seqnoff=0, bearer=1)
            Msg, err = parse_NAS5G(Msg._dec_msg)
            if err:
                return None
            return Msg
        except:
            logger.error("Failed to decrypt Msg \n\n", Msg.show())
            return None

    else:
        return Msg
    
def dl_nas_transport_extract(Msg, ue):
    return Msg['PayloadContainer'][1]