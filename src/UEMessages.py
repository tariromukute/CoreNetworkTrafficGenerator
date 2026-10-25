from src.UEUtils import *
import socket
from pycrate_mobile.TS24008_IE import encode_bcd
from pycrate_mobile.TS24501_IE import FGSIDTYPE_IMEISV
from pycrate_mobile.NAS import FGMMRegistrationRequest, FGMMMODeregistrationRequest, FGMMRegistrationComplete, FGMMAuthenticationResponse, FGMMSecProtNASMessage, FGMMSecurityModeComplete, FGMMULNASTransport, FGMMConfigurationUpdateCommand, FGMMConfigurationUpdateComplete
from pycrate_mobile.TS24501_FGSM import FGSMPDUSessionEstabRequest
from pycrate_mobile.NAS5G import parse_NAS5G
from CryptoMobile.Milenage import Milenage, make_OPc
from CryptoMobile.conv import conv_501_A2, conv_501_A4, conv_501_A6, conv_501_A7, conv_501_A8
from scapy.all import *
import binascii
import time
from src.nascache import MessageTemplate
from src import nasfast

# The messages the UEs send, with the IEs that are the same for every UE (src/nascache.py: each
# thread reuses one object per message instead of cloning pycrate's template for every message)
_UE_SEC_CAP = {'5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0,
               '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0, '5G-IA6': 0, '5G-IA7': 0,
               'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0,
               'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0}
REGISTRATION_REQUEST = MessageTemplate(FGMMRegistrationRequest, {
    '5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65},
    'NAS_KSI': {'TSC': 0, 'Value': 7},
    '5GSRegType': {'FOR': 1, 'Value': 1},
    'UESecCap': _UE_SEC_CAP})
# The Registration Request in the Security Mode Complete's NAS message container
SMC_REGISTRATION_REQUEST = MessageTemplate(FGMMRegistrationRequest, {
    **REGISTRATION_REQUEST.fixed,
    '5GSUpdateType': {'EPS-PNB-CIoT': 0, '5GS-PNB-CIoT': 0, 'NG-RAN-RCU': 0, 'SMSRequested': 0},
    '5GMMCap': {'SGC': 0, '5G-HC-CP-CIoT': 0, 'N3Data': 0, '5G-CP-CIoT': 0, 'RestrictEC': 0, 'LPP': 0, 'HOAttach': 0, 'S1Mode': 0}})
REGISTRATION_COMPLETE = MessageTemplate(FGMMRegistrationComplete, {
    '5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 67}})
MO_DEREGISTRATION_REQUEST = MessageTemplate(FGMMMODeregistrationRequest, {
    '5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 69},
    'NAS_KSI': {'TSC': 0, 'Value': 7},
    'DeregistrationType': {'SwitchOff': 0, 'ReregistrationRequired': 0, 'AccessType': 1}})
AUTHENTICATION_RESPONSE = MessageTemplate(FGMMAuthenticationResponse, {
    '5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 87}})
SECURITY_MODE_COMPLETE = MessageTemplate(FGMMSecurityModeComplete, {
    '5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0}})
PDU_SESSION_ESTABLISHMENT_REQUEST = MessageTemplate(FGSMPDUSessionEstabRequest, {
    '5GSMHeader': {'EPD': 46, 'PDUSessID': 1, 'PTI': 1, 'Type': 193},
    'PDUSessType': {'Value': 1},
    'SSCMode': {'Value': 1}})
UL_NAS_TRANSPORT = MessageTemplate(FGMMULNASTransport, {
    'FGMMHeader': {'EPD': 46, 'spare': 0, 'SecHdr': 0, 'Type': 103},   # not an IE name: pycrate ignores it
    'PayloadContainerType': {'V': 1},
    'PDUSessID': 1,
    'RequestType': {'Value': 1}})


def suci(ue):
    """ The UE's SUCI, with the null protection scheme (5GS mobile identity, TS 24.501 §9.11.3.4) """
    return {'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': {'PLMN': ue.mcc + ue.mnc,
            'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': encode_bcd(ue.msin)}}


def _fast(IEs):
    """ Whether a builder may take its message from src/nasfast.py's templates, which have the IEs it
    sets itself (and none from the caller), else it builds it with pycrate """
    return not IEs and nasfast.enabled()


def registration_request(ue, IEs, Msg=None):
    Msg = nasfast.build(nasfast.registration_request, ue) if _fast(IEs) else None
    if Msg is None:
        IEs['5GSID'] = suci(ue)
        Msg = REGISTRATION_REQUEST.build(IEs)
    ue.MsgInBytes = Msg.to_bytes()
    ue.set_state(FGMMState.REGISTERED_INITIATED)
    ue.set_procedure(65)
    ue.start_time = time.time()
    return Msg, '5GMMRegistrationRequest'


def registration_complete(ue, IEs, Msg=None):
    # IEs['SORTransContainer'] = { 'ListInd': }
    SecMsg = nasfast.protect(ue, nasfast.REGISTRATION_COMPLETE) if _fast(IEs) else None
    if SecMsg is not None:
        ue.MsgInBytes = nasfast.REGISTRATION_COMPLETE
    else:
        Msg, = REGISTRATION_COMPLETE.build(IEs)
        ue.MsgInBytes = Msg.to_bytes()
        SecMsg = security_prot_encrypt_ciphered(ue, Msg)
    ue.set_state(FGMMState.REGISTERED)
    return SecMsg, '5GMMRegistrationComplete'
    # return Msg, '5GMMRegistrationComplete'

# TODO: handle recording of operation
def configuration_update_complete(ue, IEs, Msg=None):
    # When UE is in 5GMM-DEREGISTERED-INITIATED state ignore request (https://itecspec.com/spec/3gpp-38-523-1-9-1-6-de-registration/)
    if ue.state == FGMMState.DEREGISTERED_INITIATED:
        return None, None
    # TODO: implement action before response
    SecMsg = nasfast.protect(ue, nasfast.CONFIGURATION_UPDATE_COMPLETE) if _fast(IEs) else None
    if SecMsg is not None:
        ue.MsgInBytes = nasfast.CONFIGURATION_UPDATE_COMPLETE
        return SecMsg, None
    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 85}
    Msg = FGMMConfigurationUpdateComplete(val=IEs)
    ue.MsgInBytes = Msg.to_bytes()
    SecMsg = security_prot_encrypt_ciphered(ue, Msg)
    return SecMsg, None

def mo_deregistration_request(ue, IEs, Msg=None):
    plain = nasfast.build(nasfast.mo_deregistration_request, ue) if _fast(IEs) else None
    SecMsg = nasfast.protect(ue, plain) if plain is not None else None
    if SecMsg is not None:
        ue.MsgInBytes = plain
        ue.set_state(FGMMState.DEREGISTERED_INITIATED)
        return SecMsg, '5GMMMODeregistrationRequest'
    IEs['5GSID'] = suci(ue)
    Msg = MO_DEREGISTRATION_REQUEST.build(IEs)
    ue.MsgInBytes = Msg.to_bytes()
    ue.set_state(FGMMState.DEREGISTERED_INITIATED)
    SecMsg = security_prot_encrypt_ciphered(ue, Msg)
    return SecMsg, '5GMMMODeregistrationRequest'

def deregistration_complete(ue, IEs, Msg=None):
    ue.set_state(FGMMState.DEREGISTERED)
    return None, '5GMMANConnectionReleaseComplete'  # For internal use only, it's not a real message type

def authentication_response(ue, IEs, Msg):
    # Msg, err = parse_NAS_MO(data)
    # if err:
    #     return
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
    RES, CK, IK, _ = Mil.f2345(key, rand)
    Res = conv_501_A4(CK, IK, ue.sn_name, rand, RES)

    Msg = nasfast.authentication_response(Res) if _fast(IEs) else None
    if Msg is None:
        IEs['RES'] = Res
        Msg = AUTHENTICATION_RESPONSE.build(IEs)
    ue.MsgInBytes = Msg.to_bytes()
    # Note: See CryptoMobile.conv for documentation of this function and arguments
    # Get K_AUSF
    ue.k_ausf = conv_501_A2(CK, IK, ue.sn_name, sqn_xor_ak)
    # Get K_SEAF
    ue.k_seaf = conv_501_A6(ue.k_ausf, ue.sn_name)
    # Get K_AMF
    ue.k_amf = conv_501_A7(ue.k_seaf, ue.supi.encode('ascii'), abba)
    
    ue.set_state(FGMMState.AUTHENTICATED_INITIATED)
    return Msg, '5GMMAuthenticationResponse'
    
def security_mode_complete(ue, IEs, Msg):
    NASSecAlgo = Msg['NASSecAlgo']['NASSecAlgo'].get_val_d()
    ue.CiphAlgo = NASSecAlgo['CiphAlgo']
    ue.IntegAlgo = NASSecAlgo['IntegAlgo']
    # Get K_NAS_ENC
    ue.k_nas_enc = conv_501_A8(ue.k_amf, alg_type=1, alg_id=NASSecAlgo['CiphAlgo'])
    # Get least significate 16 bytes from K_NAS_ENC 32 bytes
    ue.k_nas_enc = ue.k_nas_enc[16:]
    # Get K_NAS_INT
    k_nas_int = conv_501_A8(ue.k_amf, alg_type=2, alg_id=NASSecAlgo['IntegAlgo'])
    ue.set_k_nas_int(k_nas_int)
    ue.k_nas_int = ue.k_nas_int[16:]
    plain = nasfast.build(nasfast.security_mode_complete, ue) if _fast(IEs) else None
    # the first message of the new NAS security context, uplink COUNT 0
    SecMsg = nasfast.protect(ue, plain, count=0) if plain is not None else None
    if SecMsg is not None:
        ue.MsgInBytes = plain
        ue.set_state(FGMMState.SECURITY_MODE_INITIATED)
        return SecMsg, '5GMMSecurityModeComplete'
    RegIEs = {}
    RegIEs['5GSID'] = suci(ue)
    RegIEs['NSSAI'] = [{'SNSSAI': s} for s in ue.nssai]

    RegMsg = SMC_REGISTRATION_REQUEST.build(RegIEs)
    IEs['IMEISV'] = {'Type': FGSIDTYPE_IMEISV, 'Digit1': int(ue.imeiSv[0]), 'Digits': ue.imeiSv[1:]}
    IEs['NASContainer'] = { }
    
    Msg = SECURITY_MODE_COMPLETE.build(IEs)
    Msg['NASContainer']['V'].set_val(RegMsg.to_bytes())
    ue.MsgInBytes = Msg.to_bytes()
    # Encrypt NAS message: the first message of the new NAS security context, uplink COUNT 0
    ue.ul_nas_count = 0
    SecMsg = security_prot_encrypt_ciphered(ue, Msg)
    ue.set_state(FGMMState.SECURITY_MODE_INITIATED)
    return SecMsg, '5GMMSecurityModeComplete'

def pdu_session_establishment_request(ue, IEs, Msg):
    """ 3GPP TS 24.501 version 15.7.0 6.4.1.2
    
    """
    plain = nasfast.build(nasfast.ul_nas_transport_pdu_session_establishment_request, ue) if _fast(IEs) else None
    SecMsg = nasfast.protect(ue, plain) if plain is not None else None
    if SecMsg is not None:
        ue.MsgInBytes = nasfast.PDU_SESSION_ESTABLISHMENT_REQUEST
        ue.set_state(FGMMState.PDU_SESSION_REQUESTED)
        return SecMsg, '5GSMPDUSessionEstabRequest'
    Msg = PDU_SESSION_ESTABLISHMENT_REQUEST.build(IEs)
    ue.MsgInBytes = Msg.to_bytes()
    ULIEs = {}
    # The session's DNN and S-NSSAI from the UE's configuration (sessions[0]), as UERANSIM sends
    # them; without a DNN the AMF picks the subscriber's default
    session = ue.sessions[0] if getattr(ue, 'sessions', None) else {}
    s_slice = session.get('slice')
    ULIEs['SNSSAI'] = ({'SST': int(s_slice['sst']), 'SD': int(s_slice['sd'])} if 'sd' in s_slice
                       else {'SST': int(s_slice['sst'])}) if s_slice else ue.nssai[0]
    if session.get('apn'):
        ULIEs['DNN'] = session['apn']
    ULMsg = UL_NAS_TRANSPORT.build(ULIEs)
    ULMsg['PayloadContainer']['V'].set_val(ue.MsgInBytes)
    # Encrypt NAS message
    SecMsg = security_prot_encrypt_ciphered(ue, ULMsg)

    ue.set_state(FGMMState.PDU_SESSION_REQUESTED)
    return SecMsg, '5GSMPDUSessionEstabRequest'

def pdu_session_establishment_complete(ue, IEs, Msg=None):
    address = Msg['PDUAddress']['PDUAddress'].get_val_d()
    ue.IpAddress = address # Format is {'spare': 0, 'Type': 1, 'Addr': b'\x0c\x01\x01\x07'} with type of address
    ip_addr = socket.inet_ntoa(address['Addr'])
    logger.debug(f"UE {ue.supi} assigned address {ip_addr}")
    ue.set_state(FGMMState.PDU_SESSION_ESTABLISHED)
    return None, '5GSMPDUSessionEstabComplete' # For internal use only, it's not a real message type

def connection_release_complete(ue, IEs, Msg=None):
    ue.set_state(FGMMState.CONNECTION_RELEASED)
    ue.set_procedure(74)
    ue.end_time = time.time()
    return None, '5GMMANConnectionReleaseComplete'  # For internal use only, it's not a real message type

def pdu_session_generate_traffic(ue, IEs, Msg=None):
    ue.set_state(FGMMState.PDU_SESSION_TRANSMITTING)
    return ue.IpAddress['Addr'], '5GSMPDUSessionTransmission'