from UEUtils import *
import socket
from pycrate_mobile.TS24008_IE import encode_bcd
from pycrate_mobile.TS24501_IE import FGSIDTYPE_IMEISV
from pycrate_mobile.NAS import FGMMRegistrationRequest, FGMMMODeregistrationRequest, FGMMRegistrationComplete, FGMMAuthenticationResponse, FGMMSecProtNASMessage, FGMMSecurityModeComplete, FGMMULNASTransport
from pycrate_mobile.TS24501_FGSM import FGSMPDUSessionEstabRequest
from pycrate_mobile.NAS5G import parse_NAS5G
from CryptoMobile.Milenage import Milenage, make_OPc
from CryptoMobile.conv import conv_501_A2, conv_501_A4, conv_501_A6, conv_501_A7, conv_501_A8

def registration_request(ue, IEs, Msg=None):
    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65}
    IEs['NAS_KSI'] = {'TSC': 0, 'Value': 7}
    IEs['5GSRegType'] = {'FOR': 1, 'Value': 1}
    IEs['5GSID'] = {'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': {'PLMN': ue.mcc + ue.mnc,
                                                                           'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': encode_bcd(ue.msin)}}
    IEs['UESecCap'] = {'5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0,
                       '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0, '5G-IA6': 0, '5G-IA7': 0,
                       'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0,
                       'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0}
    Msg = FGMMRegistrationRequest(val=IEs)
    ue.MsgInBytes = Msg.to_bytes()
    logger.debug(f"UE {ue.supi} sending registration_request")
    ue.set_state(FGMMState.REGISTERED_INITIATED)
    return Msg, '5GMMRegistrationRequest'


def registration_complete(ue, IEs, Msg=None):
    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 67}
    # IEs['SORTransContainer'] = { 'ListInd': }
    Msg, = FGMMRegistrationComplete(val=IEs)
    ue.MsgInBytes = Msg.to_bytes()
    SecMsg = security_prot_encrypt(ue, Msg)
    logger.debug(f"UE {ue.supi} sending registration_complete")
    ue.set_state(FGMMState.REGISTERED)
    return SecMsg, '5GMMRegistrationComplete'


def mo_deregistration_request(ue, IEs, Msg=None):
    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 69}
    IEs['NAS_KSI'] = {'TSC': 0, 'Value': 7}
    IEs['DeregistrationType'] = {'SwitchOff': 0, 'ReregistrationRequired': 0, 'AccessType': 1 }
    IEs['5GSID'] = {'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': {'PLMN': ue.mcc + ue.mnc,
                                                                           'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': encode_bcd(ue.msin)}}
    Msg = FGMMMODeregistrationRequest(val=IEs)
    ue.MsgInBytes = Msg.to_bytes()
    logger.debug(f"UE {ue.supi} sending mo_deregistration_request")
    ue.set_state(FGMMState.DEREGISTERED_INITIATED)
    return Msg, '5GMMMODeregistrationRequest'

def deregistration_complete(ue, IEs, Msg=None):
    ue.set_state(FGMMState.DEREGISTERED)
    return None, '5GMMMODeregistrationComplete'  # For internal use only, it's not a real message type

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

    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 87}
    IEs['RES'] = Res
    Msg = FGMMAuthenticationResponse(val=IEs)
    ue.MsgInBytes = Msg.to_bytes()
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
    
    logger.debug(f"UE {ue.supi} sending authentication_response")
    ue.set_state(FGMMState.AUTHENTICATED_INITIATED)
    return Msg, '5GMMAuthenticationResponse'
    
def security_mode_complete(ue, IEs, Msg):
    RegIEs = {}
    RegIEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65}
    RegIEs['NAS_KSI'] = {'TSC': 0, 'Value': 7}
    RegIEs['5GSRegType'] = {'FOR': 1, 'Value': 1}
    RegIEs['5GSID'] = {'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': {'PLMN': ue.mcc + ue.mnc,
                                                                              'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': encode_bcd(ue.msin)}}
    RegIEs['UESecCap'] = {'5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0, '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0,
                          '5G-IA6': 0, '5G-IA7': 0, 'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0, 'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0}
    RegIEs['5GSUpdateType'] = {
        'EPS-PNB-CIoT': 0, '5GS-PNB-CIoT': 0, 'NG-RAN-RCU': 0, 'SMSRequested': 0}
    RegIEs['5GMMCap'] = {'SGC': 0, '5G-HC-CP-CIoT': 0, 'N3Data': 0,
                         '5G-CP-CIoT': 0, 'RestrictEC': 0, 'LPP': 0, 'HOAttach': 0, 'S1Mode': 0}
    RegIEs['NSSAI'] = [{'SNSSAI': s} for s in ue.nssai]

    RegMsg = FGMMRegistrationRequest(val=RegIEs)
    IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0 }
    IEs['IMEISV'] = {'Type': FGSIDTYPE_IMEISV, 'Digit1': int(ue.imeiSv[0]), 'Digits': ue.imeiSv[1:]}
    IEs['NASContainer'] = { }
    
    Msg = FGMMSecurityModeComplete(val=IEs)
    Msg['NASContainer']['V'].set_val(RegMsg.to_bytes())
    ue.MsgInBytes = Msg.to_bytes()
    # Encrypt NAS message
    SecMsg = security_prot_encrypt(ue, Msg)
    logger.debug(f"UE {ue.supi} sending security_mode_complete")
    ue.set_state(FGMMState.SECURITY_MODE_INITIATED)
    return SecMsg, '5GMMRegistrationRequest'

def pdu_session_establishment_request(ue, IEs, Msg):
    """ 3GPP TS 24.501 version 15.7.0 6.4.1.2
    
    """
    IEs['5GSMHeader'] = {'EPD': 46,  'PDUSessID': 1, 'PTI': 1, 'Type': 193}
    IEs['PDUSessType'] = { 'Value': 1 }
    IEs['SSCMode'] = { 'Value': 1 }
    # IEs['SMPDUDNReqContainer'] = { }
    IEs['IntegrityProtMaxDataRate'] = { 'UPUL': 0xff, 'UPDL': 0xff }
    # IEs['5GSMCap'] = { }
    Msg = FGSMPDUSessionEstabRequest(val=IEs)
    ue.MsgInBytes = Msg.to_bytes()
    ULIEs = {}
    ULIEs['FGMMHeader'] = {'EPD': 46, 'spare': 0, 'SecHdr': 0, 'Type': 103 }
    ULIEs['PayloadContainerType'] = { 'V': 1 }
    ULIEs['PDUSessID'] = 1
    ULIEs['RequestType'] = { 'Value': 1 }
    ULIEs['DNN'] = [{ 'Value': b'default'} ]
    ULIEs['RequestType'] = { 'Value': 1 }
    ULIEs['SNSSAI'] =  ue.nssai[0] # { 'SNSSAI': ue.nssai[0] }
    # ULIEs['PayloadContainer'] = { '5GSMPDUSessionEstabRequest': {'5GSMHeader': {'EPD': 46, 'PDUSessID': 1, 'PTI': 1, 'Type': 193}, 'IntegrityProtMaxDataRate': {'IntegrityProtMaxDataRate': {'UPUL': 255, 'UPDL': 255}}, 'PDUSessType': {'T': 9, 'PDUSessType': {'spare': 0, 'Value': 1}}, 'SSCMode': {'T': 10, 'SSCMode': {'spare': 0, 'Value': 1}}, '5GSMCap': {'T': 40, 'L': 1, '5GSMCap': {'TPMIC': 0, 'ATSSS-ST': 0, 'EPT-S1': 0, 'MH6-PDU': 0, 'RQoS': 0, 'spare': b''}}, 'ExtProtConfig': {'T': 123, 'L': 7, 'ProtConfig': {'Ext': 1, 'spare': 0, 'Prot': 0, 'Config': [{'ID': 10, 'Len': 0, 'Cont': b''}, {'ID': 13, 'Len': 0, 'Cont': b''}]}}}}
    ULMsg = FGMMULNASTransport(val=ULIEs)
    ULMsg['PayloadContainer']['V'].set_val(Msg.to_bytes())
    # Encrypt NAS message
    SecMsg = security_prot_encrypt(ue, ULMsg)
    logger.debug(f"UE {ue.supi} sending pdu_session_establishment_request")
    ue.set_state(FGMMState.PDU_SESSION_REQUESTED)
    return SecMsg, '5GSMPDUSessionEstabRequest'

def pdu_session_establishment_complete(ue, IEs, Msg=None):
    address = Msg['PDUAddress']['PDUAddress'].get_val_d()
    ue.IpAddress = address # Format is {'spare': 0, 'Type': 1, 'Addr': b'\x0c\x01\x01\x07'} with type of address
    ip_addr = socket.inet_ntoa(address['Addr'])
    logger.info(f"UE {ue.supi} assigned address {ip_addr}")
    ue.set_state(FGMMState.PDU_SESSION_ESTABLISHED)
    return None, '5GSMPDUSessionEstabComplete' # For internal use only, it's not a real message type