from UEUtils import *
from pycrate_mobile.TS24008_IE import encode_bcd
from pycrate_mobile.TS24501_IE import FGSIDTYPE_IMEISV
from pycrate_mobile.NAS import FGMMRegistrationRequest, FGMMMODeregistrationRequest, FGMMRegistrationComplete, FGMMAuthenticationResponse, FGMMSecProtNASMessage, FGMMSecurityModeComplete
from pycrate_mobile.NAS5G import parse_NAS5G
from CryptoMobile.Milenage import Milenage, make_OPc
from CryptoMobile.conv import conv_501_A2, conv_501_A4, conv_501_A6, conv_501_A7, conv_501_A8

# --------------------------------------------------------
# Section 1: Registration Request validations 
# --------------------------------------------------------

def registration_request_protocol_error(ue, IEs, Msg=None):
    """ 3GPP TS 24.501 version 15.7.0 5.5.1.2.8 b)
    If the REGISTRATION REQUEST message is received with a protocol error, the AMF shall return a 
    REGISTRATION REJECT message with one of the following 5GMM cause values: 
    #96 invalid mandatory information; 
    #99 information element non-existent or not implemented; 
    #100 conditional IE error; or 
    #111 protocol error, unspecified.


    """

    # TODO: implement method

    return Msg, '5GMMRegistrationRequest'

def registration_request_timeout(ue, IEs, Msg=None):
    """ 3GPP TS 24.501 version 15.7.0 5.5.1.2.8 c)
    On the first expiry of the timer, the AMF shall retransmit the REGISTRATION ACCEPT message and shall 
    reset and restart timer T3550. 

    """

    # TODO: implement method

    return Msg, '5GMMRegistrationRequest'

def registration_request_resent(ue, IEs, Msg=None):
    """ 3GPP TS 24.501 version 15.7.0 5.5.1.2.8 d)
    REGISTRATION REQUEST message received after the REGISTRATION ACCEPT message has been sent 
    and before the REGISTRATION COMPLETE message is received.
    """

    # TODO: implement method

    return Msg, '5GMMRegistrationRequest'

def registration_request_implicit_deregistration(ue, IEs, Msg=None):
    """ 3GPP TS 24.501 version 15.7.0 5.5.1.2.8 g)
    REGISTRATION REQUEST message with 5GS registration type IE set to "mobility registration updating" or 
    "periodic registration updating" received before REGISTRATION COMPLETE message.


    """

    # TODO: implement method

    return Msg, '5GMMRegistrationRequest'

def registration_request_early_deregistration(ue, IEs, Msg=None):
    """ 3GPP TS 24.501 version 15.7.0 5.5.1.2.8 h)
    DEREGISTRATION REQUEST message received before REGISTRATION COMPLETE message

    """

    # TODO: implement method

    return Msg, '5GMMRegistrationRequest'

def registration_request_invalid_security_capabilities(ue, IEs, Msg=None):
    """ 3GPP TS 24.501 version 15.7.0 5.5.1.2.8 i)
    UE security capabilities invalid or unacceptable

    """

    # TODO: implement method

    return Msg, '5GMMRegistrationRequest'

# --------------------------------------------------------
# Section 2: Authentication Response validations 
# --------------------------------------------------------

def authentication_response_invalid_rand(ue, IEs, Msg):
    
    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 87}
    IEs['RES'] = b'\x00\x00z\x00\x00\x00\x00\x00/\x00\x00x\x00\x00\x00\x00'
    Msg = FGMMAuthenticationResponse(val=IEs)
    ue.MsgInBytes = Msg.to_bytes()
    
    logger.debug(f"UE {ue.supi} sending authentication_response")
    ue.set_state(FGMMState.AUTHENTICATED_INITIATED)
    return Msg, '5GMMAuthenticationResponse'

# --------------------------------------------------------
# Section 3: Security Mode Complete validations 
# --------------------------------------------------------
def security_mode_complete_missing_nas_container(ue, IEs, Msg):
    NASSecAlgo = Msg['NASSecAlgo']['NASSecAlgo'].get_val_d()
    ue.CiphAlgo = NASSecAlgo['CiphAlgo']
    ue.IntegAlgo = NASSecAlgo['IntegAlgo']
    # print(f"Set Algo {ue.CiphAlgo} and {ue.IntegAlgo}")
    # Get K_NAS_ENC
    ue.k_nas_enc = conv_501_A8(ue.k_amf, alg_type=1, alg_id=NASSecAlgo['CiphAlgo'])
    # Get least significate 16 bytes from K_NAS_ENC 32 bytes
    ue.k_nas_enc = ue.k_nas_enc[16:]
    # Get K_NAS_INT
    k_nas_int = conv_501_A8(ue.k_amf, alg_type=2, alg_id=NASSecAlgo['IntegAlgo'])
    ue.set_k_nas_int(k_nas_int)
    ue.k_nas_int = ue.k_nas_int[16:]

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
    # Msg['NASContainer']['V'].set_val(RegMsg.to_bytes()) 
    # Encrypt NAS message
    ue.MsgInBytes = Msg.to_bytes()
    SecMsg = security_prot_encrypt(ue, Msg)
    logger.debug(f"UE {ue.supi} sending invalid_security_mode_complete")
    ue.set_state(FGMMState.SECURITY_MODE_INITIATED)
    return SecMsg, 'FGMMSecurityModeComplete'