import math
import random
from enum import IntEnum
import time
import logging
import threading
from binascii import unhexlify, hexlify
from pycrate_mobile.TS24008_IE import encode_bcd
from pycrate_mobile.NAS import FGMMRegistrationRequest, FGMMMODeregistrationRequest, FGMMRegistrationComplete, FGMMAuthenticationResponse
from pycrate_mobile.NAS5G import parse_NAS_MO, parse_NAS5G
from CryptoMobile.Milenage import Milenage, make_OPc
from CryptoMobile.conv import conv_501_A2, conv_501_A4, conv_501_A6, conv_501_A7, conv_501_A8

def byte_xor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

# TODO: complete and incoperate the validator
def validator(PrevMsgSent, MsgRecvd):
    """
        Checks the last message sent against the message received to see if it is the expected response.
        It logs the mismatch if any is detected
    """
    PrevMsgSentDict = PrevMsgSent.get_val_d()
    MsgRecvdDict = MsgRecvd.get_val_d()
    if PrevMsgSent.__class__.__name__ == 'FGMMRegistrationRequest':
        if MsgRecvd.__class__.__name__ != 'FGMMRegistrationAccept':
            logging.error(f"Expected FGMMRegistrationAccept but got {MsgRecvd.__class__.__name__}")
        elif '5GSRegResult' not in MsgRecvdDict:
            logging.error("FGMMRegistrationAccept did not contain 5GSRegResult")
        elif MsgRecvdDict['5GSRegResult']['V'] != 310:
            logging.error("FGMMRegistrationAccept contained incorrect 5GSRegResult Value")
    elif PrevMsgSent.__class__.__name__ == 'FGMMMODeregistrationRequest':
        if MsgRecvd.__class__.__name__ != 'FGMMMODeregistrationComplete':
            logging.error(f"Expected FGMMMODeregistrationComplete but got {MsgRecvd.__class__.__name__}")
        elif '5GMMCause' in MsgRecvdDict:
            logging.error(f"FGMMMODeregistrationComplete contained RejectionCause: {MsgRecvdDict['RejectionCause']}")


def registration_request(ue, IEs, Msg = None):
    IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65 }
    IEs['NAS_KSI'] = { 'TSC': 0, 'Value': 7 }
    IEs['5GSRegType'] = { 'FOR': 1, 'Value': 1 }
    IEs['5GSID'] = { 'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': { 'PLMN': ue.mcc + ue.mnc, 'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': encode_bcd(ue.msin) } }
    IEs['UESecCap'] = {'5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0,
                       '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0, '5G-IA6': 0, '5G-IA7': 0,
                       'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0,
                       'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0}
    Msg, err = FGMMRegistrationRequest(val=IEs)
    ue.set_state(FGMMState.REGISTERED_INITIATED)
    return Msg

def registration_complete(ue, IEs, Msg = None):
    IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 67 }
    # IEs['SORTransContainer'] = { 'ListInd': }
    Msg, err = FGMMRegistrationComplete(val=IEs)
    ue.set_state(FGMMState.REGISTERED)
    return Msg

def mo_deregistration_request(ue, IEs, Msg = None):
    IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65 }
    IEs['NAS_KSI'] = { 'TSC': 0, 'Value': 7 }
    IEs['5GSRegType'] = { 'FOR': 1, 'Value': 1 }
    IEs['5GSID'] = { 'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': { 'PLMN': ue.mcc + ue.mnc, 'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': encode_bcd(ue.msin) } }
    IEs['UESecCap'] = {'5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0,
                       '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0, '5G-IA6': 0, '5G-IA7': 0,
                       'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0,
                       'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0}
    Msg, err = FGMMMODeregistrationRequest(val=IEs)
    ue.set_state(FGMMState.REGISTERED_INITIATED)
    return Msg

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
    RES, CK, IK, _  = Mil.f2345(key, rand)
    Res = conv_501_A4(CK, IK, ue.sn_name, rand, RES)

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
    ue.set_state(FGMMState.AUTHENTICATED_INITIATED)
    return Msg


request_mapper = {
    '5GMMRegistrationRequest': registration_request,
    'FGMMMODeregistrationRequest': mo_deregistration_request
}

response_mapper = {
    '5GMMAuthenticationRequest': authentication_response,
    '5GMMRegistrationAccept': registration_complete
}

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
    # Last state indicate number of states
    FGMM_STATE_MAX = 10

class UE:
    def __init__(self, config):
        """
        Initializes a new UE object with the given configuration.
        
        Args:
            config (dict): A dictionary containing the configuration data for the UE.
                Must have the keys 'mmn' and 'supi'.
        
        Returns:
            None
        """
        self.common_ies = self.create_common_ies()

        # Set several instance variables to None
        self.ue_capabilities = self.ue_security_capabilities = self.ue_network_capability = None
        self.Msg = None
        # Set values for empty variables to all zeros in bytes
        empty_values = ['k_nas_int', 'k_nas_enc', 'k_amf', 'k_ausf', 'k_seaf', 'sqn', 'autn',
                        'mac_a', 'mac_s', 'xres_star', 'xres', 'res_star', 'res', 'rand']
        for var_name in empty_values:
            setattr(self, var_name, b'\x00' * 32)

        if config is None:
            # If config is None, set some variables to None and others to default values
            self.supi = self.amf_ue_ngap_id = None
            self.state = FGMMState.NULL
            self.op_type, self.state_time = 'OPC', time.time()
            self.actions = ['5GMMRegistrationRequest', 'FGMMMODeregistrationRequest']
            self.action = None # contains the request that UE is processing or has 
        else:
            # Otherwise, set variables based on values from config
            self.actions = config['actions'] # The elements on actions should be keys in request_mapper 
            self.supi = config['supi']
            self.mcc = config['mcc']
            self.mnc = config['mnc']
            self.msin = config['supi'][-10:]
            self.key = config['key']
            self.op = config['op']
            self.op_type = config['opType']
            self.amf = config['amf']
            self.imei = config['imei']
            self.imeiSv = config['imeiSv']
            sn_name = "5G:mnc{:03d}.mcc{:03d}.3gppnetwork.org".format(int(config['mnc']), int(config['mcc']))
            self.sn_name = sn_name.encode()
            self.nssai = [{'SST': int(a['sst']), 'SD': int(a['sd'])} 
             if 'sd' in a else {'SST': int(a['sst'])}  # Create dictionaries for each item in defaultNssai list
             for a in config['defaultNssai']]
            self.state, self.state_time = FGMMState.NULL, time.time()

    def set_k_nas_int(self, k_nas_int):
        self.k_nas_int = k_nas_int

    def set_state(self, state):
        self.state_time = time.time()
        self.state = state

    def next_action(self, Msg):
        """
        Determines the next action to process based on the given response.
        
        Args:
            response: The response received by the UE.
                Should be a string representing the current action being processed.
        
        Returns:
            The function corresponding to the action to be processed next.
        """

        # Get the action function corresponding to the given response
        IEs = {}
        # IEs['NAS_KSI'] = self.common_ies['NAS_KSI']
        action_func = response_mapper.get(Msg._name)
        
        if action_func is None:
            # Get the index of the current action in actions
            idx = self.actions.index(self.action) if self.action in self.actions else -1
            # Get the next action in actions (wrapping around if necessary)
            action = self.actions[(idx + 1) % len(self.actions)]
            # Get the action function corresponding to the next action
            action_func = request_mapper[action]
            # Update the UE's state with the next action
            self.action = action
    
        # Call the action function and return its result
        Msg = action_func(self, IEs, Msg)
        self.Msg = Msg
        return Msg
    
    def create_common_ies(self):
        IEs = {}
        IEs['NAS_KSI'] = { 'TSC': 0, 'Value': 7 }
        return IEs


class UESim:

    def __init__(self, nas_dl_queue, nas_ul_queue, ue_list):
        self.nas_dl_queue = nas_dl_queue
        self.nas_ul_queue = nas_ul_queue
        self.ue_list = ue_list

    def dispatcher(self, data: bytes, ueId):
        Msg, err = parse_NAS5G(data)
        return self.ue_list[ueId].next_action(Msg)

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
                data, ueId = self.nas_dl_queue.get()
                tx_nas_pdu = self.dispatcher(data, ue)
                if tx_nas_pdu:
                    self.nas_ul_queue.put((tx_nas_pdu, ueId))

    def run(self):
        """ Run the NAS thread """
        self._load_nas_dl_thread()