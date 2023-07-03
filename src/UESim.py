import math
import random
from enum import IntEnum
import sys
import time
import logging
import threading
import time
from binascii import unhexlify, hexlify
import traceback
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
    # Last state indicate number of states
    FGMM_STATE_MAX = 10

# TODO: complete and incoperate the validator

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
    
def validator(PrevMsgSent, MsgRecvd):
    """
        Checks the last message sent against the message received to see if it is the expected response.
        It logs the mismatch if any is detected
    """
    PrevMsgSent, err = parse_NAS5G(PrevMsgSent)
    if err:
        logging.error(f"Failed to parse the UE's previous message")
        return
    PrevMsgSentDict = PrevMsgSent.get_val_d()
    MsgRecvdDict = MsgRecvd.get_val_d()
    if PrevMsgSent.__class__.__name__ == 'FGMMRegistrationRequest':
        if MsgRecvd.__class__.__name__ != 'FGMMRegistrationAccept':
            logging.error(
                f"Expected FGMMRegistrationAccept but got {MsgRecvd.__class__.__name__}")
        elif '5GSRegResult' not in MsgRecvdDict:
            logging.error(
                "FGMMRegistrationAccept did not contain 5GSRegResult")
        elif MsgRecvdDict['5GSRegResult']['V'] != 310:
            logging.error(
                "FGMMRegistrationAccept contained incorrect 5GSRegResult Value")
    elif PrevMsgSent.__class__.__name__ == 'FGMMMODeregistrationRequest':
        if MsgRecvd.__class__.__name__ != 'FGMMMODeregistrationComplete':
            logging.error(
                f"Expected FGMMMODeregistrationComplete but got {MsgRecvd.__class__.__name__}")
        elif '5GMMCause' in MsgRecvdDict:
            logging.error(
                f"FGMMMODeregistrationComplete contained RejectionCause: {MsgRecvdDict['RejectionCause']}")


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
    ue.set_state(FGMMState.REGISTERED_INITIATED)
    return Msg


def registration_complete(ue, IEs, Msg=None):
    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 67}
    # IEs['SORTransContainer'] = { 'ListInd': }
    Msg, = FGMMRegistrationComplete(val=IEs)
    SecMsg = security_prot_encrypt(ue, Msg)
    ue.set_state(FGMMState.REGISTERED)
    return SecMsg


def mo_deregistration_request(ue, IEs, Msg=None):
    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65}
    IEs['NAS_KSI'] = {'TSC': 0, 'Value': 7}
    IEs['5GSRegType'] = {'FOR': 1, 'Value': 1}
    IEs['5GSID'] = {'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': {'PLMN': ue.mcc + ue.mnc,
                                                                           'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': encode_bcd(ue.msin)}}
    IEs['UESecCap'] = {'5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0,
                       '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0, '5G-IA6': 0, '5G-IA7': 0,
                       'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0,
                       'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0}
    Msg = FGMMMODeregistrationRequest(val=IEs)
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
    RES, CK, IK, _ = Mil.f2345(key, rand)
    Res = conv_501_A4(CK, IK, ue.sn_name, rand, RES)

    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 87}
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
    # Encrypt NAS message
    SecMsg = security_prot_encrypt(ue, Msg)
    ue.set_state(FGMMState.SECURITY_MODE_INITIATED)
    return SecMsg


request_mapper = {
    '5GMMRegistrationRequest': registration_request,
    '5GMMMODeregistrationRequest': mo_deregistration_request,
}

response_mapper = {
    '5GMMAuthenticationRequest': authentication_response,
    '5GMMRegistrationAccept': registration_complete,
    '5GMMSecurityModeCommand': security_mode_complete
}


class UE:
    def __init__(self, config=None):
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

        self.supi = self.amf_ue_ngap_id = None
        self.action = None  # contains the request that UE is processing or has
        self.actions = config.get('actions') if 'actions' in config else [
            '5GMMRegistrationRequest', '5GMMMODeregistrationRequest']
        if config is None:
            # raise ValueError(f"Config is required")
            # If config is None, set some variables to None and others to default values
            self.state = FGMMState.NULL
            self.op_type, self.state_time = 'OPC', time.time()
        else:
            # Otherwise, set variables based on values from config
            # The elements on actions should be keys in request_mapper
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
            sn_name = "5G:mnc{:03d}.mcc{:03d}.3gppnetwork.org".format(
                int(config['mnc']), int(config['mcc']))
            self.sn_name = sn_name.encode()
            self.nssai = [{'SST': int(a['sst']), 'SD': int(a['sd'])}
                          # Create dictionaries for each item in defaultNssai list
                          if 'sd' in a else {'SST': int(a['sst'])}
                          for a in config['defaultNssai']]
            self.state, self.state_time = FGMMState.NULL, time.time()

    def set_k_nas_int(self, k_nas_int):
        self.k_nas_int = k_nas_int

    def set_state(self, state):
        self.state_time = time.time()
        self.state = state

    def next_action(self, Msg, type = None):
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
        action_func = None
        if Msg and type:
            action_func = response_mapper.get(type)

        if action_func is None:
            # Get the index of the current action in actions
            idx = self.actions.index(
                self.action) if self.action in self.actions else -1
            # Get the next action in actions (wrapping around if necessary)
            if (idx + 1) >= len(self.actions):
                return None, self
            # action = self.actions[(idx + 1) % len(self.actions)]
            action = self.actions[idx+1]
            # Get the action function corresponding to the next action
            action_func = request_mapper[action]
            # Update the UE's state with the next action
            self.action = action

        # Call the action function and return its result
        Msg = action_func(self, IEs, Msg)
        self.Msg = Msg.to_bytes()
        return self.Msg, self

    def create_common_ies(self):
        IEs = {}
        IEs['NAS_KSI'] = {'TSC': 0, 'Value': 7}
        return IEs

    def __str__(self):
        return "<UE supi={}, mcc={}, mnc={}, imei={}>".format(self.supi, self.mcc, self.mnc, self.imei)
    def __repr__(self) -> str:
        return (f'UE( SUPI: {self.supi}, AMF UE NGAP ID: '
                f'{self.amf_ue_ngap_id}, k_nas_int: {hexlify(self.k_nas_int)}, '
                f'k_nas_enc: {hexlify(self.k_nas_enc)}, k_amf: {hexlify(self.k_amf)}, '
                f'k_ausf: {hexlify(self.k_ausf)}, k_seaf: {hexlify(self.k_seaf)}, '
                f'k_nas_int: {hexlify(self.k_nas_int)}, k_nas_enc: {hexlify(self.k_nas_enc)} )')

    def __format__(self, format_spec: str) -> str:
        return (f'UE( SUPI: {self.supi}, AMF UE NGAP ID: '
                f'{self.amf_ue_ngap_id}, k_nas_int: {hexlify(self.k_nas_int)}, '
                f'k_nas_enc: {hexlify(self.k_nas_enc)}, k_amf: {hexlify(self.k_amf)}, '
                f'k_ausf: {hexlify(self.k_ausf)}, k_seaf: {hexlify(self.k_seaf)}, '
                f'k_nas_int: {hexlify(self.k_nas_int)}, k_nas_enc: {hexlify(self.k_nas_enc)} )')

logging.basicConfig(format='%(asctime)s [%(levelname)s]: %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

class UESim:
    exit_flag = False

    def __init__(self, nas_dl_queue, nas_ul_queue, ue_list, ue_config, interval, number):
        self.nas_dl_queue = nas_dl_queue
        self.nas_ul_queue = nas_ul_queue
        self.ue_list = ue_list
        self.number = number
        self.interval = interval
        self.ue_config = ue_config

    def dispatcher(self, data: bytes, ueId):
        Msg, err = parse_NAS5G(data)
        ue = self.ue_list[ueId]
        if err:
            return None, ue
            
        msg_type = Msg._name
        
        if msg_type == '5GMMSecProtNASMessage':
            Msg_ = security_prot_decrypt(Msg, ue)
            
            if Msg_._by_name.count('5GMMSecurityModeCommand'):
                SmcMsg = Msg_['5GMMSecurityModeCommand']
                msg_type = SmcMsg._name
            else:
                msg_type = Msg_._name
            
        tx_nas_pdu, ue_ = ue.next_action(Msg, msg_type)
        
        if tx_nas_pdu:
            return tx_nas_pdu, ue_
            
        return None, ue_
    

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
        while not UESim.exit_flag:
            if not self.nas_dl_queue.empty():
                data, ueId = self.nas_dl_queue.get()
                tx_nas_pdu, ue = self.dispatcher(data, ueId)
                self.ue_list[int(ue.supi[-10:])] = ue

                if tx_nas_pdu:
                    self.nas_ul_queue.put((tx_nas_pdu, ueId))

    def init(self):
        for ue in self.ue_list:
            if (ue):
                tx_nas_pdu, ue_ = ue.next_action(None, )
                self.ue_list[int(ue.supi[-10:])] = ue
                self.nas_ul_queue.put(
                    (tx_nas_pdu, int(ue.supi[-10:])))
    
    def create_ues(self):
        init_imsi = self.ue_config['supi'][-10:]
        base_imsi = self.ue_config['supi'][:-10]
        init_imsi = int(init_imsi)
        for i in range(0, init_imsi + self.number):
            if (i < init_imsi):
                self.ue_list.append(None)
            else:
                imsi = '{}{}'.format(base_imsi, format(i, '010d'))
                config = self.ue_config
                config['supi'] = imsi
                ue = UE(config)
                self.ue_list.append(ue)
                if self.interval > 0:
                    time.sleep(self.interval)

    def print_stats_process(self):
        start_time = time.time()

        # run forever
        while not UESim.exit_flag:
            try:
                # Create array of size 10
                ue_state_count = [0] * 10
                for ue in self.ue_list:
                    if ue and ue.supi and ue.state < FGMMState.FGMM_STATE_MAX:
                        try:
                            ue_state_count[ue.state] += 1
                        except IndexError:
                            logger.error(f"UE: {ue.supi} has unknown state: {ue.state}")
                
                # Get FGMMState names
                fgmm_state_names = [
                    FGMMState(i).name for i in range(FGMMState.FGMM_STATE_MAX)]
                print(f"UE state count: {dict(zip(fgmm_state_names, ue_state_count))}")
                # If all the UEs have registered exit
                if ue_state_count[FGMMState.REGISTERED] >= self.number:
                    # Get the UE that had the latest state_time and calculate the time it took all UEs to be registered
                    latest_time = start_time
                    for ue in self.ue_list:
                        if ue and ue.supi:
                            latest_time = ue.state_time if latest_time < ue.state_time else latest_time

                    logger.info(f"Registered {self.number} UEs in {latest_time - start_time}")
                    
                    # Tell parent process to exit
                    UESim.exit_flag = True
                time.sleep(1)
            except Exception:
                # logger.exception('Whoops! Problem:', file=sys.stderr)
                traceback.print_exc(file=sys.stderr)

    def run(self):
        """ Run the NAS thread """
        self.create_ues()
        # Wait for GNB to be ready
        time.sleep(5)
        self.init()
        self._load_nas_dl_thread()
        # self._load_stats_thread()
        self.print_stats_process()
