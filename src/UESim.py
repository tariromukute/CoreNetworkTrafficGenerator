import sys
import time
import logging
import threading
import time
import traceback
from itertools import product
from tabulate import tabulate
from pycrate_mobile.NAS5G import parse_NAS5G, parse_PayCont
from UEMessages import *
from ComplianceTestUEMessages import *
from UEUtils import *

request_mapper = {
    '5GMMRegistrationRequest': registration_request,
    '5GSMPDUSessionEstabRequest': pdu_session_establishment_request,
    '5GMMMODeregistrationRequest': mo_deregistration_request,
}

response_mapper = {
    '5GMMAuthenticationRequest': authentication_response,
    '5GMMRegistrationAccept': registration_complete,
    '5GSMPDUSessionEstabAccept': pdu_session_establishment_complete,
    '5GMMSecurityModeCommand': security_mode_complete,
    '5GMMMODeregistrationAccept': deregistration_complete
}

compliance_test_mapper = {
    '5GMMRegistrationRequest': [registration_request],
    '5GMMAuthenticationRequest': [ authentication_response, authentication_response_invalid_rand ],
    '5GMMRegistrationAccept': [ registration_complete ],
    '5GMMSecurityModeCommand': [ security_mode_complete, security_mode_complete_missing_nas_container ],
    '5GSMPDUSessionEstabRequest': [ pdu_session_establishment_request ],
    '5GMMMODeregistrationRequest': [mo_deregistration_request],
    '5GMMMODeregistrationAccept': [ deregistration_complete ]
}

# TODO: complete and incoperate the validator    
def validator(PrevMsgBytesSent, MsgRecvd):
    """
        Checks the last message sent against the message received to see if it is the expected response.
        It logs the mismatch if any is detected
    """
    PrevMsgSent, err = parse_NAS5G(PrevMsgBytesSent)
    if err:
        logger.error(f"Failed to parse the UE's previous message {PrevMsgSent}")
        return

    PrevMsgSentDict = PrevMsgSent.get_val_d()
    # print(PrevMsgSentDict)
    MsgRecvdDict = MsgRecvd.get_val_d()

    # Check if the received message doesn't have a response mapped
    if not MsgRecvd._name in response_mapper:
        # This is not an error, log for info purposes
        logger.info(f"Received {MsgRecvd._name} a message without a response mapped to it")

    if PrevMsgSent._name == '5GMMRegistrationRequest':
        """ General Registration procedure 3GPP TS 23.502 4.2.2.2.2

        Depending on the parameter provided and whether it's moving from an old AMF, the next
        message from the CN is either Identity Request (5GMMIdentityRequest) or Authentication request
        (5GMMAuthenticationRequest)
        """
        if MsgRecvd._name == '5GMMAuthenticationRequest':
            if 'AUTN' not in MsgRecvdDict:
                error_message = "5GMMAuthenticationRequest did not contain AUTN"
                return FGMMState.FAIL, error_message
        # TODO: Add elif for 5GMMIdentityRequest
        else:
            error_message = f"Expected 5GMMAuthenticationRequest but got {MsgRecvd._name}"
            return FGMMState.FAIL, error_message
    elif PrevMsgSent._name == '5GMMAuthenticationResponse':
        if  MsgRecvd._name == '5GMMSecurityModeCommand':
            return None, None
        # Note: didn't handle the compliance test to show results
        else:
            error_message = f"Expected 5GMMSecurityModeCommand but got {MsgRecvd._name}"
            return FGMMState.FAIL, error_message
    elif PrevMsgSent._name == '5GMMSecurityModeComplete':
        """
        During the registration procedure, after sending the 5GMMSecurityModeCommand the UE
        should received the 5GMMRegistrationAccept response.
        """
        if MsgRecvd._name != '5GMMRegistrationAccept':
            """ Check if we didn't send an invalid request for compliance test """
            if PrevMsgSentDict['NASContainer']['V'] == b'\x00\x00':
                """ We sent an invalid 5GMMSecurityModeComplete with no UE data
                we should get a registration reject
                """
                if MsgRecvd._name != '5GMMRegistrationReject':
                    error_message= f"Expected 5GMMAuthenticationRequest but got {MsgRecvd._name}"
                    return FGMMState.FAIL, error_message
                # We expected reject therefore pass
                return FGMMState.PASS, None
            else:
                error_message = f"Expected 5GMMRegistrationAccept but got {MsgRecvd._name}"
                return FGMMState.FAIL, error_message
    # elif PrevMsgSent._name == '5GSMPDUSessionEstabRequest':
        
    elif PrevMsgSent._name == '5GMMMODeregistrationRequest':
        """ UE-initiated Deregistration procedure 3GPP TS 23.502 4.2.2.3.2
        
        The next message from the CN should be De-registration Accept (5GMMMODeregistrationAccept)
        """
        if MsgRecvd._name == '5GMMMODeregistrationAccept':
            if '5GMMCause' in MsgRecvdDict:
                error_message = f"5GMMMODeregistrationComplete contained RejectionCause: {MsgRecvdDict['RejectionCause']}"
                return FGMMState.FAIL, error_message
        else:
            error_message = f"Expected 5GMMMODeregistrationAccept but got {MsgRecvd._name}"
            return FGMMState.FAIL, error_message

    return None, None

g_verbose = 0
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
        global logger
        self.common_ies = self.create_common_ies()

        # Set map for compliance flows, used if program in compliance check mode
        self.compliance_mapper = {}

        # Set several instance variables to None
        self.ue_capabilities = self.ue_security_capabilities = self.ue_network_capability = None
        self.MsgInBytes = None
        self.RcvMsgInBytes = None
        self.IpAddress = None
        # Set values for empty variables to all zeros in bytes
        empty_values = ['k_nas_int', 'k_nas_enc', 'k_amf', 'k_ausf', 'k_seaf', 'sqn', 'autn',
                        'mac_a', 'mac_s', 'xres_star', 'xres', 'res_star', 'res', 'rand']
        for var_name in empty_values:
            setattr(self, var_name, b'\x00' * 32)

        self.supi = self.amf_ue_ngap_id = None
        self.procedure = None  # contains the request that UE is processing or has
        self.error_message = None
        self.procedures = config.get('procedures') if 'procedures' in config else [
            '5GMMRegistrationRequest', '5GMMMODeregistrationRequest']
        if config is None:
            self.state = FGMMState.NULL
            # raise ValueError(f"Config is required")
            # If config is None, set some variables to None and others to default values
            self.op_type, self.state_time = 'OPC', time.time()
        else:
            # Otherwise, set variables based on values from config
            # The elements on procedures should be keys in request_mapper
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

    def set_compliance_mapper(self, mapper):
        self.compliance_mapper = mapper
        
    def next_action(self, Msg, type = None):
        """
        Determines the next procedure to process based on the given response.

        Args:
            response: The response received by the UE.
                Should be a string representing the current procedure being processed.

        Returns:
            The function corresponding to the procedure to be processed next.
        """
        if g_verbose >= 3 and Msg is not None:
            logger.debug(f"UE {self.supi} received {type}")
            validator(self.MsgInBytes, Msg)

        # Get the procedure function corresponding to the given response
        IEs = {}
        action_func = None
        if Msg and type:
            action_func = response_mapper.get(type)

        if action_func is None:
            # Get the index of the current procedure in procedures
            idx = self.procedures.index(
                self.procedure) if self.procedure in self.procedures else -1
            # Get the next procedure in procedures (wrapping around if necessary)
            if (idx + 1) >= len(self.procedures):
                return None, self, None
            # procedure = self.procedures[(idx + 1) % len(self.procedures)]
            procedure = self.procedures[idx+1]
            # Get the procedure function corresponding to the next procedure
            action_func = request_mapper[procedure]
            # Update the UE's state with the next procedure
            self.procedure = procedure

        # Call the procedure function and return its result
        Msg, sent_type = action_func(self, IEs, Msg)
        logger.debug("UE {} change to state {} and sending {}".format(self.supi, FGMMState(self.state).name, sent_type))
        ReturnMsg = Msg.to_bytes() if Msg != None else None                                                           
        return ReturnMsg, self, sent_type

    def next_compliance_test(self, Msg, type = None):

        if g_verbose > 3 and Msg is not None:
            self.RcvMsgInBytes = Msg.to_bytes()
            logger.debug(f"UE {self.supi} received {type}")
            test_result, error_message = validator(self.MsgInBytes, Msg)
            if test_result != None:
                self.state = test_result
                self.error_message = error_message
                return None, self

        IEs = {}
        action_func = None
        if Msg and type:
            action_func = self.compliance_mapper.get(type)
            # action_func = response_mapper.get(type)

        if action_func is None:
            # Get the index of the current procedure in procedures
            idx = self.procedures.index(
                self.procedure) if self.procedure in self.procedures else -1
            # Get the next procedure in procedures (wrapping around if necessary)
            if (idx + 1) >= len(self.procedures):
                return None, self
            # procedure = self.procedures[(idx + 1) % len(self.procedures)]
            procedure = self.procedures[idx+1]
            # Get the procedure function corresponding to the next procedure
            action_func = self.compliance_mapper[procedure]
            # Update the UE's state with the next procedure
            self.procedure = procedure

        # Call the procedure function and return its result
        Msg, sent_type = action_func(self, IEs, Msg)
        logger.debug("UE {} change to state {}".format(self.supi, FGMMState(self.state).name))
        # self.MsgInBytes = Msg.to_bytes() if Msg != None else None 
        return Msg.to_bytes() if Msg != None else None, self
    
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

class UESim:
    exit_flag = False

    def __init__(self, ngap_to_ue, ue_to_ngap, ue_profiles, interval, verbose):
        global g_verbose
        g_verbose = verbose
        self.ngap_to_ue = ngap_to_ue
        self.ue_to_ngap = ue_to_ngap
        self.ue_list = {}
        self.number = 0
        self.interval = interval
        self.ue_profiles = ue_profiles
        global logger
        # Set logging level based on the verbose argument
        # Note: A verbose of 4 implies compliance test
        if verbose == 0:
            logging.basicConfig(level=logging.ERROR)
        elif verbose == 1:
            logging.basicConfig(level=logging.WARNING)
        elif verbose == 2:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.DEBUG)

    def dispatcher(self, data: bytes, ueId):
        ue = self.ue_list[ueId]
        if data == None:
            return ue.next_action(None, None) if g_verbose <= 3 else ue.next_compliance_test(None, None)
        
        Msg, err = parse_NAS5G(data)
        if err:
            return None, ue
            
        msg_type = Msg._name
        
        if msg_type == '5GMMSecProtNASMessage':
            Msg = security_prot_decrypt(Msg, ue)
            if Msg._by_name.count('5GMMSecurityModeCommand'):
                Msg = Msg['5GMMSecurityModeCommand']
                msg_type = Msg._name
            elif Msg._name == '5GMMDLNASTransport':
                Msg = dl_nas_transport_extract(Msg, ue)
                msg_type = Msg._name
            else:
                msg_type = Msg._name
            
        tx_nas_pdu, ue_, sent_type = ue.next_action(Msg, msg_type) if g_verbose <= 3 else ue.next_compliance_test(Msg, msg_type)
        
        if tx_nas_pdu:
            return tx_nas_pdu, ue_, sent_type
            
        return None, ue_, sent_type
    

    def _load_ngap_to_ue_thread(self):
        """ Load the thread that will handle NAS DownLink messages from gNB """
        ngap_to_ue_thread = threading.Thread(target=self._ngap_to_ue_thread_function)
        ngap_to_ue_thread.daemon = True
        ngap_to_ue_thread.start()
        return ngap_to_ue_thread

    def _ngap_to_ue_thread_function(self):
        """ Thread function that will handle NAS DownLink messages from gNB 

            It will select the NAS procedure to be executed based on the NAS message type.
            When the NAS procedure is completed, the NAS message will be put on a queue 
            that will be read by the gNB thread.
        """
        while not UESim.exit_flag:
            data, ueId = self.ue_to_ngap.recv()
            if data:
                tx_nas_pdu, ue, sent_type = self.dispatcher(data, ueId)
                self.ue_list[int(ue.supi[-10:])] = ue

                if tx_nas_pdu:
                    self.ue_to_ngap.send((tx_nas_pdu, ueId))

                if sent_type == '5GMMRegistrationComplete':
                    # send the next procedure
                    tx_nas_pdu, ue, sent_type = self.dispatcher(None, ueId)
                    self.ue_list[int(ue.supi[-10:])] = ue

                    if tx_nas_pdu:
                        self.ue_to_ngap.send((tx_nas_pdu, ueId))
                if sent_type == '5GSMPDUSessionEstabComplete': # For internal use only, it's not a real message type
                    tx_nas_pdu, ue, sent_type = self.dispatcher(None, ueId)
                    self.ue_list[int(ue.supi[-10:])] = ue

                    if tx_nas_pdu:
                        self.ue_to_ngap.send((tx_nas_pdu, ueId))
    def init(self):
        for supi, ue in self.ue_list.items():
            if (ue):
                tx_nas_pdu, ue_, sent_type = ue.next_action(None, ) if g_verbose <= 3 else ue.next_compliance_test(None, )
                self.ue_list[int(ue.supi[-10:])] = ue
                self.ue_to_ngap.send(
                    (tx_nas_pdu, int(ue.supi[-10:])))

    def create_ues(self):
        profiles = self.ue_profiles['ue_profiles']
        # If doing compliance and validation (self.verbose > 3) create UEs
        # with all the possible combinations for compliance_mapper
        if g_verbose > 3:
            # create unique compliance_mappers
            combinations = product(*compliance_test_mapper.values())
            unique_compliance_mappers = [{k: v for k, v in zip(compliance_test_mapper.keys(), combination)} for combination in combinations]

            ue_config = profiles[0]
            init_imsi = ue_config['supi'][-10:]
            base_imsi = ue_config['supi'][:-10]
            init_imsi = int(init_imsi)
            for i, compliance_mapper in enumerate(unique_compliance_mappers, start=init_imsi):
                imsi = f"{base_imsi}{i:010d}"
                ue = UE({**ue_config, 'supi': imsi})
                ue.set_compliance_mapper(compliance_mapper)
                logger.debug(f"Set UE {imsi} with compliance_mapper")
                for k, v in compliance_mapper.items():
                    logger.debug(f"Request message: {k}, Response function: {v.__name__}")
                self.ue_list[i] = ue
            
        else:
            # Else create UEs based on config profile
            for ue_config in profiles:
                count, base_imsi, init_imsi = ue_config['count'], ue_config['supi'][:-10], int(ue_config['supi'][-10:])
                for i in range(init_imsi, init_imsi + count):
                    imsi = f"{base_imsi}{i:010d}"
                    ue = UE({**ue_config, 'supi': imsi})
                    self.ue_list[i] = ue

        self.number = len(self.ue_list)
        logger.info("Created {} UEs".format(len(self.ue_list)))

    def update_ue_state_counts(self):
        # Create array of size 10
        ue_state_count = [0] * FGMMState.FGMM_STATE_MAX
        for supi, ue in self.ue_list.items():
            if ue and ue.supi and ue.state < FGMMState.FGMM_STATE_MAX:
                try:
                    ue_state_count[ue.state] += 1
                except IndexError:
                    logger.error(f"UE: {ue.supi} has unknown state: {ue.state}")
        
        # Get FGMMState names
        fgmm_state_names = [
            FGMMState(i).name for i in range(FGMMState.FGMM_STATE_MAX)]
        
        return ue_state_count, fgmm_state_names

    def print_stats_process(self):
        start_time = time.time()

        # run forever
        while not UESim.exit_flag:
            try:
                ue_state_count, fgmm_state_names = self.update_ue_state_counts()
                logger.debug(f"{dict(zip(fgmm_state_names, ue_state_count))}")

                # If all the UEs have registered exit
                if ue_state_count[FGMMState.DEREGISTERED] >= self.number:
                    # Get the UE that had the latest state_time and calculate the time it took all UEs to be registered
                    latest_time = start_time
                    for supi, ue in self.ue_list.items():
                        if ue and ue.supi:
                            latest_time = ue.state_time if latest_time < ue.state_time else latest_time

                    print(f"Registered {self.number} UEs in {latest_time - start_time}")
                    
                    # Tell parent process to exit
                    UESim.exit_flag = True
                time.sleep(1)
            except Exception:
                # logger.exception('Whoops! Problem:', file=sys.stderr)
                traceback.print_exc(file=sys.stderr)

    def print_compliance_test_results(self):
        start_time = time.time()

        # run forever
        while not UESim.exit_flag:
            try:
                ue_state_count, fgmm_state_names = self.update_ue_state_counts()
                
                # If all the UEs have registered exit
                if ue_state_count[FGMMState.DEREGISTERED] + ue_state_count[FGMMState.FAIL] + ue_state_count[FGMMState.PASS] >= self.number:
                    # Get the UE that had the latest state_time and calculate the time it took all UEs to be registered
                    latest_time = start_time
                    for supi, ue in self.ue_list.items():
                        if ue and ue.supi:
                            latest_time = ue.state_time if latest_time < ue.state_time else latest_time

                    print(f"Ran compliance test for {self.number} UEs in {latest_time - start_time}")
                    
                    # Print test results in a table
                    for supi, ue in self.ue_list.items():
                        if g_verbose == 4 and ue.error_message == None:
                            continue
                        SentMsg, err = parse_NAS5G(ue.MsgInBytes)
                        if err:
                            print('Failed to parse ue.MsgInBytes when print compliance test results')
                        RcvMsg, err = parse_NAS5G(ue.RcvMsgInBytes)
                        if err:
                            print('Failed to parse ue.RcvMsgInBytes when print compliance test results')
                        profile = ''
                        for k, v in ue.compliance_mapper.items():
                            profile += f"Request message: {k}, Response function: {v.__name__}\n"
                        headers = ['UE', ue.supi]
                        table = [['Status', fgmm_state_names[ue.state]], ['Message', ue.error_message], ['Profile', profile], ['Sent', SentMsg.show()], ['Received', RcvMsg.show()] ]
                        print(tabulate(table, headers, tablefmt="grid"))
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
        self.ngap_to_ue_thread = self._load_ngap_to_ue_thread()
        if g_verbose > 3:
            self.print_compliance_test_results()
        else:
            self.print_stats_process()
        self.ngap_to_ue.close()
        sys.exit(0)
