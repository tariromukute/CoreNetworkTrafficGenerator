import sys
import time
import logging
import threading
import time
import traceback
import signal
from functools import partial
from itertools import product
from tabulate import tabulate
from pycrate_mobile.NAS5G import parse_NAS5G, parse_PayCont
from src.UEMessages import *
from src.ComplianceTestUEMessages import *
from src.UEUtils import *
from src.UE import *
import psutil
import multiprocessing

def interrupt_handler(ueSim, ask, signum, frame):
    if ask:
        signal.signal(signal.SIGINT, partial(interrupt_handler, ueSim, False))
        print('Compiling results, to interrupt the results compilation press ctrl-c again.')
        ueSim.stop()
        return
    sys.exit(0)

import threading

# Create a lock object
lock = threading.Lock()
num_threads = 2
class UESim:
    exit_flag = False
    global start_time

    def __init__(self, ue_fg_msg_states, exit_program, ue_list, ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, interval, statistics, verbose, ue_sim_time):
        global g_verbose
        g_verbose = verbose
        self.ngap_to_ue = ngap_to_ue
        self.ue_to_ngap = ue_to_ngap
        self.upf_to_ue = upf_to_ue
        self.ue_to_upf = ue_to_upf
        self.statistics = statistics
        self.ue_list = ue_list
        self.number = len(ue_list)
        self.interval = interval
        self.ue_sim_time = ue_sim_time
        self.exit_program = exit_program 
        self.procedures_count = {}
        self.ue_fg_msg_states = ue_fg_msg_states
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
        
        # If the gNB receives a UE Context Release Command it will send data b'F' as the (R)AN Connection Release
        # TODO: implement the appropriate message for R(AN) Connection Release
        if data == b'F':
            return ue.next_action(data, '5GMMANConnectionReleaseComplete') if g_verbose <= 3 else ue.next_compliance_test(data, '5GMMANConnectionReleaseComplete')
        
        Msg, err = parse_NAS5G(data)
        if err:
            return None, ue
        
        msg_type = Msg._name
        
        if msg_type == '5GMMSecProtNASMessage':
            Msg = security_prot_decrypt(Msg, ue)
            if Msg._by_name.count('5GMMSecurityModeCommand'):
                Msg = Msg['5GMMSecurityModeCommand']
                msg_type = Msg._name
            else:
                msg_type = Msg._name

        if Msg._name == '5GMMDLNASTransport':
            Msg = dl_nas_transport_extract(Msg, ue)
            msg_type = Msg._name
        
        msg_code = fg_msg_codes[msg_type] - FGMM_MIN_TYPE
        self.procedures_count[ue.current_procedure] = self.procedures_count.get(ue.current_procedure, 1) - 1
        with self.ue_fg_msg_states.get_lock():
            self.ue_fg_msg_states[ue.current_procedure] -= 1
            self.ue_fg_msg_states[msg_code] += 1
        
        self.procedures_count[msg_code] = self.procedures_count.get(msg_code, 0) + 1
        ue.current_procedure = msg_code
        tx_nas_pdu, ue_, sent_type = ue.next_action(Msg, msg_type) if g_verbose <= 3 else ue.next_compliance_test(Msg, msg_type)
        
        if tx_nas_pdu:
            return tx_nas_pdu, ue_, sent_type
            
        return None, ue_, sent_type
    

    def _load_ngap_to_ue_thread(self):
        """ Load the thread that will handle NAS DownLink messages from gNB """
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=self._ngap_to_ue_thread_function)
            t.daemon = True
            threads.append(t)

        # start all threads
        for t in threads:
            t.start()

        return threads

    def _ngap_to_ue_thread_function(self):
        """ Thread function that will handle NAS DownLink messages from gNB 

            It will select the NAS procedure to be executed based on the NAS message type.
            When the NAS procedure is completed, the NAS message will be put on a queue 
            that will be read by the gNB thread.
        """
        while not self.exit_program.value:
            data = None
            ueId = None
            with lock:
                data, ueId = self.ue_to_ngap.recv()
            if data:
                tx_nas_pdu, ue, sent_type = self.dispatcher(data, ueId)
                self.ue_list[int(ue.supi[-10:])] = ue
                if tx_nas_pdu and sent_type != '5GSMPDUSessionTransmission':
                    self.ue_to_ngap.send((tx_nas_pdu, ueId))
                elif tx_nas_pdu:
                    self.ue_to_upf.send((tx_nas_pdu, ueId))
                    
                if sent_type == '5GMMRegistrationComplete' or sent_type == '5GSMPDUSessionEstabComplete' or sent_type == '5GSMPDUSessionTransmissionComplete':
                    # send the next procedure
                    tx_nas_pdu, ue, sent_type = self.dispatcher(None, ueId)
                    self.ue_list[int(ue.supi[-10:])] = ue

                    if tx_nas_pdu and sent_type != '5GSMPDUSessionTransmission':
                        self.ue_to_ngap.send((tx_nas_pdu, ueId))
                    elif tx_nas_pdu:
                        self.ue_to_upf.send((tx_nas_pdu, ueId))
                
                msg_code = fg_msg_codes[sent_type] - FGMM_MIN_TYPE
                self.procedures_count[ue.current_procedure] = self.procedures_count.get(ue.current_procedure, 1) - 1
                with self.ue_fg_msg_states.get_lock():
                    self.ue_fg_msg_states[ue.current_procedure] -= 1
                    self.ue_fg_msg_states[msg_code] += 1
                self.procedures_count[msg_code] = self.procedures_count.get(msg_code, 0) + 1
                ue.current_procedure = msg_code     
    
    def init(self):
        global start_time
        start_time = time.time()
        self.procedures_count["NULL"] = len(self.ue_list.items()) # All UEs are initialised with last_procedure = NULL, set count to the number of UEs
        for supi, ue in self.ue_list.items():
            if (ue):
                tx_nas_pdu, ue_, sent_type = ue.next_action(None, ) if g_verbose <= 3 else ue.next_compliance_test(None, )
                self.ue_list[int(ue.supi[-10:])] = ue
                self.ue_to_ngap.send(
                    (tx_nas_pdu, int(ue.supi[-10:])))

                msg_code = fg_msg_codes[sent_type] - FGMM_MIN_TYPE
                self.procedures_count[ue.current_procedure] = self.procedures_count.get(ue.current_procedure, 1) - 1
                self.procedures_count[msg_code] = self.procedures_count.get(msg_code, 0) + 1
                with self.ue_fg_msg_states.get_lock():
                    self.ue_fg_msg_states[msg_code] += 1
                
                ue.current_procedure = msg_code


    def show_results(self):
        global start_time
        latest_time = start_time
        end_time = time.time()
        min_interval = 9999999
        max_interval = 0
        completed = 0
        sum_interval = 0
        # Print test results in a table
        for supi, ue in self.ue_list.items():
            # Get the UE that had the latest state_time and calculate the time it took all UEs to be registered
            # Don't consider UEs that didn't get a respond
            if ue.current_procedure == (fg_msg_codes["5GMMANConnectionReleaseComplete"] - FGMM_MIN_TYPE) and ue.end_time != None and ue.start_time != None:
                latest_time = ue.state_time if latest_time < ue.state_time else latest_time
                min_interval = ue.end_time - ue.start_time if min_interval > ue.end_time - ue.start_time else min_interval
                max_interval = ue.end_time - ue.start_time if max_interval < ue.end_time - ue.start_time else max_interval
                sum_interval += ue.end_time - ue.start_time
                with self.ue_sim_time.success.get_lock():
                    self.ue_sim_time.success.value += 1
            else:
                ue.error_message += f"\n\nUE hung for {end_time - ue.state_time} seconds"

            if g_verbose <= 4 and ue.error_message == "":
                continue
            SentMsg, err = parse_NAS5G(ue.MsgInBytes)
            if err:
                logger.error('Failed to parse ue.MsgInBytes when print compliance test results')
                SentMsgShow = ''
            else:
                SentMsgShow = SentMsg.show()
            RcvMsg, err = parse_NAS5G(ue.RcvMsgInBytes)
            if err:
                logger.error('Failed to parse ue.RcvMsgInBytes when print compliance test results')
                RcvMsgShow = ''
            else:
                RcvMsgShow = RcvMsg.show()
            profile = ''
            for k, v in ue.compliance_mapper.items():
                profile += f"Request message: {k}, Response function: {v.__name__}\n"
            headers = ['UE', ue.supi]
            table = [
                     ['Message', ue.error_message], 
                     ['Profile', profile], 
                     ['Sent', SentMsgShow], 
                     ['Received', RcvMsgShow] ]
            logger.info("\n" + tabulate(table, headers, tablefmt="grid"))

        with self.ue_sim_time.end_time.get_lock():
            self.ue_sim_time.end_time.value = latest_time if self.ue_sim_time.end_time.value < latest_time else self.ue_sim_time.end_time.value
        with self.ue_sim_time.start_time.get_lock():
            self.ue_sim_time.start_time.value = start_time if self.ue_sim_time.start_time.value > start_time or self.ue_sim_time.start_time.value == 0.0 else self.ue_sim_time.start_time.value
        with self.ue_sim_time.min_interval.get_lock():
            self.ue_sim_time.min_interval.value = min_interval if self.ue_sim_time.min_interval.value > min_interval else self.ue_sim_time.min_interval.value
        with self.ue_sim_time.max_interval.get_lock():
            self.ue_sim_time.max_interval.value = max_interval if self.ue_sim_time.max_interval.value < max_interval else self.ue_sim_time.max_interval.value
        with self.ue_sim_time.sum_interval.get_lock():    
            self.ue_sim_time.sum_interval.value += sum_interval
        
    def run(self, cpu_core):
        """ Run the NAS thread """
        affinity_mask = { cpu_core } 
        os.sched_setaffinity(0, affinity_mask)
        signal.signal(signal.SIGINT, partial(interrupt_handler, self, True))
        logger.info(f"Running {multiprocessing.current_process().name} with {len(self.ue_list)} UEs on CPU {psutil.Process().cpu_num()}")

        # Wait for GNB to be ready
        time.sleep(5)
        self.init()
        self.ngap_to_ue_thread = self._load_ngap_to_ue_thread()
        # self.upf_to_ue_thread = self._load_upf_to_ue_thread()
        while not self.exit_program.value:
            time.sleep(1)
  
        self.ngap_to_ue.close()
        self.stop()

    def stop(self):
        # Check the UE if the have all terminated if not log details and state the UE is in
        if self.exit_program.value == False:
            # Check if any UEs are not terminated and call validator
            for supi, ue in self.ue_list.items():
                if ue.current_procedure != fg_msg_codes["5GMMANConnectionReleaseComplete"]: 
                    test_result, error_message = validator(ue.MsgInBytes, b'0')
                    ue.error_message = error_message
                    ue.RcvMsgInBytes = None
            
        self.show_results()

        sys.exit(0)