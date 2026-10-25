import os
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
import json
import csv
import queue
import random
from src.pacing import InFlight, start_offsets
from src import nascache, nasfast
import src.UE as ue_module

def _nas_fastpath():
    """ Whether the UEs may take their messages from src/nasfast.py, which gives the handlers the
    fields they read and bytes, not pycrate messages: not when the messages are validated, logged or
    used by the compliance tests """
    return g_verbose < 3 and ue_module.g_verbose < 3 and nasfast.enabled()

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

    def __init__(self, ue_fg_msg_states, exit_program, ue_list, ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, interval, statistics, verbose, ue_sim_time, folder='.', index=None,
                 poisson=False, seed=None, inflight=0, ue_timeout=30.0):
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
        self.folder = folder   # where procedure_times_<index>.csv and .json go
        self.index = index
        # When to start the UEs (src/pacing.py): every interval s, or as a Poisson process with that mean
        # gap; with inflight > 0, also at most inflight UEs in their procedures at once (a closed loop)
        self.poisson = poisson
        self.rng = random.Random(seed)
        self.inflight = InFlight(inflight, ue_timeout) if inflight else None
        self.exit_program = exit_program 
        self.procedures_count = {}
        self.ue_fg_msg_states = ue_fg_msg_states
        # init() and the workers all write to the pipes to the gNB: one write at a time
        self.send_lock = threading.Lock()
        self.worker_queues = []
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

    def dispatcher(self, data: bytes, ueId, received_at=None, ul_sent=None):
        received_at = received_at or time.time()
        ue = self.ue_list[ueId]
        # When the gNB sent the UE's uplink messages: these replace the times taken when they were built
        for code, sent_at in ul_sent or ():
            ue.procedure_times[code] = sent_at
        if data == None:
            tx_nas_pdu, ue, sent_type = ue.next_action(None, None) if g_verbose <= 3 else ue.next_compliance_test(None, None)
            ue.procedure_times[fg_msg_codes[sent_type]] = time.time()
            return tx_nas_pdu, ue, sent_type
        
        # If the gNB receives a UE Context Release Command it will send data b'F' as the (R)AN Connection Release
        # TODO: implement the appropriate message for R(AN) Connection Release
        if data == b'F':
            return ue.next_action(data, '5GMMANConnectionReleaseComplete') if g_verbose <= 3 else ue.next_compliance_test(data, '5GMMANConnectionReleaseComplete')
        
        # The messages of a registration, PDU session and deregistration without pycrate (src/nasfast.py)
        fast = nasfast.downlink(data, ue) if _nas_fastpath() else None
        if fast is not None:
            Msg, msg_type = fast
        else:
            Msg, err = nascache.parse_NAS5G(data)
            if err:
                return None, ue

            msg_type = Msg._name

            if msg_type == '5GMMSecProtNASMessage':
                try:
                    Msg = security_prot_decrypt(Msg, ue)
                    if Msg and Msg._by_name.count('5GMMSecurityModeCommand'):
                        Msg = Msg['5GMMSecurityModeCommand']
                        msg_type = Msg._name
                    elif Msg:
                        msg_type = Msg._name
                    else:
                        logger.error("Unexpected None value for Decrypted 5GMMSecProtNASMessage Msg")
                        return None, ue, None
                except err:
                    logger.exception(err)
                    return None, ue, None

            if Msg._name == '5GMMDLNASTransport':
                Msg = dl_nas_transport_extract(Msg, ue)
                msg_type = Msg._name
        
        # TODO handle recording of procedure
        if msg_type == '5GMMConfigurationUpdateCommand': # Ignore 5GMMConfigurationUpdateCommand
            return None, ue, None
        
        ue.procedure_times[fg_msg_codes[msg_type]] = received_at

        msg_code = fg_msg_codes[msg_type] - FGMM_MIN_TYPE
        self.procedures_count[ue.current_procedure] = self.procedures_count.get(ue.current_procedure, 1) - 1
        with self.ue_fg_msg_states.get_lock():
            self.ue_fg_msg_states[ue.current_procedure] -= 1
            self.ue_fg_msg_states[msg_code] += 1
        
        self.procedures_count[msg_code] = self.procedures_count.get(msg_code, 0) + 1
        ue.current_procedure = msg_code

        tx_nas_pdu, ue_, sent_type = ue.next_action(Msg, msg_type) if g_verbose <= 3 else ue.next_compliance_test(Msg, msg_type)
        if sent_type:
            ue.procedure_times[fg_msg_codes[sent_type]] = time.time()

        if tx_nas_pdu:
            return tx_nas_pdu, ue_, sent_type
            
        return None, ue_, sent_type
    

    def _send_ngap(self, msg):
        with self.send_lock:
            self.ue_to_ngap.send(msg)

    def _send_upf(self, msg):
        with self.send_lock:
            self.ue_to_upf.send(msg)

    def _load_ngap_to_ue_thread(self):
        """ Load the threads that handle NAS DownLink messages from gNB

            One reader hands each message to the worker of its UE (ueId % num_threads), so a UE's
            messages are processed in order and one at a time (its state, its NAS COUNT), while
            different UEs are processed in parallel.
        """
        self.worker_queues = [queue.Queue() for _ in range(num_threads)]
        threads = [threading.Thread(target=self._ngap_to_ue_reader, daemon=True)]
        threads += [threading.Thread(target=self._ngap_to_ue_thread_function, args=(q,), daemon=True)
                    for q in self.worker_queues]
        for t in threads:
            t.start()
        return threads

    def _ngap_to_ue_reader(self):
        """ Thread function that reads NAS DownLink messages from gNB and hands them to the workers """
        while not self.exit_program.value:
            if not self.ue_to_ngap.poll(0.5):   # so that the loop sees exit_program
                continue
            # (NAS PDU, UE ID[, the time the gNB received it[, when it sent the UE's uplink messages]])
            msg = self.ue_to_ngap.recv()
            data, ueId = msg[0], msg[1]
            received_at = msg[2] if len(msg) > 2 else None
            ul_sent = msg[3] if len(msg) > 3 else None
            self.worker_queues[ueId % len(self.worker_queues)].put((data, ueId, received_at, ul_sent))

    def _ngap_to_ue_thread_function(self, messages):
        """ Thread function that will handle NAS DownLink messages from gNB 

            It will select the NAS procedure to be executed based on the NAS message type.
            When the NAS procedure is completed, the NAS message will be put on a queue 
            that will be read by the gNB thread. A message that fails is logged; the worker
            carries on with the next one.
        """
        while not self.exit_program.value:
            try:
                data, ueId, received_at, ul_sent = messages.get(timeout=0.5)
            except queue.Empty:
                continue
            if not data:
                continue
            try:
                self._handle_downlink(data, ueId, received_at, ul_sent)
            except Exception:
                logger.exception(f"UE {ueId}: handling a downlink message failed")

    def _handle_downlink(self, data, ueId, received_at=None, ul_sent=None):
        tx_nas_pdu, ue, sent_type = self.dispatcher(data, ueId, received_at, ul_sent)
        self.ue_list[int(ue.supi[-10:])] = ue
        if tx_nas_pdu and sent_type != '5GSMPDUSessionTransmission':
            self._send_ngap((tx_nas_pdu, ueId, fg_msg_codes[sent_type]))
        elif tx_nas_pdu:
            self._send_upf((tx_nas_pdu, ueId, ue.supi))
            
        if sent_type == '5GMMRegistrationComplete' or sent_type == '5GSMPDUSessionEstabComplete' or sent_type == '5GSMPDUSessionTransmissionComplete':
            # send the next procedure
            tx_nas_pdu, ue, sent_type = self.dispatcher(None, ueId)
            self.ue_list[int(ue.supi[-10:])] = ue

            if tx_nas_pdu and sent_type != '5GSMPDUSessionTransmission':
                self._send_ngap((tx_nas_pdu, ueId, fg_msg_codes[sent_type]))
            elif tx_nas_pdu:
                self._send_upf((tx_nas_pdu, ueId, ue.supi))
        
        # TODO: handle recording of operation
        if sent_type == '5GMMANConnectionReleaseComplete' and self.inflight:
            self.inflight.release(ueId)   # the UE has finished: the next may start
        if sent_type is None: # Leave state as is, e.g., on ConfigurationUpdateCommand
            return
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
        ues = [ue for ue in self.ue_list.values() if ue]
        offsets = start_offsets(len(ues), self.interval, self.poisson, self.rng)
        for ue, offset in zip(ues, offsets):
            # An absolute schedule: a late start does not delay the later ones
            wait = start_time + offset - time.time()
            if wait > 0:
                time.sleep(wait)
            if self.inflight and not self.inflight.acquire(int(ue.supi[-10:]), stop=lambda: self.exit_program.value):
                return
            if (ue):
                tx_nas_pdu, ue_, sent_type = ue.next_action(None, ) if g_verbose <= 3 else ue.next_compliance_test(None, )
                self.ue_list[int(ue.supi[-10:])] = ue
                self._send_ngap((tx_nas_pdu, int(ue.supi[-10:]), fg_msg_codes[sent_type]))

                msg_code = fg_msg_codes[sent_type] - FGMM_MIN_TYPE
                self.procedures_count[ue.current_procedure] = self.procedures_count.get(ue.current_procedure, 1) - 1
                self.procedures_count[msg_code] = self.procedures_count.get(msg_code, 0) + 1
                with self.ue_fg_msg_states.get_lock():
                    self.ue_fg_msg_states[msg_code] += 1
                
                ue.current_procedure = msg_code


    def _expire_inflight(self):
        """ Free the places of UEs that did not finish in time, so the closed loop goes on """
        while not self.exit_program.value:
            time.sleep(0.5)
            for ue_id in self.inflight.expire():
                logger.warning(f"UE {ue_id} did not finish within {self.inflight.timeout} s: its place is freed")

    def show_results(self):
        global start_time
        latest_time = start_time
        end_time = time.time()
        min_interval = 9999999
        max_interval = 0
        completed = 0
        sum_interval = 0
        # Print test results in a table
        jsonArray = []
        for supi, ue in self.ue_list.items():
            # Write UE to file
            ue.procedure_times['UE'] = supi
            jsonArray.append(ue.procedure_times)
            # Get the UE that had the latest state_time and calculate the time it took all UEs to be registered
            # Don't consider UEs that didn't get a respond
            if ue.current_procedure == (fg_msg_codes["5GMMANConnectionReleaseComplete"] - FGMM_MIN_TYPE) and ue.end_time != None and ue.start_time != None:
                latest_time = ue.state_time if latest_time < ue.state_time else latest_time
                min_interval = ue.end_time - ue.start_time if (min_interval > ue.end_time - ue.start_time and ue.end_time - ue.start_time != 0)  else min_interval
                max_interval = ue.end_time - ue.start_time if max_interval < ue.end_time - ue.start_time else max_interval
                sum_interval += ue.end_time - ue.start_time
                with self.ue_sim_time.success.get_lock():
                    self.ue_sim_time.success.value += 1
            else:
                ue.error_message += f"\n\nUE hung for {end_time - ue.state_time} seconds"

            if g_verbose <= 4 and ue.error_message == "":
                continue

            SentMsgShow = ''
            if ue.MsgInBytes:
                SentMsg, err = parse_NAS5G(ue.MsgInBytes)
                if err:
                    logger.error('Failed to parse ue.MsgInBytes when print compliance test results')
                else:
                    SentMsgShow = SentMsg.show()

            RcvMsgShow = ''
            if ue.RcvMsgInBytes:
                RcvMsg, err = parse_NAS5G(ue.RcvMsgInBytes)
                if err:
                    logger.error('Failed to parse ue.RcvMsgInBytes when print compliance test results')
                else:
                    RcvMsgShow = RcvMsg.show()

            profile = ''
            for k, v in ue.compliance_mapper.items():
                profile += f"Request message: {k}, Response function: {v.__name__}\n"
            headers = ['UE', ue.supi + f" {(ue.current_procedure)}"]
            table = [
                     ['Message', ue.error_message], 
                     ['Profile', profile], 
                     ['Sent', SentMsgShow], 
                     ['Received', RcvMsgShow] ]
            logger.info("\n" + tabulate(table, headers, tablefmt="grid"))

        message_names = [
            fg_msg_names.get(code, f"Unknown_{code}")
            for code in range(FGMM_MIN_TYPE, FGSM_MAX_TYPE + 1)
        ]
        headers = ["UE"] + message_names
        
        message_codes = ["UE"] + list(range(FGMM_MIN_TYPE, FGSM_MAX_TYPE + 1))

        # One pair of files per UE simulator, in the output folder
        name = os.path.join(self.folder, f'procedure_times_{self.index if self.index is not None else psutil.Process().cpu_num()}')
        with open(f'{name}.json', 'w') as f:
                json.dump(jsonArray, f)

        with open(f'{name}.csv', 'w') as csvfile:
            hwriter = csv.writer(csvfile)
            hwriter.writerow(headers)
            writer = csv.DictWriter(csvfile, fieldnames=message_codes)
            writer.writerows(jsonArray)

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
        if cpu_core is not None:
            os.sched_setaffinity(0, {cpu_core})
        signal.signal(signal.SIGINT, partial(interrupt_handler, self, True))
        logger.info(f"Running {multiprocessing.current_process().name} with {len(self.ue_list)} UEs on CPU {psutil.Process().cpu_num()}")

        # Wait for GNB to be ready
        time.sleep(5)
        # Handle the 5GC's answers while the UEs are still being started (-i paces the starts)
        self.ngap_to_ue_thread = self._load_ngap_to_ue_thread()
        if self.inflight:
            threading.Thread(target=self._expire_inflight, daemon=True).start()
        self.init()
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
                if ue.current_procedure != (fg_msg_codes["5GMMANConnectionReleaseComplete"] - FGMM_MIN_TYPE): 
                    test_result, error_message = validator(ue.MsgInBytes, b'0')
                    ue.error_message = error_message
                    ue.RcvMsgInBytes = None
            
        self.show_results()

        sys.exit(0)