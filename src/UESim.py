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

    def __init__(self, exit_program, ue_list, ngap_to_ue, ue_to_ngap, upf_to_ue, ue_to_upf, interval, statistics, verbose, ue_sim_time):
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
            return ue.next_action(data, '5GMMANConnectionRelease') if g_verbose <= 3 else ue.next_compliance_test(data, '5GMMANConnectionRelease')
        
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
        
        _msg_type = f">>{msg_type}"
        self.procedures_count[ue.current_procedure] = self.procedures_count.get(ue.current_procedure, 1) - 1
        self.procedures_count[_msg_type] = self.procedures_count.get(_msg_type, 0) + 1
        ue.current_procedure = _msg_type
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
        # ngap_to_ue_thread = threading.Thread(target=self._ngap_to_ue_thread_function)
        # ngap_to_ue_thread.daemon = True
        # ngap_to_ue_thread.start()
        # return ngap_to_ue_thread
        return threads

    def _ngap_to_ue_thread_function(self):
        """ Thread function that will handle NAS DownLink messages from gNB 

            It will select the NAS procedure to be executed based on the NAS message type.
            When the NAS procedure is completed, the NAS message will be put on a queue 
            that will be read by the gNB thread.
        """
        while not UESim.exit_flag:
            # process = psutil.Process()
            # cpu_affinity = process.cpu_affinity()  # Get current CPU affinity as a set
            # cpu_core = next(iter(cpu_affinity))  # Extract any CPU core
            # print(f"Process {multiprocessing.current_process().name} working on CPU {process.cpu_num()}")
            data = None
            ueId = None
            with lock:
                data, ueId = self.ue_to_ngap.recv()
            if data:
                tx_nas_pdu, ue, sent_type = self.dispatcher(data, ueId)
                self.ue_list[int(ue.supi[-10:])] = ue
                if tx_nas_pdu and sent_type != '5GUPMessage':
                    self.ue_to_ngap.send((tx_nas_pdu, ueId))
                elif tx_nas_pdu:
                    self.ue_to_upf.send((tx_nas_pdu, ueId))
                    
                if sent_type == '5GMMRegistrationComplete' or sent_type == '5GSMPDUSessionEstabComplete' or sent_type == '5GUPMessageComplete':
                    # send the next procedure
                    tx_nas_pdu, ue, sent_type = self.dispatcher(None, ueId)
                    self.ue_list[int(ue.supi[-10:])] = ue

                    if tx_nas_pdu and sent_type != '5GUPMessage':
                        self.ue_to_ngap.send((tx_nas_pdu, ueId))
                    elif tx_nas_pdu:
                        self.ue_to_upf.send((tx_nas_pdu, ueId))
                _sent_type = f"{sent_type}>>"
                self.procedures_count[ue.current_procedure] = self.procedures_count.get(ue.current_procedure, 1) - 1
                self.procedures_count[_sent_type] = self.procedures_count.get(_sent_type, 0) + 1
                ue.current_procedure = _sent_type

    def _load_upf_to_ue_thread(self):
        """ Load the thread that will handle NAS DownLink messages from gNB """
        upf_to_ue_thread = threading.Thread(target=self._upf_to_ue_thread_function)
        upf_to_ue_thread.daemon = True
        upf_to_ue_thread.start()
        return upf_to_ue_thread

    def _upf_to_ue_thread_function(self):
        """ Thread function that will handle NAS DownLink messages from gNB 

            It will select the NAS procedure to be executed based on the NAS message type.
            When the NAS procedure is completed, the NAS message will be put on a queue 
            that will be read by the gNB thread.
        """
        while not UESim.exit_flag:
            data, ueId = self.ue_to_upf.recv()
            if data:
                ue = self.ue_list[ueId]
                tx_nas_pdu, sent_type = up_send_data(ue, None, data)
                self.ue_list[int(ue.supi[-10:])] = ue
                if tx_nas_pdu and sent_type == '5GUPMessage':
                    self.ue_to_upf.send((tx_nas_pdu, ueId))
                else:
                    tx_nas_pdu, ue, sent_type = self.dispatcher(None, ueId)
                    self.ue_list[int(ue.supi[-10:])] = ue

                    if tx_nas_pdu and sent_type != '5GUPMessage':
                        self.ue_to_ngap.send((tx_nas_pdu, ueId))
                    
    
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
                _sent_type = f"{sent_type}>>"
                self.procedures_count[ue.current_procedure] = self.procedures_count.get(ue.current_procedure, 1) - 1
                self.procedures_count[_sent_type] = self.procedures_count.get(_sent_type, 0) + 1
                ue.current_procedure = _sent_type

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
        
        # run forever
        while not UESim.exit_flag:
            try:
                ue_state_count, fgmm_state_names = self.update_ue_state_counts()
                if self.statistics:
                    # print(f"{dict(zip(fgmm_state_names, ue_state_count))}")
                    print(self.procedures_count)

                # If all the UEs have registered exit
                if ue_state_count[FGMMState.CONNECTION_RELEASED] >= self.number:
                    
                    # Tell parent process to exit
                    UESim.exit_flag = True
                    self.exit_program.value = True
                time.sleep(1)
            except Exception:
                # logger.exception('Whoops! Problem:', file=sys.stderr)
                traceback.print_exc(file=sys.stderr)

        self.stop()

    def show_results(self, fgmm_state_names):
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
            if ue.state >= FGMMState.DEREGISTERED and ue.end_time != None and ue.start_time != None:
                latest_time = ue.state_time if latest_time < ue.state_time else latest_time
                min_interval = ue.end_time - ue.start_time if min_interval > ue.end_time - ue.start_time else min_interval
                max_interval = ue.end_time - ue.start_time if max_interval < ue.end_time - ue.start_time else max_interval
                sum_interval += ue.end_time - ue.start_time
                completed += 1
            else:
                ue.error_message += f"\n\nUE hung for {end_time - ue.state_time} seconds"

            if g_verbose <= 4 and ue.error_message == "":
                continue
            SentMsg, err = parse_NAS5G(ue.MsgInBytes)
            if err:
                print('Failed to parse ue.MsgInBytes when print compliance test results')
                SentMsgShow = ''
            else:
                SentMsgShow = SentMsg.show()
            RcvMsg, err = parse_NAS5G(ue.RcvMsgInBytes)
            if err:
                print('Failed to parse ue.RcvMsgInBytes when print compliance test results')
                RcvMsgShow = ''
            else:
                RcvMsgShow = RcvMsg.show()
            profile = ''
            for k, v in ue.compliance_mapper.items():
                profile += f"Request message: {k}, Response function: {v.__name__}\n"
            headers = ['UE', ue.supi]
            table = [['Status', fgmm_state_names[ue.state]], 
                     ['Message', ue.error_message], 
                     ['Profile', profile], 
                     ['Sent', SentMsgShow], 
                     ['Received', RcvMsgShow] ]
            print(tabulate(table, headers, tablefmt="grid"))

        # Calculate the number of seconds between the monotonic starting point and the Unix epoch
        epoch_to_monotonic_s = time.monotonic() - time.time()
 
        self.ue_sim_time.end_time.value = int((latest_time + epoch_to_monotonic_s) * 1e9)
        self.ue_sim_time.start_time.value = int((start_time + epoch_to_monotonic_s) * 1e9)
        table = [["Duration",f" {end_time - start_time} seconds"],["Completed in",f" {latest_time - start_time} seconds"],
        ["N# of UEs",self.number],["Successful procedures ",f"{completed} UEs"],
        ["Failed procedures",f"{len(self.ue_list) - completed} UEs"],["Min interval",f"{min_interval} seconds"],
        ["Avg interval",f"{sum_interval/completed if completed > 0 else -1} seconds"], ["Max interval",f"{max_interval} seconds"]]
        print("\n\n")
        print(tabulate(table, ["Item","Results"], tablefmt="heavy_outline"))

    def print_compliance_test_results(self):
        global start_time

        # run forever
        while not UESim.exit_flag:
            try:
                ue_state_count, fgmm_state_names = self.update_ue_state_counts()
                if self.statistics:
                    print(f"{dict(zip(fgmm_state_names, ue_state_count))}")
                
                # If all the UEs have registered exit
                if ue_state_count[FGMMState.DEREGISTERED] + ue_state_count[FGMMState.CONNECTION_RELEASED] + ue_state_count[FGMMState.FAIL] + ue_state_count[FGMMState.PASS] >= self.number:
                    
                    # Tell parent process to exit
                    UESim.exit_flag = True
                    self.exit_program.value = True
                time.sleep(1)
            except Exception:
                # logger.exception('Whoops! Problem:', file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
        
        self.stop()
        
    def run(self, cpu_core):
        affinity_mask = { cpu_core } 
        os.sched_setaffinity(0, affinity_mask)
        signal.signal(signal.SIGINT, partial(interrupt_handler, self, True))
        """ Run the NAS thread """
        logger.info(f"Running {multiprocessing.current_process().name} with {len(self.ue_list)} UEs on CPU {psutil.Process().cpu_num()}")
        # self.create_ues()
        # Wait for GNB to be ready
        time.sleep(5)
        self.init()
        self.ngap_to_ue_thread = self._load_ngap_to_ue_thread()
        self.upf_to_ue_thread = self._load_upf_to_ue_thread()
        if g_verbose > 3:
            self.print_compliance_test_results()
        else:
            self.print_stats_process()
        self.ngap_to_ue.close()
        sys.exit(0)

    def stop(self):
        # Check the UE if the have all terminated if not log details and state the UE is in
        if UESim.exit_flag == False:
            # Check if any UEs are not terminated and call validator
            for supi, ue in self.ue_list.items():
                if ue.state < FGMMState.DEREGISTERED:
                    test_result, error_message = validator(ue.MsgInBytes, b'0')
                    ue.state = test_result
                    ue.error_message = error_message
                    ue.RcvMsgInBytes = None
            
        fgmm_state_names = [
                FGMMState(i).name for i in range(FGMMState.FGMM_STATE_MAX)]
        self.show_results(fgmm_state_names)

        print(f"Stopping UESim press ctrl+c to end program")
        sys.exit(0)
