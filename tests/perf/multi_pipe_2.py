"""
Benchmark using pipe with multiple processes. Source: https://stackoverflow.com/questions/8463008/multiprocessing-pipe-vs-queue
"""

from multiprocessing import Process, Pipe
import sys
import time
import threading

class NGAP:
    exit_flag = False

    def __init__(self, count, ngap_to_ue, ue_to_ngap):
        self.count = count
        self.ngap_to_ue = ngap_to_ue
        self.ue_to_ngap = ue_to_ngap
    
    def run(self):
        self.rcv_ue_data_thread = self.load_rcv_ue_data_thread(self.rcv_ue_data_thread_function)
        self.send_ue_data_thread = self.load_send_ue_data_thread(self.send_ue_data_thread_function)

    def load_rcv_ue_data_thread(self, rcv_ue_data_thread_function):
        rcv_ue_data_thread = threading.Thread(target=rcv_ue_data_thread_function)
        rcv_ue_data_thread.start()
        return rcv_ue_data_thread

    def rcv_ue_data_thread_function(self):
        while not NGAP.exit_flag:
            data = self.ue_to_ngap.recv()
            if data == 'DONE':
                self.ue_to_ngap.close()
                NGAP.exit_flag = True
    
    def load_send_ue_data_thread(self, send_ue_data_thread_function):
        send_ue_data_thread = threading.Thread(target=send_ue_data_thread_function)
        send_ue_data_thread.start()
        return send_ue_data_thread

    def send_ue_data_thread_function(self):
        for ii in range(0, self.count):
            self.ngap_to_ue.send(ii)
        self.ngap_to_ue.send('DONE')
            
class UE:
    exit_flag = False
    def __init__(self, count, ngap_to_ue, ue_to_ngap):
        self.count = count
        self.ngap_to_ue = ngap_to_ue
        self.ue_to_ngap = ue_to_ngap
    
    def run(self):
        self.rcv_ngap_data_thread = self.load_rcv_ngap_data_thread(self.rcv_ngap_data_thread_function)
        self.send_ngap_data_thread = self.load_send_ngap_data_thread(self.send_ngap_data_thread_function)

    def load_rcv_ngap_data_thread(self, rcv_ngap_data_thread_function):
        rcv_ngap_data_thread = threading.Thread(target=rcv_ngap_data_thread_function)
        rcv_ngap_data_thread.start()
        return rcv_ngap_data_thread

    def rcv_ngap_data_thread_function(self):
        while not UE.exit_flag:
            data = self.ngap_to_ue.recv()
            if data == 'DONE':
                self.ngap_to_ue.close()
                UE.exit_flag = True
    
    def load_send_ngap_data_thread(self, send_ngap_data_thread_function):
        send_ngap_data_thread = threading.Thread(target=send_ngap_data_thread_function)
        send_ngap_data_thread.start()
        return send_ngap_data_thread

    def send_ngap_data_thread_function(self):
        for ii in range(0, self.count):
            self.ue_to_ngap.send(ii)
        self.ue_to_ngap.send('DONE')

if __name__=='__main__':
    for count in [10**4, 10**5, 10**6]:
        ngap_to_ue, ue_to_ngap = Pipe()
        ngap = NGAP(count, ngap_to_ue, ue_to_ngap)
        ue = UE(count, ngap_to_ue, ue_to_ngap)
        _start = time.time()
        ngap_p = Process(target=ngap.run)
        ngap_p.daemon = True
        ngap_p.start()     # Launch the reader process

        ue_p = Process(target=ue.run)
        ue_p.daemon = True
        ue_p.start()     # Launch the reader process
        
        ngap_p.join()
        ue_p.join()
        print("Sending {0} numbers to Pipe() took {1} seconds".format(count,
            (time.time() - _start)))
    sys.exit(0)