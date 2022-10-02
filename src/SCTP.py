import socket
import queue
import threading
import binascii
import logging
import json
import time

from Ctx import ClientCtx, ServerCtx

# Create SCTP Client class inheriting from Client Ctx class
class SCTPClient(ClientCtx):
    """ This class is a base class for all SCTP client contexts. """
    def __init__(self, config):
        # Call parent class init
        super().__init__(config)
        self.logger = logging.getLogger('SCTPClient')
        self._sctp_queue = self._load_sctp_queue()
        self._thread = self._load_thread(self._thread_function)
        self._listener_thread = self._load_listener(self._listener_thread_function)

    def _load_socket(self):
        # Create SCTP socket
        sctp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
        # Return SCTP socket
        return sctp_socket

    def _load_sctp_queue(self):
        # Create SCTP queue
        return queue.Queue()

    def _load_thread(self, client_thread_function) -> threading.Thread:
        # Create SCTP thread
        sctp_thread = threading.Thread(target=client_thread_function, daemon=True)
        # Start SCTP thread
        sctp_thread.start()
        # Return SCTP thread
        return sctp_thread

    def _load_listener(self, listener_thread_function) -> threading.Thread:
        # Create SCTP listener thread
        sctp_listener_thread = threading.Thread(target=listener_thread_function, daemon=True)
        # Start SCTP listener thread
        sctp_listener_thread.start()
        # Return SCTP listener thread
        return sctp_listener_thread

    def _listener_thread_function(self) -> None:
        # Loop forever
        while True:
            # Check if SCTP connection is closed
            if self._socket._closed:
                # Log SCTP connection
                self.logger.info('SCTP connection closed')
                # Break loop
                break
            # Receive data from SCTP connection
            sctp_data = self._socket.recv(4096)
            # Check if data is empty
            if not sctp_data:
                # Log SCTP disconnection
                self.logger.info('SCTP disconnection')
                # Break loop
                break
            # Log SCTP data
            self.logger.info('SCTP Client data: %s', binascii.hexlify(sctp_data).decode('utf-8'))
            # Put data in SCTP queue
            # self.sctp_queue.put(sctp_data)
        # Close SCTP connection
        self._socket.close()

    def _thread_function(self) -> None:
        # Loop forever
        while True:
            # Check if connection is closed
            if self._socket._closed:
                # Break loop
                self.logger.info('_sctp_thread_function: SCTP socket closed exiting thread')
                break
            # Check if SCTP queue is not empty
            if not self._sctp_queue.empty():
                # Get SCTP message from queue
                sctp_message = self._sctp_queue.get()
                # Send SCTP message
                self._socket.send(sctp_message)
                # Log SCTP message
                self.logger.info('_sctp_thread_function: sent SCTP message: {}'.format(sctp_message))
            # Sleep for 1 second
            time.sleep(1)

    def send(self, data: bytes):
        # Check if connection is closed
        if self._socket._closed:
            # Break loop
            self.logger.info('_sctp_thread_function: SCTP socket closed exiting thread')
            return
        # Put SCTP message in queue
        self._sctp_queue.put(data)
        # Log SCTP message
        self.logger.info('send: queued SCTP message: {}'.format(binascii.hexlify(sctp_data).decode('utf-8')))

    def recv(self, size) -> bytes:
        return super().recv(size)

    def close(self) -> None:
        return super().close()

    def connect(self, address, port) -> None:
        # Connect to SCTP socket
        self._socket.connect((address, port))

    def disconnect(self) -> None:
        # Disconnect from SCTP socket
        self.logger.info('Closing SCTP socket')
        self._socket.close()

# Create SCTP Server class inheriting from Server Ctx class
class SCTPServer(ServerCtx):
    """ This class is a base class for all SCTP server contexts. """
    def __init__(self, config):
        # Call parent class init
        super().__init__(config)
        self.logger = logging.getLogger('SCTPServer')
        self._thread = self._load_thread(self._thread_function)
        self._sctp_queue = self._load_sctp_queue()

    def _load_socket(self):
        # Create SCTP socket
        sctp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
        # Bind SCTP socket to address and port
        sctp_socket.bind((self._config['sctp']['address'], self._config['sctp']['port']))
        # Listen for incoming connections
        sctp_socket.listen(1)
        # Return SCTP socket
        return sctp_socket

    def _load_sctp_queue(self):
        # Create SCTP queue
        return queue.Queue()

    def _load_thread(self, client_thread_function) -> threading.Thread:
        # Create SCTP thread
        sctp_thread = threading.Thread(target=client_thread_function, daemon=True)
        # Start SCTP thread
        sctp_thread.start()
        # Return SCTP thread
        return sctp_thread

    def _connection_thread_function(self, sctp_connection, sctp_address):
        # Loop forever
        while True:
            # Check if SCTP connection is closed
            if sctp_connection._closed:
                # Log SCTP connection
                self.logger.info('SCTP connection from %s:%d closed', sctp_address[0], sctp_address[1])
                # Break loop
                break
            # Receive data from SCTP connection
            sctp_data = sctp_connection.recv(4096)
            # Check if data is empty
            if not sctp_data:
                # Log SCTP disconnection
                self.logger.info('SCTP disconnection from %s:%d', sctp_address[0], sctp_address[1])
                # Break loop
                break
            # Log SCTP data
            self.logger.info('SCTP data from %s:%d: %s', sctp_address[0], sctp_address[1], binascii.hexlify(sctp_data).decode('utf-8'))
            # Log SCTP data
            response = self.handle_sctp_data(sctp_data)
            if response:
                self.logger.info('SCTP response: %s', binascii.hexlify(response).decode('utf-8'))
                sctp_connection.send(response)
            # # Put data in SCTP queue
            # self._sctp_queue.put(sctp_data)
        # Close SCTP connection
        sctp_connection.close() 

    
    def _thread_function(self) -> None:
       # Loop forever
        while True:
            # Accept incoming connection
            sctp_connection, sctp_address = self._socket.accept()
            # Log SCTP connection
            self.logger.info('SCTP connection from %s:%d', sctp_address[0], sctp_address[1])
            # Create SCTP connection thread
            sctp_connection_thread = threading.Thread(target=self._connection_thread_function, args=(sctp_connection, sctp_address), daemon=True)
            # Start SCTP connection thread
            sctp_connection_thread.start()

    def handle_sctp_data(self, sctp_data):
        # Log SCTP data
        self.logger.info('SCTP data: %s', binascii.hexlify(sctp_data).decode('utf-8'))
        # Check if data needs a response
        if sctp_data[0] != 0x01:
            # Send response
            return b'OK'
        return None

    def send(self, data: bytes):
        # Check if connection is closed
        if self._socket._closed:
            # Break loop
            self.logger.info('_sctp_thread_function: SCTP socket closed exiting thread')
            return
        # Put SCTP message in queue
        self._sctp_queue.put(data)
        # Log SCTP message
        self.logger.info('send: queued SCTP message: {}'.format(binascii.hexlify(sctp_data).decode('utf-8')))

    def recv(self, size) -> bytes:
        return super().recv(size)

    def close(self):
        # Close SCTP socket
        self._socket.close()
        # Wait for listener thread to finish
        self._listener_thread.join()

    def listen(self) -> None:
        return super().listen()