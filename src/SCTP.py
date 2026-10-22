import socket
import logging
import sctp
from sctp import *
import threading
import select
import inspect

logger = logging.getLogger('__SCTPClient__')

# NGAP's SCTP payload protocol identifier (TS 38.412 §7). pysctp 0.7.3 converts the
# PPID to network byte order inside sctp_send(); 0.7.2 and earlier pass it through, so the caller
# had to. Give sctp_send() the value its version expects: a doubly converted PPID (0x3C000000)
# makes OAI's AMF close the association.
NGAP_PPID = 60
try:
    _PYSCTP_CONVERTS_PPID = 'ntohl(ppid)' in inspect.getsource(sctp.sctpsocket.sctp_send)
except (OSError, TypeError):
    _PYSCTP_CONVERTS_PPID = False
NGAP_PPID_ARG = NGAP_PPID if _PYSCTP_CONVERTS_PPID else socket.htonl(NGAP_PPID)

# NGAP messages are small. With Nagle's algorithm on, the kernel holds each one while earlier data
# is unacknowledged, and the AMF delays its SACK by up to 200 ms (net.sctp.sack_timeout) when it has
# nothing to send back: the messages then leave in bursts, and the delay counts as core latency.
# Python's socket module has no SCTP_NODELAY; linux/sctp.h defines it as 3.
SCTP_NODELAY = getattr(socket, 'SCTP_NODELAY', 3)

# Create a lock to synchronize access to socket
socket_lock = threading.Lock()

class SCTPClient():
    """ This class is a base class for all SCTP client contexts. """
    def __init__(self, server_config, nodelay=True):
        self.nodelay = nodelay
        try:
            self.__socket = self._load_socket()
            # self.__socket.events.data_io = 1
            # self.__socket.events.association = 1
            # self.__socket.events.address = 1
            # self.__socket.events.send_failure = 1
            # self.__socket.events.peer_error = 1
            # self.__socket.events.shutdown = 1
            # self.__socket.events.partial_delivery = 1
            # self.__socket.events.adaptation_layer = 1
            # print(f"Association {self.__socket.events.association}")
        except:
            logger.exception("Failed to create socket")
            raise
        # TODO: Allow connecting to multiple servers
        self.server_config = server_config['amfConfigs'][0]
        self.connect()

    def connect(self) -> None:
        logger.debug("Connecting to 5G Core")
        logger.debug("Server config: {}".format(self.server_config))
        self.__socket.connect((self.server_config['address'], self.server_config['port']))

    def disconnect(self) -> None:
        logger.info("Disconnecting from 5G Core")
        if socket_lock.locked():
            socket_lock.release()
        self.__socket.close()

    def _load_socket(self):
        # Create SCTP socket; Nagle's algorithm is off unless asked for (see SCTP_NODELAY)
        sk = sctp.sctpsocket_tcp(socket.AF_INET)
        sk.sock().setsockopt(socket.IPPROTO_SCTP, SCTP_NODELAY, int(self.nodelay))
        return sk

    def send(self, data: bytes):
        # Acquire the socket lock before sending data
        if self.__socket._closed:
            raise
         
        sock = self.__socket.sock()
        while True:
            readable, writable, exceptional = select.select([], [sock], [sock], 0.1)

            if sock in writable:
                break
            # print("------------- Received request to send but socket not writable ---------------")

        socket_lock.acquire()
        try:
            self.__socket.sctp_send(data, ppid=NGAP_PPID_ARG)
        except ConnectionResetError:
            print("************ Connection reset ******************")
            self.disconnect()
        except Exception as e:
            print(f"*********** General error {e}")
        finally:
            # Release the socket lock after sending data
            socket_lock.release() 

    def recv(self) -> bytes:
        if self.__socket._closed:
            raise
        
        sock = self.__socket.sock()
        readable, writable, exceptional = select.select([sock], [], [sock], 0.1)

        if sock not in readable:
            return None
        
        # Acquire the socket lock before receiving data
        socket_lock.acquire()
        try:
            sctp_data = self.__socket.recv(4096)
            # fromaddr, flags, sctp_data, notif = self.__socket.sctp_recv(4096)
            # if flags & FLAG_NOTIFICATION:
            #     print(f"+++++++++++ Received notification, flags {flags}, notif {notif.__dict__}")
        
            if not sctp_data:
                logger.debug('SCTP disconnection')
                return None
            return sctp_data
        except ConnectionResetError:
            logger.error("************ Connection reset ******************")
            self.disconnect()
        except Exception as e:
            print(f"*********** General error {e}")
        finally:
            # Release the socket lock after receiving data
            socket_lock.release()

    def close(self) -> None:
        return super().close()