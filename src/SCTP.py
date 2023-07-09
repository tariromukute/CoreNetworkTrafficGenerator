import socket
import threading
import binascii
import logging
import sctp

from logging.handlers import QueueHandler

from Ctx import ClientCtx, ServerCtx

logger = logging.getLogger('__SCTPClient__')

class SCTPClient():
    """ This class is a base class for all SCTP client contexts. """
    def __init__(self, server_config):
        self.__socket = self._load_socket()
        # TODO: Allow connecting to multiple servers
        self.server_config = server_config['amfConfigs'][0]
        self.connect()

    def connect(self) -> None:
        logger.debug("Connecting to 5G Core")
        logger.debug("Server config: {}".format(self.server_config))
        self.__socket.connect((self.server_config['address'], self.server_config['port']))

    def disconnect(self) -> None:
        logger.debug("Disconnecting from 5G Core")
        self.__socket.close()

    def _load_socket(self):
        # Create SCTP socket
        return sctp.sctpsocket_tcp(socket.AF_INET)

    def send(self, data: bytes):
        self.__socket.sctp_send(data, ppid=socket.htonl(60))

    def recv(self) -> bytes:
        if self.__socket._closed:
            return None
        sctp_data = self.__socket.recv(4096)
        if not sctp_data:
            logger.debug('SCTP disconnection')
            return None
        return sctp_data

    def close(self) -> None:
        return super().close()