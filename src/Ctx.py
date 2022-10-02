import socket
import queue
import threading
import binascii
import logging
import json
import time

from abc import ABC, ABCMeta, abstractmethod

class Ctx(metaclass=ABCMeta):
    """ This class is a base class for all contexts. """
    def __init__(self, config):
        self._ctx = None
        self._config = config
        self._socket = self._load_socket()
        # Create ctx thread
        # self._thread = self._load_thread(self._thread_function)

    def _load_ctx(self):
        """ This method loads the context. """
        pass

    def _load_socket(self):
        """ This method loads the socket for the context. """
        pass

    @abstractmethod
    def _load_thread(self, client_thread_function) -> threading.Thread:
        """ This method loads the client thread. """
        pass

    @abstractmethod
    def _thread_function(self) -> None:
        """ This method is the client thread function. """
        pass

    @abstractmethod
    def send(self, data: bytes) -> int:
        """ This method sends data to the socker. """
        pass

    @abstractmethod
    def recv(self, size) -> bytes:
        """ This method receives data from the socket. """
        pass

    @abstractmethod
    def close(self) -> None:
        """ This method closes the socket. """
        pass

    # @abstractmethod
    # def get(self):
    #     """ This method returns the context. """
    #     pass

    # @abstractmethod
    # def set(self, ctx):
    #     """ This method sets the context. """
    #     pass

    # @abstractmethod
    # def clear(self):
    #     """ This method clears the context. """
    #     pass

    # @abstractmethod
    # def is_set(self):
    #     """ This method returns True if the context is set. """
    #     pass

    # @abstractmethod
    # def is_not_set(self):
    #     """ This method returns True if the context is not set. """
    #     pass

    # @abstractmethod
    # def __enter__(self):
    #     """ This method is called when entering a context. """
    #     pass

    # @abstractmethod
    # def __exit__(self, exc_type, exc_value, traceback):
    #     """ This method is called when exiting a context. """
    #     pass

    # @abstractmethod
    # def __call__(self, ctx):
    #     """ This method is called when the context is used as a decorator. """
    #     pass

# Create client context class that inherits from context abstract class
class ClientCtx(Ctx, metaclass=ABCMeta):
    """ This class is a base class for all client contexts. """
    def __init__(self, config):
        # Call parent class init
        super().__init__(config)
    

    @abstractmethod
    def connect(self, address, port) -> None:
        """ This method connects the client to the server. """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """ This method disconnects the client from the server. """
        pass

# Create a server context class that inherits from context abstract class
class ServerCtx(Ctx, metaclass=ABCMeta):
    """ This class is a base class for all server contexts. """
    def __init__(self, config):
        # Call parent class init
        super().__init__(config)
        

    # Create abstract methods for server context class
    @abstractmethod
    def listen(self) -> None:
        """ This method listens for incoming connections. """
        pass

    @abstractmethod
    def _connection_thread_function(self) -> None:
        """ This method is the connection thread function. """
        pass