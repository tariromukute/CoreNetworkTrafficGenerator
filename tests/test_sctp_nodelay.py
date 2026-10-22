""" The gNB's SCTP socket: Nagle's algorithm off by default (SCTP_NODELAY), on when asked for.

Run from the repository root (needs pysctp and the kernel's SCTP module):

    python3 -m pytest tests/test_sctp_nodelay.py
"""
import socket

import pytest

from src.SCTP import SCTP_NODELAY, SCTPClient


def load_socket(nodelay):
    client = SCTPClient.__new__(SCTPClient)    # no association: only the socket's options
    client.nodelay = nodelay
    return client._load_socket()


@pytest.mark.parametrize("nodelay, expected", [(True, 1), (False, 0)])
def test_nodelay_option(nodelay, expected):
    sk = load_socket(nodelay)
    try:
        assert sk.sock().getsockopt(socket.IPPROTO_SCTP, SCTP_NODELAY) == expected
    finally:
        sk.close()


def test_nodelay_is_the_default():
    assert SCTPClient.__init__.__defaults__ == (True,)
