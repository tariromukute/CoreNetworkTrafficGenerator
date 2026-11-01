""" The gNB picks the NGAP procedure for an uplink NAS message from its header, as parsing it would.

Run from the repository root (needs pycrate, as src/NGAPSim.py does):

    python3 -m pytest tests/test_uplink_procedure.py
"""
from types import SimpleNamespace

from pycrate_mobile.NAS5G import parse_NAS5G
from pycrate_mobile.TS24501_FGMM import FGMMRegistrationComplete, FGMMRegistrationRequest
from src.NGAPSim import is_plain_registration_request
from src.UEUtils import security_prot_encrypt_ciphered


def protected(msg):
    ue = SimpleNamespace(CiphAlgo=0, IntegAlgo=2, k_nas_enc=16 * b'\x01', k_nas_int=16 * b'\x02', ul_nas_count=0)
    return security_prot_encrypt_ciphered(ue, msg).to_bytes()


def as_parsed(nas_pdu):
    msg, err = parse_NAS5G(nas_pdu)
    assert not err
    return msg._name == '5GMMRegistrationRequest'


def test_plain_registration_request_is_initial():
    nas_pdu = FGMMRegistrationRequest().to_bytes()
    assert is_plain_registration_request(nas_pdu) and as_parsed(nas_pdu)


def test_other_plain_messages_are_not():
    nas_pdu = FGMMRegistrationComplete().to_bytes()
    assert not is_plain_registration_request(nas_pdu) and not as_parsed(nas_pdu)


def test_protected_messages_are_not():
    nas_pdu = protected(FGMMRegistrationRequest())
    assert not is_plain_registration_request(nas_pdu) and not as_parsed(nas_pdu)


def test_short_input():
    assert not is_plain_registration_request(b'\x7e')
