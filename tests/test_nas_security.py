""" Uplink NAS protection: security header type, NAS COUNT, and 5G-EA0 (null ciphering).

Run from the repository root (needs pycrate and CryptoMobile, as src/UEUtils.py does):

    python3 -m pytest tests/test_nas_security.py
"""
from types import SimpleNamespace

from pycrate_mobile.TS24501_FGMM import FGMMRegistrationComplete
from src.UEUtils import nas_plaintext, security_prot_encrypt_ciphered


def ue(ciph, integ):
    return SimpleNamespace(CiphAlgo=ciph, IntegAlgo=integ, k_nas_enc=16 * b'\x01', k_nas_int=16 * b'\x02',
                           ul_nas_count=0)


def protect(u):
    return security_prot_encrypt_ciphered(u, FGMMRegistrationComplete(val={'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0}}))


def test_count_grows_per_message():
    u = ue(0, 2)
    seqns = [protect(u)['Seqn'].get_val() for _ in range(3)]
    assert seqns == [0, 1, 2]
    assert u.ul_nas_count == 3


def test_sequence_number_wraps_into_the_overflow():
    u = ue(0, 2)
    u.ul_nas_count = 0x1FF
    assert protect(u)['Seqn'].get_val() == 0xFF
    assert protect(u)['Seqn'].get_val() == 0x00       # COUNT 0x200: overflow 2, sequence number 0
    assert u.ul_nas_count == 0x201


def test_null_ciphering_is_still_integrity_protected_and_ciphered():
    u = ue(0, 2)
    msg = protect(u)
    assert msg['5GMMHeaderSec']['SecHdr'].get_val() == 2
    assert msg['MAC'].get_val() != 0
    assert nas_plaintext(msg) == FGMMRegistrationComplete(val={'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0}}).to_bytes()


def test_ciphered_message_keeps_its_plaintext():
    u = ue(2, 2)
    msg = protect(u)
    plain = FGMMRegistrationComplete(val={'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0}}).to_bytes()
    assert msg['NASMessage'].get_val() != plain       # 128-5G-EA2 changed it
    assert nas_plaintext(msg) == plain
