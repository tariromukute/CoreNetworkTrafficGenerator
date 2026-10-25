""" The UE simulator's NAS fast path (src/nasfast.py): the same bytes sent, and the same values handed to
the handlers, as pycrate's path (src/nascache.py).

- OAI's downlink messages from the testbed captures (tests/data/oai_nas_captures.json): each UE's
  registration (and PDU session) replayed sends the uplink messages CN-TG sent then, byte for byte,
  on the fast path without touching pycrate, and on pycrate's path.
- Many UEs (PLMNs with 2- and 3-digit MNCs, MSINs, keys, OP and OPc, slices, sessions, IMEISVs, the
  algorithms 5G-EA0/1/2 with 5G-IA0/1/2, and some the templates do not cover), interleaved at random,
  through registration, PDU session and deregistration, with downlink messages of many forms, odd and
  malformed ones included: every message sent (or exception raised), every UE's state and the
  dispatcher's counts are those of pycrate's path; also on three threads.
- The parser against pycrate's decoding, for well-formed, odd, truncated and mutated messages; the
  templates and protect() against the builders and security_prot_encrypt_ciphered().

Run from the repository root (needs pycrate and CryptoMobile, as src/UESim.py does):

    python3 -m pytest tests/test_nas_fastpath.py
"""
import contextlib
import json
import logging
import os
import random
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from pycrate_mobile.NAS5G import parse_NAS5G as pycrate_parse_NAS5G
from pycrate_mobile.TS24501_FGMM import (FGMMAuthenticationRequest, FGMMDLNASTransport, FGMMMODeregistrationAccept,
                                         FGMMSecProtNASMessage, FGMMSecurityModeCommand)
from pycrate_mobile.TS24501_FGSM import FGSMPDUSessionEstabAccept, FGSMPDUSessionReleaseCommand

import src.UE
import src.UEMessages
import src.UESim
from src import nascache, nasfast
from src.UE import UE
from src.UEMessages import security_mode_complete
from src.UEUtils import dl_nas_transport_extract, security_prot_decrypt, security_prot_encrypt_ciphered

sys.path.insert(0, os.path.dirname(__file__))
from test_message_cache import (auth_request, configuration_update_command, make_sim,  # noqa: E402
                                pdu_session_accept, registration_accept, registration_reject,
                                security_mode_command, ue_config)

ALGORITHMS = [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2), (2, 0), (2, 1), (2, 2)]


@pytest.fixture
def quiet(monkeypatch):
    monkeypatch.setattr(src.UESim, 'g_verbose', 1, raising=False)
    monkeypatch.setattr(nasfast, 'ENABLED', True)


@contextlib.contextmanager
def fastpath(on):
    saved = nasfast.ENABLED
    nasfast.ENABLED = on
    try:
        yield
    finally:
        nasfast.ENABLED = saved


@contextlib.contextmanager
def without_pycrate():
    """ The pycrate path's entry points fail: what passes went through the fast path only """
    def fail(*args, **kwargs):
        raise AssertionError('the pycrate path was used')
    saved = (nascache.parse_NAS5G, nascache.MessageTemplate.build, src.UEMessages.security_prot_encrypt_ciphered)
    nascache.parse_NAS5G = nascache.MessageTemplate.build = src.UEMessages.security_prot_encrypt_ciphered = fail
    try:
        yield
    finally:
        nascache.parse_NAS5G, nascache.MessageTemplate.build, src.UEMessages.security_prot_encrypt_ciphered = saved


def ue_state(ue):
    """ What the UE keeps: its message, NAS COUNT, keys, algorithms, state and procedure """
    return (ue.MsgInBytes, ue.ul_nas_count, ue.k_ausf, ue.k_seaf, ue.k_amf, ue.k_nas_enc, ue.k_nas_int,
            ue.CiphAlgo, ue.IntegAlgo, ue.state, ue.IpAddress, ue.procedure, ue.current_procedure,
            sorted(map(str, ue.procedure_times)))


def sim_state(sim):
    return (dict(sim.procedures_count), list(sim.ue_fg_msg_states))


def outcome(sim, data, i):
    """ What dispatcher() returns, or the exception it raises """
    try:
        out = sim.dispatcher(data, i)
    except Exception as e:
        return ('raised', type(e).__name__, str(e))
    return (out[0], type(out[0]), len(out), out[2] if len(out) > 2 else None)


# --------------------------------------------------------------------------------------------------
# OAI's messages from the testbed captures
# --------------------------------------------------------------------------------------------------

CAPTURES = json.loads((Path(__file__).parent / 'data' / 'oai_nas_captures.json').read_text())


def captured_ues():
    for cap in CAPTURES['captures']:
        for msgs in cap['ues']:
            rr = bytes.fromhex(msgs[0][1])
            msin = rr[-11:-6].hex()               # the SUCI's BCD MSIN, its digits swapped in pairs
            msin = ''.join(msin[k + 1] + msin[k] for k in range(0, 10, 2))
            config = dict(CAPTURES['ue'], supi=CAPTURES['ue']['mcc'] + CAPTURES['ue']['mnc'] + msin,
                          procedures=cap['procedures'])
            yield cap['source'], config, [(d, bytes.fromhex(h)) for d, h in msgs]


def replay(config, msgs):
    """ The uplink messages a UE sends for the captured downlink ones, and the UE """
    sim = make_sim({0: UE(config)})
    sent = [sim.dispatcher(None, 0)[0]]
    for direction, data in msgs[1:]:
        if direction != 'dl':
            continue
        out, _, sent_type = sim.dispatcher(data, 0)
        if out:
            sent.append(out)
        if sent_type == '5GMMRegistrationComplete' and len(config['procedures']) > 1:
            sent.append(sim.dispatcher(None, 0)[0])         # what _handle_downlink() does next
    return sent, sim.ue_list[0]


def test_oai_registrations_send_what_cn_tg_sent(quiet):
    n = 0
    for source, config, msgs in captured_ues():
        expected = [data for direction, data in msgs if direction == 'ul']
        with without_pycrate():
            sent, ue = replay(config, msgs)
        assert sent == expected, source
        assert all(type(m) is bytes for m in sent)
        with fastpath(False):
            ref_sent, ref_ue = replay(config, msgs)
        assert ref_sent == expected, source
        assert ue_state(ue) == ue_state(ref_ue), source
        # the captured downlink messages are OAI's for the keys the UE derived: their MACs check
        for direction, data in msgs[2:]:
            if direction == 'dl' and data[1] in (2, 3):
                sec = FGMMSecProtNASMessage()
                sec.from_bytes(data)
                assert sec.mac_verify(key=ue.k_nas_int, dir=1, fgia=ue.IntegAlgo, seqnoff=0, bearer=1), source
        n += 1
    assert n == 60


def test_oai_downlink_messages_parse_as_pycrate_parses_them(quiet):
    for source, config, msgs in captured_ues():
        ue = UE(config)
        ue.CiphAlgo = 0                           # OAI's 5G-EA0
        for direction, data in msgs[1:]:
            if direction == 'dl':
                fast = nasfast.downlink(data, ue)
                assert fast is not None, data.hex()
                assert handler_view(*fast) == handler_view(*ref_decode(data, ue)), data.hex()


# --------------------------------------------------------------------------------------------------
# Downlink messages of many forms
# --------------------------------------------------------------------------------------------------

def ref_decode(data, ue):
    """ dispatcher()'s decoding of a downlink message with pycrate (src/UESim.py): (message, name), or
    'error' where it returns early """
    msg, err = nascache.parse_NAS5G(data)
    if err:
        return 'error'
    if msg._name == '5GMMSecProtNASMessage':
        msg = security_prot_decrypt(msg, ue)
        if not msg:
            return 'error'
        if msg._by_name.count('5GMMSecurityModeCommand'):
            msg = msg['5GMMSecurityModeCommand']
    if msg._name == '5GMMDLNASTransport':
        msg = dl_nas_transport_extract(msg, ue)
    return msg, msg._name


def handler_view(msg, name):
    """ What the UE's handlers read of a message (src/UEMessages.py) """
    try:
        if name == '5GMMAuthenticationRequest':
            return (name, list(msg['AUTN']['AUTN'].get_val()), list(msg['RAND'].get_val()), msg['ABBA']['V'].get_val())
        if name == '5GMMSecurityModeCommand':
            return (name, msg['NASSecAlgo']['NASSecAlgo'].get_val_d())
        if name == '5GSMPDUSessionEstabAccept':
            return (name, msg['PDUAddress']['PDUAddress'].get_val_d())
    except Exception as e:
        return (name, 'raises', type(e).__name__)
    return (name,)


OAI_RA = bytes.fromhex('7e0042010177000bf202f859010041dd24c5a454070002f85900a000150504de00007b310504de00007b'
                       '210201005e01b616010c')
OAI_PDU_ACCEPT = bytes.fromhex(
    '7e006801005a2e0101c211000901000631210101ff01060b00010b00012905010c0100022204de00007b817900060120410101097b000d'
    '80000d04080808080010020578251a0764656661756c74056d6e633935066d636332303804677072731201')


def truncated(rng, buf):
    return buf[:rng.randrange(3, len(buf))] if len(buf) > 3 else buf


def odd_auth_request(rng):
    val = {'NAS_KSI': rng.randrange(8), 'ABBA': rng.choice([b'\x00\x00', b'', b'\x00\x00\x01']),
           'RAND': rng.randbytes(16), 'AUTN': rng.randbytes(16)}
    k = rng.randrange(7)
    if k == 0:
        val['EAPMsg'] = b'\x01\x02\x00\x05\x17'
    elif k == 1:
        del val['AUTN']
    elif k == 2:
        del val['RAND']
    buf = FGMMAuthenticationRequest(val=val).to_bytes()
    if k == 3:                                    # an AUTN of another length
        buf = FGMMAuthenticationRequest(val={'ABBA': b'\x00\x00', 'RAND': rng.randbytes(16)}).to_bytes()
        n = rng.choice([0, 8, 15, 17, 32])
        buf += b'\x20' + bytes([n]) + rng.randbytes(n)
    elif k == 4:
        buf += rng.choice([b'\x7f\x00\x02\xaa\xbb', b'\x21' + rng.randbytes(16), b'\x55\x01\x00'])  # unknown, again
    elif k == 5:
        buf = truncated(rng, buf)
    return buf


def odd_security_mode_command(rng, ciph, integ):
    val = {'NASSecAlgo': bytes([ciph << 4 | integ]), 'NAS_KSI': rng.randrange(8),
           'UESecCap': rng.choice([b'\xf0\xf0', b'\xe0\xe0\xf0\xf0', b'\xf0', 8 * b'\xff'])}
    for name, value in [('EPSNASSecAlgo', b'\x11'), ('S1UESecCap', b'\xf0\xf0'), ('EAPMsg', b'\x03\x01\x00\x04'),
                        ('ABBA', b'\x00\x00'), ('IMEISVReq', 1), ('Add5GSecInfo', b'\x01')]:
        if rng.random() < 0.3:
            val[name] = value
    plain = FGMMSecurityModeCommand(val=val).to_bytes()
    k = rng.randrange(6)
    if k == 0:
        plain += rng.choice([b'\xe1', b'\x7f\x00\x01\x00', b'\x99'])   # repeated, unknown
    elif k == 1:
        plain = truncated(rng, plain)
    shdr = rng.choice([0, 1, 3, 3, 4])
    return plain if shdr == 0 else outer(plain, shdr, rng.randrange(256))


def odd_registration_accept(rng):
    k = rng.randrange(6)
    if k == 0:
        return OAI_RA
    buf = registration_accept(rng)
    if k == 1:
        buf += b'\x34\x01\x00'                    # a second IEI 0x34: pycrate takes it for 5GSAddReqResult
    elif k == 2:
        buf += b'\x34\x01\x00\x34\x01\x00'
    elif k == 3:
        buf = truncated(rng, buf)
    elif k == 4:
        buf += b'\x9a\xb1'                        # Type 1 IEs: NetSlicingInd, MICOInd
    return buf


def odd_pdu_session_accept(rng):
    k = rng.randrange(9)
    if k == 0:
        return OAI_PDU_ACCEPT
    val = {'5GSMHeader': {'EPD': 46, 'PDUSessID': 1, 'PTI': 1, 'Type': 194}, 'SSCMode': 1, 'PDUSessType': 1,
           'QoSRules': b'\x01\x00\x06\x31\x31\x01\x01\xff\x09', 'SessAMBR': b'\x06\x00\x64\x06\x00\x64',
           # IPv4, IPv6, IPv4v6, with the SMF's link local address; of other lengths or types
           'PDUAddress': rng.choice([b'\x01' + rng.randbytes(4), b'\x02' + rng.randbytes(8),
                                     b'\x03' + rng.randbytes(12), b'\x05' + rng.randbytes(20),
                                     b'\x01' + rng.randbytes(3), b'\x01' + rng.randbytes(6),
                                     b'\x07' + rng.randbytes(4)])}
    for name, value in [('SNSSAI', b'\x01'), ('DNN', b'\x08internet'), ('AlwaysOnPDUSess', 1), ('RQTimer', b'\x21'),
                        ('ExtProtConfig', b'\x80\x00\x0d\x04\x08\x08\x08\x08'), ('5GSMCause', b'\x1a')]:
        if rng.random() < 0.4:
            val[name] = value
    if k == 1:
        del val['PDUAddress']
    sm = FGSMPDUSessionEstabAccept(val=val).to_bytes()
    if k == 2:
        sm = FGSMPDUSessionReleaseCommand(val={'5GSMHeader': {'EPD': 46, 'PDUSessID': 1, 'PTI': 0, 'Type': 211},
                                               '5GSMCause': b'\x24'}).to_bytes()
    elif k == 3:
        sm = truncated(rng, sm)
    elif k == 4:
        sm += b'\x7f\x00\x01\x00'
    dl = {'PayloadContainerType': 1, 'PayloadContainer': sm, 'PDUSessID': b'\x01'}
    if k == 5:
        dl['PayloadContainerType'] = rng.choice([2, 3, 5])
    for name, value in [('AddInfo', b'\x00'), ('5GMMCause', b'\x16'), ('BackOffTimer', b'\x21')]:
        if rng.random() < 0.2:
            dl[name] = value
    return FGMMDLNASTransport(val=dl).to_bytes()


def odd_message(rng):
    """ Messages the UE does not expect or that do not decode """
    return rng.choice([lambda: registration_reject(rng), lambda: b'\x7e\x00\x99', lambda: b'\x7e\x00',
                       lambda: b'\x2e\x01\x01\xc2', lambda: b'\x00\x01\x02\x03', lambda: b'\x7e\x00\x46\x00',
                       lambda: FGMMMODeregistrationAccept().to_bytes() + b'\x7f\x00\x00',
                       lambda: truncated(rng, configuration_update_command(rng))])()


def outer(plain, shdr, seqn, ue=None):
    """ A security protected message: plain ciphered for ue when shdr is 2, a random MAC """
    sec = FGMMSecProtNASMessage(val={'5GMMHeaderSec': {'EPD': 126, 'spare': 0, 'SecHdr': shdr}, 'Seqn': seqn})
    sec['NASMessage'].set_val(plain)
    if ue is not None and shdr == 2 and ue.CiphAlgo in nasfast._FGEA:
        sec.encrypt(key=ue.k_nas_enc, dir=1, fgea=ue.CiphAlgo, seqnoff=0, bearer=1)
    sec['MAC'].set_val(bytes([seqn, 9, 8, 7]))
    return sec.to_bytes()


def well_formed_downlink(rng, ciph, integ):
    """ (plain message, whether the fast path must parse it): the messages a UE handles, as G10's tests
    and OAI make them """
    return rng.choice([
        lambda: (auth_request(rng), True),
        lambda: (FGMMSecurityModeCommand(val={'NASSecAlgo': bytes([ciph << 4 | integ]), 'NAS_KSI': rng.randrange(7),
                                              'UESecCap': b'\xf0\xf0'}).to_bytes(), True),
        lambda: (registration_accept(rng), None),        # (some with an unknown IE)
        lambda: (OAI_RA, True), lambda: (OAI_PDU_ACCEPT, True),
        lambda: (configuration_update_command(rng), True),
        lambda: (pdu_session_accept(rng), True),
        lambda: (FGMMMODeregistrationAccept().to_bytes(), True)])()


# --------------------------------------------------------------------------------------------------
# The parser against pycrate's decoding
# --------------------------------------------------------------------------------------------------

def mutated(rng, buf):
    buf = bytearray(buf)
    for _ in range(rng.randrange(1, 4)):
        k = rng.randrange(4)
        pos = rng.randrange(3, len(buf)) if len(buf) > 3 else len(buf)
        if k == 0 and pos < len(buf):
            buf[pos] = rng.randrange(256)
        elif k == 1:
            buf[pos:pos] = rng.randbytes(rng.randrange(1, 4))
        elif k == 2:
            del buf[pos:pos + rng.randrange(1, 4)]
        else:
            buf += rng.randbytes(rng.randrange(1, 6))
    return bytes(buf)


def check_parse(data, ue):
    """ None if the fast path left data to pycrate, else True: then pycrate decodes it to a message
    of the same name with the same fields for the handlers """
    fast = nasfast.downlink(data, ue)
    if fast is None:
        return None
    ref = ref_decode(data, ue)
    assert ref != 'error', data.hex()
    assert fast[1] == ref[1], data.hex()
    view = handler_view(*fast)
    assert 'raises' not in view, data.hex()
    assert view == handler_view(*ref), data.hex()
    return True


def test_the_parser_gives_what_pycrate_gives():
    rng = random.Random(21)
    parsed = 0
    for _ in range(1500):
        ciph, integ = rng.choice(ALGORITHMS)
        ue = SimpleNamespace(CiphAlgo=ciph, k_nas_enc=rng.randbytes(16))
        plain, must = well_formed_downlink(rng, ciph, integ)
        for data in (plain, outer(plain, 2, rng.randrange(256), ue)):
            got = check_parse(data, ue)
            assert got or not must, data.hex()
            parsed += bool(got)
        if plain[2] == 93:                         # a Security Mode Command in an integrity protected message
            assert check_parse(outer(plain, rng.choice([1, 3]), 0), ue)
    assert parsed > 2500


def test_odd_and_malformed_messages_parse_as_pycrate_parses_them_or_go_to_pycrate():
    rng = random.Random(22)
    parsed = left = 0
    for _ in range(3000):
        ciph, integ = rng.choice(ALGORITHMS)
        ue = SimpleNamespace(CiphAlgo=ciph, k_nas_enc=rng.randbytes(16))
        data = rng.choice([lambda: odd_auth_request(rng), lambda: odd_security_mode_command(rng, ciph, integ),
                           lambda: outer(odd_registration_accept(rng), rng.choice([0, 1, 2, 2, 3, 4]), 1, ue),
                           lambda: outer(odd_pdu_session_accept(rng), 2, 3, ue), lambda: odd_message(rng),
                           lambda: outer(odd_message(rng), 2, 4, ue)])()
        if data[:2] == b'\x7e\x00' and rng.random() < 0.3:
            data = outer(data, 2, rng.randrange(256), ue)
        if check_parse(data, ue):
            parsed += 1
        else:
            left += 1
    assert parsed > 600 and left > 600            # both paths are taken


def test_mutated_messages_parse_as_pycrate_parses_them_or_go_to_pycrate():
    rng = random.Random(23)
    parsed = 0
    for _ in range(6000):
        ciph, integ = rng.choice(ALGORITHMS)
        ue = SimpleNamespace(CiphAlgo=0, k_nas_enc=rng.randbytes(16))
        plain, _ = well_formed_downlink(rng, ciph, integ)
        data = mutated(rng, plain)
        if rng.random() < 0.3:
            data = outer(data, rng.choice([1, 2, 3]), rng.randrange(256))
        parsed += bool(check_parse(data, ue))
    assert parsed > 400                           # (and none differed)


def test_the_parser_follows_the_algorithm_and_the_count():
    """ Deciphering with the UE's algorithm and the header's sequence number, as pycrate's decrypt() """
    rng = random.Random(24)
    for ciph in (1, 2):
        ue = SimpleNamespace(CiphAlgo=ciph, k_nas_enc=rng.randbytes(16))
        data = outer(OAI_PDU_ACCEPT, 2, 77, ue)
        assert nasfast.downlink(data, ue) is not None
        assert nasfast.downlink(data[:6] + b'\x78' + data[7:], ue) is None     # another COUNT: garbage
        assert nasfast.downlink(data, SimpleNamespace(CiphAlgo=3 - ciph, k_nas_enc=ue.k_nas_enc)) is None
        assert nasfast.downlink(data, SimpleNamespace(CiphAlgo=None, k_nas_enc=ue.k_nas_enc)) is None


def test_messages_pycrate_appends_an_ie_to_go_to_pycrate():
    """ (an unknown IE, or one more time than the class has it) """
    ue = SimpleNamespace(CiphAlgo=0, k_nas_enc=bytes(16))
    assert nasfast.downlink(OAI_RA, ue) is not None
    assert nasfast.downlink(OAI_RA + b'\x7f\x00\x02\xaa\xbb', ue) is None
    assert nasfast.downlink(OAI_RA + b'\x5e\x01\x06', ue) is None                # T3512 again
    assert nasfast.downlink(OAI_RA + b'\x34\x01\x00\x34\x01\x00', ue) is not None   # 0x34: two IEs have it
    assert nasfast.downlink(OAI_RA + 3 * b'\x34\x01\x00', ue) is None


# --------------------------------------------------------------------------------------------------
# The uplink templates against the builders
# --------------------------------------------------------------------------------------------------

def odd_config(rng, i):
    """ UEs as G10's tests make them, and some the templates do not cover """
    config = ue_config(rng, i)
    k = rng.randrange(12)
    if k == 0:
        config['imeiSv'] = config['imeiSv'][:15]
    elif k == 1:
        config['imeiSv'] = config['imeiSv'][:15] + 'A'
    elif k == 2:
        config['sessions'] = [{'type': 'IPv4', 'apn': rng.choice(['a..b', 'ims.mnc095.mcc208.gprs', 'x' * 300, '.']),
                               'slice': {'sst': 1, 'sd': 1}}]
    elif k == 3:
        config['sessions'] = [{'type': 'IPv4', 'apn': 'internet', 'slice': {'sst': 300}}]
    elif k == 4:
        config['defaultNssai'] = [{'sst': 1, 'sd': 1 << 24}]
    elif k == 5:
        config['defaultNssai'] = [{'sst': 1}, {'sst': 2, 'sd': 3}, {'sst': 4, 'sd': 0xFFFFFF}]
    return config


def twins(config):
    return UE(config), UE(config)


def built(builder, ue, *args, fast=True):
    with fastpath(fast):
        try:
            msg, sent_type = builder(ue, {}, *args)
            return (msg.to_bytes() if msg is not None else None, sent_type)    # (as next_action())
        except Exception as e:
            return ('raised', type(e).__name__, str(e))


def keyed(ue, rng, ciph, integ):
    ue.CiphAlgo, ue.IntegAlgo = ciph, integ
    ue.k_nas_enc, ue.k_nas_int, ue.k_amf = rng.randbytes(16), rng.randbytes(16), rng.randbytes(32)
    ue.ul_nas_count = rng.choice([0, 1, 2, 255, 256, 257, 0x1FF, 0x10000 + rng.randrange(1 << 16),
                                  rng.randrange(1 << 24)])


def test_the_templates_give_what_the_builders_give(quiet):
    rng = random.Random(31)
    covered = 0
    for i in range(600):
        config = odd_config(rng, i)
        ciph, integ = rng.choice(ALGORITHMS + [(0, 4), (4, 1), (None, None)])
        state = rng.getstate()
        fast_ue, ref_ue = twins(config)
        for ue in (fast_ue, ref_ue):
            rng.setstate(state)
            keyed(ue, rng, ciph, integ)
        smc = nascache.parse_NAS5G(FGMMSecurityModeCommand(val={'NASSecAlgo': bytes([(ciph or 0) << 4 | (integ or 0)]),
                                                                  'UESecCap': b'\xf0\xf0'}).to_bytes())[0]
        res = rng.randbytes(rng.choice([16, 16, 8, 0]))
        for builder, args in [(src.UEMessages.registration_request, ()),
                              (src.UEMessages.registration_complete, ()),
                              (src.UEMessages.configuration_update_complete, ()),
                              (src.UEMessages.pdu_session_establishment_request, (None,)),
                              (src.UEMessages.mo_deregistration_request, ()),
                              (security_mode_complete, (smc,)),
                              (src.UEMessages.deregistration_complete, ()),
                              (src.UEMessages.connection_release_complete, ())]:
            a, b = built(builder, fast_ue, *args), built(builder, ref_ue, *args, fast=False)
            assert a == b, (builder.__name__, config)
            assert ue_state(fast_ue) == ue_state(ref_ue), (builder.__name__, config)
            covered += a[0] is not None
        ref_res = src.UEMessages.AUTHENTICATION_RESPONSE.build({'RES': res}).to_bytes()
        assert nasfast.authentication_response(res) == ref_res
    assert covered > 2000


def test_protect_gives_what_security_prot_encrypt_ciphered_gives():
    rng = random.Random(32)
    for _ in range(2000):
        ciph, integ = rng.choice(ALGORITHMS)
        a = SimpleNamespace(CiphAlgo=ciph, IntegAlgo=integ, k_nas_enc=rng.randbytes(16), k_nas_int=rng.randbytes(16),
                            ul_nas_count=rng.choice([0, 1, 255, 256, 0x1FF, rng.randrange(1 << 24)]))
        b = SimpleNamespace(**vars(a))
        plain = b'\x7e\x00' + rng.randbytes(rng.randrange(1, 300))
        sec = nasfast.protect(a, plain)
        assert type(sec.to_bytes()) is bytes
        assert sec == security_prot_encrypt_ciphered(b, SimpleNamespace(to_bytes=lambda: plain)).to_bytes()
        assert a.ul_nas_count == b.ul_nas_count


def test_protect_leaves_other_algorithms_to_pycrate():
    for ciph, integ in [(None, None), (0, 4), (4, 0), (7, 7), (0, None)]:
        ue = SimpleNamespace(CiphAlgo=ciph, IntegAlgo=integ, k_nas_enc=bytes(16), k_nas_int=bytes(16), ul_nas_count=5)
        assert nasfast.protect(ue, b'\x7e\x00\x43') is None and ue.ul_nas_count == 5
    ue = SimpleNamespace(CiphAlgo=2, IntegAlgo=2, k_nas_enc=bytes(5), k_nas_int=bytes(16), ul_nas_count=5)
    assert nasfast.protect(ue, b'\x7e\x00\x43') is None and ue.ul_nas_count == 5     # the key: CryptoMobile fails


def test_the_templates_leave_other_identities_to_pycrate():
    base = dict(ue_config(random.Random(33), 0), mcc='208', mnc='95')
    for change in [{'mnc': '5'}, {'mcc': '20', 'mnc': '9'}, {'mnc': '9a'}, {'imeiSv': '123456789012345'}]:
        ue = UE(base)
        for name, value in change.items():
            setattr(ue, name, value)
        assert (nasfast.build(nasfast.registration_request, ue) is None) == ('imeiSv' not in change)
        assert (nasfast.build(nasfast.security_mode_complete, ue) is None)
    ue = UE(base)
    ue.nssai = []
    assert nasfast.build(nasfast.security_mode_complete, ue) is None
    ue.sessions = [{'apn': 7}]
    assert nasfast.build(nasfast.ul_nas_transport_pdu_session_establishment_request, ue) is None


# --------------------------------------------------------------------------------------------------
# Many UEs through registration, PDU session and deregistration, against pycrate's path
# --------------------------------------------------------------------------------------------------

def script(rng, ciph, integ):
    """ One UE's steps: None for the UE's next procedure, or (plain message, security header type,
    sequence number) for a downlink message, ciphered for the UE when it is sent """
    odd = rng.random() < 0.4
    s = [None]
    s.append((odd_auth_request(rng) if odd and rng.random() < 0.3 else auth_request(rng), 0, 0))
    if odd and rng.random() < 0.3:
        s.append((odd_security_mode_command(rng, ciph, integ), 0, 0))
    else:
        s.append((security_mode_command(rng, ciph, integ), 0, 0))
    s.append((odd_registration_accept(rng) if odd and rng.random() < 0.3 else registration_accept(rng), 2, 1))
    if rng.random() < 0.5:
        s.append((configuration_update_command(rng), 2, 2))
    s.append(None)
    s.append((odd_pdu_session_accept(rng) if odd and rng.random() < 0.5 else pdu_session_accept(rng), 2, 3))
    s.append(None)
    s.append((FGMMMODeregistrationAccept().to_bytes(), rng.choice([2, 2, 2, 0]), 4))
    if odd:
        for _ in range(rng.randrange(1, 3)):
            s.insert(rng.randrange(1, len(s) + 1), (odd_message(rng), rng.choice([0, 2]), rng.randrange(256)))
    s.append((b'F', 0, 0))
    return s


def downlink_bytes(step, ue):
    plain, shdr, seqn = step
    return plain if shdr == 0 else outer(plain, shdr, seqn, ue)


def lacks_rand(data):
    """ An Authentication Request without RAND: G10's reused decoder (src/nascache.py) hands the
    handler the RAND of the thread's last one that had it (pycrate's fresh object, zeros), so the UE's
    keys depend on the order the thread decodes the messages in. The fast path leaves it to that path. """
    msg, err = pycrate_parse_NAS5G(data)
    return not err and msg._name == '5GMMAuthenticationRequest' and msg['RAND'].get_trans()


def many_ues(seed, n, any_order=False):
    """ UEs and their scripts; with any_order, none whose outcome depends on the order of the UEs' steps """
    rng = random.Random(seed)
    configs = {i: odd_config(rng, i) for i in range(n)}
    algorithms = ALGORITHMS + ([(3, 3)] if 3 in nasfast._FGEA and 3 in nasfast._FGIA else []) + [(0, 4)]
    scripts = {i: script(rng, *rng.choice(algorithms)) for i in range(n)}
    if any_order:
        for s in scripts.values():
            s[:] = [(auth_request(rng), 0, 0) if step is not None and lacks_rand(step[0]) else step for step in s]
    return configs, scripts


def test_ues_send_what_pycrates_path_sends(quiet):
    configs, scripts = many_ues(41, 150)
    fast_sim = make_sim({i: UE(c) for i, c in configs.items()})
    ref_sim = make_sim({i: UE(c) for i, c in configs.items()})
    rng = random.Random(42)
    pending = {i: list(s) for i, s in scripts.items()}
    fast_downlinks = steps = 0
    real_downlink = nasfast.downlink
    counted = []
    nasfast.downlink = lambda data, ue: counted.append(real_downlink(data, ue)) or counted[-1]
    try:
        while pending:
            i = rng.choice(sorted(pending))
            step = pending[i].pop(0)
            if not pending[i]:
                del pending[i]
            data = None if step is None else downlink_bytes(step, ref_sim.ue_list[i])
            with fastpath(True):
                a = outcome(fast_sim, data, i)
            with fastpath(False):
                b = outcome(ref_sim, data, i)
            assert a == b, (i, step, configs[i])
            assert ue_state(fast_sim.ue_list[i]) == ue_state(ref_sim.ue_list[i]), (i, step)
            steps += 1
    finally:
        nasfast.downlink = real_downlink
    assert sim_state(fast_sim) == sim_state(ref_sim)
    fast_downlinks = sum(c is not None for c in counted)
    assert steps > 150 * 10 and fast_downlinks > 150 * 4


def test_ues_on_several_threads_send_what_pycrates_path_sends(quiet):
    """ The UE simulator decodes and builds in its init() thread and in two workers at once """
    configs, scripts = many_ues(43, 120, any_order=True)
    expected = {}
    with fastpath(False):
        ref_sim = make_sim({i: UE(c) for i, c in configs.items()})
        for i, s in scripts.items():
            expected[i] = [outcome(ref_sim, None if step is None else downlink_bytes(step, ref_sim.ue_list[i]), i)
                           for step in s]
    sim = make_sim({i: UE(c) for i, c in configs.items()})
    errors = []

    def worker(ids, seed):
        rng = random.Random(seed)
        pending = {i: list(scripts[i]) for i in ids}
        got = {i: [] for i in ids}
        try:
            while pending:
                i = rng.choice(sorted(pending))
                step = pending[i].pop(0)
                if not pending[i]:
                    del pending[i]
                got[i].append(outcome(sim, None if step is None else downlink_bytes(step, sim.ue_list[i]), i))
            for i in ids:
                assert got[i] == expected[i], i
                assert ue_state(sim.ue_list[i]) == ue_state(ref_sim.ue_list[i]), i
        except Exception as e:                    # pragma: no cover - reported below
            errors.append(e)
    threads = [threading.Thread(target=worker, args=(list(range(k, 120, 3)), 50 + k)) for k in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors


# --------------------------------------------------------------------------------------------------
# When the pycrate path stays
# --------------------------------------------------------------------------------------------------

def test_pycrates_path_when_messages_are_logged_validated_or_in_compliance_tests(quiet, monkeypatch):
    assert src.UESim._nas_fastpath()
    logger = logging.getLogger('__UESim__')
    level = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        assert not nasfast.enabled() and not src.UESim._nas_fastpath()
    finally:
        logger.setLevel(level)
    monkeypatch.setattr(src.UE, 'g_verbose', 3)
    assert not src.UESim._nas_fastpath()
    monkeypatch.setattr(src.UE, 'g_verbose', 0)
    monkeypatch.setattr(src.UESim, 'g_verbose', 4)
    assert not src.UESim._nas_fastpath()
    monkeypatch.setattr(src.UESim, 'g_verbose', 1)
    monkeypatch.setattr(nasfast, 'ENABLED', False)
    assert not src.UESim._nas_fastpath()
    ue = UE(ue_config(random.Random(51), 0))
    msg, _ = src.UEMessages.registration_request(ue, {})
    assert type(msg) is not nasfast.NASBytes                 # a pycrate message
