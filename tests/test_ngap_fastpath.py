""" The gNB's NGAP fast path (src/ngapfast.py): the bytes pycrate encodes, and what pycrate's decoding
gives the gNB, without pycrate; pycrate's path, with the same result, for anything else.

- Uplink: the templates of the InitialUEMessage, UplinkNASTransport, InitialContextSetupResponse and
  UEContextReleaseComplete give the bytes of src/NGAPSim.py's pycrate builders for ids across their
  ranges (the boundaries 0, 255, 256, 65535, 65536, 2^32-1, 2^40-1 among them), NAS PDUs of 0 to
  140000 octets (around the length determinant's forms: 127/128, 16383/16384), every establishment
  cause, with and without a 5G-S-TMSI, for gNBs of other PLMNs, TACs and ids; CN-TG's own uplink
  messages in the testbed captures are rebuilt byte for byte.
- Downlink: OAI's DownlinkNASTransports and InitialContextSetupRequests from the testbed captures
  (tests/data/oai_ngap_captures.json), and synthesized messages (long NAS PDUs, large ids, other
  IEs, UEContextReleaseCommands), give the gNB what pycrate's path gives it: the procedure, the UE
  NGAP IDs, the NAS PDU, the answer's bytes.
- Fallback: messages outside the parser (other procedures, extension bits, IEs out of order, of
  another criticality or unknown, non-canonical or fragmented lengths, ...) and malformed or mutated
  ones take pycrate's path: the gNB gets the same result, or the same exception.
- The switch: GNB(ngap_fastpath=False), run.py --no-ngap-fastpath, and debug logging use pycrate only.

Run from the repository root (needs pycrate, as src/NGAPSim.py does):

    python3 -m pytest tests/test_ngap_fastpath.py
"""
import json
import logging
import os
import random
import struct
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest
from pycrate_asn1dir import NGAP

import src.NGAPSim as ngapsim
from src import ngapfast, ranlink
from src.NGAPSim import (GNB, initial_context_setup_uplink, initial_ue_message, nr_cell_identity, plmn_str_to_buf,
                         ue_connection_release_complete, uplink_nas_transport)
from src.ngapfast import IGNORE, REJECT, wrap
from src.ngapfast import _ie as field
from src.ranlink import CONNECT, UL_NAS, Event

sys.path.insert(0, os.path.dirname(__file__))
import amf_stub  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(os.path.dirname(__file__), 'data', 'oai_ngap_captures.json')) as _f:
    CAPTURES = json.load(_f)
DOWNLINK = [bytes.fromhex(m['ngap']) for m in CAPTURES['messages'] if m['dir'] == 'dl']
UPLINK = [bytes.fromhex(m['ngap']) for m in CAPTURES['messages'] if m['dir'] == 'ul']

PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
AMF_IDS = [0, 1, 127, 128, 255, 256, 65535, 65536, 2**24 - 1, 2**24, 2**32 - 1, 2**32, 2**40 - 1]
RAN_IDS = [0, 1, 127, 128, 255, 256, 65535, 65536, 2**24 - 1, 2**24, 2**32 - 1]
NAS_LENGTHS = [0, 1, 2, 125, 126, 127, 128, 129, 255, 256, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 32767,
               32768, 49152, 65535, 65536, 65537, 81920, 140000]
GNBS = [(0, '20895', 0xa000), (1, '20895', 0), (7, '001010', 0xffffff), (254, '310410', 0x000001),
        (255, '99999', 0x123456), (2**32 - 2, '20893', 0xa000)]
REGISTRATION_REQUEST = bytes.fromhex('7e004179000d0102f8590000000000000000132e04f0f0f0f0')
AUTHENTICATION_REQUEST = bytes.fromhex('7e005602020000211d4a7bf589181846daa6bd809065798f2010'
                                       '44259dab34a98000be9d2e8b0ff26d04')
REGISTRATION_ACCEPT = bytes.fromhex('7e0250c655a2017e0042010177000bf202f8590100418ec18e3e54070002f85900a00015'
                                    '0504de00007b310504de00007b210201005e01b616010c')


def gnb_identity(index=0, plmn='20895', tac=0xa000):
    return SimpleNamespace(gnb_id=1 + index, plmn_identity=plmn_str_to_buf(plmn), tac=tac.to_bytes(3, 'big'))


def templates(g):
    return ngapfast.Uplink(g.plmn_identity, nr_cell_identity(g), g.tac)


def pycrate_uplink(build, nas, ue, g):
    """ src/NGAPSim.py's pycrate path for an Initial UE Message or Uplink NAS Transport """
    build(PDU, [{'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', nas)}], ue, g)
    return PDU.to_aper()


def pycrate_answer(build, amf_id, ran_id):
    build(PDU, [], {'amf_ue_ngap_id': amf_id, 'ran_ue_ngap_id': ran_id})
    return PDU.to_aper()


@pytest.fixture
def clock(monkeypatch):
    """ time.time() as the test sets it: src/NGAPSim.py and src/ngapfast.py both read it """
    now = [1761400000.25]
    monkeypatch.setattr(ngapsim.time, 'time', lambda: now[0])
    return now


@pytest.fixture
def fresh(monkeypatch):
    """ The parser has learnt no IE yet """
    monkeypatch.setattr(ngapfast, '_learnt', set())


# --------------------------------------------------------------------------------------------------
# Uplink: the templates give pycrate's bytes
# --------------------------------------------------------------------------------------------------

def test_the_length_determinant_is_pycrates():
    for n in NAS_LENGTHS + [16384 * k for k in range(1, 9)] + [16384 * k + 1 for k in range(1, 9)]:
        value = bytes(random.Random(n).randrange(256) for _ in range(n))
        PDU.set_val(('initiatingMessage', {'procedureCode': 4, 'criticality': 'ignore', 'value': (
            'DownlinkNASTransport', {'protocolIEs': [
                {'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', value)}]})}))
        # the NAS-PDU's length determinant, then the open type of the IE, then the message's
        assert PDU.to_aper() == b'\x00\x04\x40' + wrap(b'\x00\x00\x01' + b'\x00\x26\x00' + wrap(wrap(value))), n


def one_id(ie_id, name, v):
    """ pycrate's encoding of an InitialContextSetupResponse with one UE NGAP ID """
    return encode(('successfulOutcome', {'procedureCode': 14, 'criticality': 'reject', 'value': (
        'InitialContextSetupResponse', {'protocolIEs': [
            {'id': ie_id, 'criticality': 'ignore', 'value': (name, v)}]})}))


def test_ids_are_encoded_as_pycrate_encodes_them():
    rng = random.Random(1)
    def message_of(ie_id, value):
        return b'\x20\x0e\x00' + wrap(b'\x00\x00\x01' + field(ie_id, IGNORE, value))
    for v in AMF_IDS + [rng.randrange(2**40) for _ in range(200)] + [rng.randrange(2**k) for k in range(1, 41)]:
        assert one_id(10, 'AMF-UE-NGAP-ID', v) == message_of(10, ngapfast.amf_ue_ngap_id(v)), v
    for v in RAN_IDS + [rng.randrange(2**32) for _ in range(200)] + [rng.randrange(2**k) for k in range(1, 33)]:
        assert one_id(85, 'RAN-UE-NGAP-ID', v) == message_of(85, ngapfast.ran_ue_ngap_id(v)), v
    assert [ngapfast.amf_ue_ngap_id(v) for v in (-1, 2**40, None, 1.0, '1', True)] == [None] * 6
    assert [ngapfast.ran_ue_ngap_id(v) for v in (-1, 2**32, None, 1.0, '1', True)] == [None] * 6


def nas_of(n, rng):
    return bytes(rng.randrange(256) for _ in range(n))


def test_uplink_nas_transport_is_pycrates(clock):
    rng = random.Random(2)
    cases = [(a, r, rng.choice(NAS_LENGTHS[:12])) for a in AMF_IDS for r in RAN_IDS]
    cases += [(rng.choice(AMF_IDS), rng.choice(RAN_IDS), n) for n in NAS_LENGTHS]
    cases += [(rng.randrange(2**40), rng.randrange(2**32), rng.randrange(1, 3000)) for _ in range(100)]
    for i, (amf_id, ran_id, n) in enumerate(cases):
        g = gnb_identity(*GNBS[i % len(GNBS)])
        clock[0] = rng.choice([0.0, 1761400000.75, 2085978495.9, rng.uniform(0, 2085978495)])
        nas = nas_of(n, rng)
        want = pycrate_uplink(uplink_nas_transport, nas, {'amf_ue_ngap_id': amf_id, 'ran_ue_ngap_id': ran_id}, g)
        assert templates(g).uplink_nas_transport(amf_id, ran_id, nas) == want, (amf_id, ran_id, n, g)


def test_initial_ue_message_is_pycrates(clock):
    rng = random.Random(3)
    s_tmsis = [None, b'', bytes(6), b'\xff' * 6, bytes.fromhex('0141deadbeef'), bytes.fromhex('ffc000000001'),
               bytes.fromhex('003f12345678'), bytearray.fromhex('8001cafe0001')]
    cases = [(r, rng.choice(NAS_LENGTHS[:12]), c, s) for r in RAN_IDS for c in range(10) for s in s_tmsis[:3]]
    cases += [(rng.choice(RAN_IDS), n, rng.randrange(10), rng.choice(s_tmsis)) for n in NAS_LENGTHS]
    cases += [(rng.randrange(2**32), rng.randrange(1, 3000), rng.randrange(10), s) for s in s_tmsis for _ in range(10)]
    cases += [(rng.randrange(2**32), 30, rng.randrange(10), nas_of(6, rng)) for _ in range(50)]
    for i, (ran_id, n, cause, s_tmsi) in enumerate(cases):
        g = gnb_identity(*GNBS[i % len(GNBS)])
        clock[0] = rng.choice([0.0, 1761400000.75, 2085978495.9, rng.uniform(0, 2085978495)])
        nas = nas_of(n, rng)
        want = pycrate_uplink(initial_ue_message, nas, {'ran_ue_ngap_id': ran_id, 'cause': cause, 's_tmsi': s_tmsi}, g)
        assert templates(g).initial_ue_message(ran_id, nas, cause, s_tmsi) == want, (ran_id, n, cause, s_tmsi, g)
    # without a cause, mo-Signalling, as NGAPSim's default
    g = gnb_identity()
    assert templates(g).initial_ue_message(31, REGISTRATION_REQUEST) == pycrate_uplink(
        initial_ue_message, REGISTRATION_REQUEST, {'ran_ue_ngap_id': 31}, g)


def test_the_answers_are_pycrates():
    rng = random.Random(4)
    cases = [(a, r) for a in AMF_IDS for r in RAN_IDS]
    cases += [(rng.randrange(2**40), rng.randrange(2**32)) for _ in range(300)]
    for amf_id, ran_id in cases:
        assert ngapfast.initial_context_setup_response(amf_id, ran_id) == pycrate_answer(
            initial_context_setup_uplink, amf_id, ran_id)
        assert ngapfast.ue_context_release_complete(amf_id, ran_id) == pycrate_answer(
            ue_connection_release_complete, amf_id, ran_id)


def test_the_templates_leave_to_pycrate_what_they_do_not_cover(clock):
    g = gnb_identity()
    t = templates(g)
    for amf_id, ran_id in [(None, 31), (2**40, 31), (-1, 31), (1031, None), (1031, 2**32), ('1031', 31)]:
        assert t.uplink_nas_transport(amf_id, ran_id, b'\x7e') is None
        assert ngapfast.initial_context_setup_response(amf_id, ran_id) is None
        assert ngapfast.ue_context_release_complete(amf_id, ran_id) is None
        with pytest.raises(Exception):        # pycrate's path then fails as before
            pycrate_uplink(uplink_nas_transport, b'\x7e', {'amf_ue_ngap_id': amf_id, 'ran_ue_ngap_id': ran_id}, g)
    for cause in (10, 255, None, '3'):
        assert t.initial_ue_message(31, b'\x7e', cause) is None
        with pytest.raises(Exception):
            pycrate_uplink(initial_ue_message, b'\x7e', {'ran_ue_ngap_id': 31, 'cause': cause}, g)
    for s_tmsi in (b'\x01' * 5, b'\x01' * 7):
        assert t.initial_ue_message(31, b'\x7e', 3, s_tmsi) is None
    assert t.uplink_nas_transport(1031, 31, bytearray(b'\x7e')) is None
    assert t.uplink_nas_transport(1031, 31, None) is None
    clock[0] = 2085978496.0              # 2036: the 1900-based time stamp overflows 32 bits
    assert t.uplink_nas_transport(1031, 31, b'\x7e') is None
    with pytest.raises(Exception):
        pycrate_uplink(uplink_nas_transport, b'\x7e', {'amf_ue_ngap_id': 1031, 'ran_ue_ngap_id': 31}, g)
    for bad in [dict(plmn_identity=b'\x02\xf8'), dict(tac=b'\x00\xa0'), dict(gnb_id=2**32)]:
        g = gnb_identity()
        vars(g).update(bad)
        with pytest.raises(ValueError):
            templates(g)


def test_cntgs_uplink_messages_in_the_captures_are_rebuilt_byte_for_byte():
    """ The InitialUEMessages, UplinkNASTransports and InitialContextSetupResponses that CN-TG's
    pycrate path sent to OAI's AMF, from their values """
    seen = set()
    for data in UPLINK:
        PDU.from_aper(data)
        kind, val = PDU.get_val()
        code = val['procedureCode']
        ies = {ie['id']: ie['value'][1] for ie in val['value'][1]['protocolIEs']}
        if code == 21:
            continue                         # the NGSetupRequest stays with pycrate
        seen.add(code)
        if code == 14:
            assert ngapfast.initial_context_setup_response(ies[10], ies[85]) == data
            continue
        uli = ies[121][1]
        assert uli['nR-CGI']['pLMNIdentity'] == uli['tAI']['pLMNIdentity']
        t = ngapfast.Uplink(uli['tAI']['pLMNIdentity'], uli['nR-CGI']['nRCellIdentity'][0], uli['tAI']['tAC'])
        now = struct.unpack('!I', uli['timeStamp'])[0] - 2208988800
        if code == 15:
            s_tmsi = None
            if 26 in ies:
                s = ies[26]
                s_tmsi = ((s['aMFSetID'][0] << 6 | s['aMFPointer'][0]).to_bytes(2, 'big') + s['fiveG-TMSI'])
            cause = ngapsim.RRC_ESTABLISHMENT_CAUSES.index(ies[90])
            assert t.initial_ue_message(ies[85], ies[38], cause, s_tmsi, now=now) == data
        else:
            assert code == 46
            assert t.uplink_nas_transport(ies[10], ies[85], ies[38], now=now) == data
    assert seen == {14, 15, 46}


# --------------------------------------------------------------------------------------------------
# Downlink: the parser gives what pycrate's path gives
# --------------------------------------------------------------------------------------------------

class FakeSCTP:
    def __init__(self):
        self.sent = []

    def send(self, data):
        self.sent.append(data)


def make_gnb(fast=True, link=None):
    gnb = GNB.__new__(GNB)                 # only what the uplink and downlink paths use
    gnb.ngap_fastpath = fast
    gnb.links = [link] if link is not None else []
    gnb.ue_links, gnb.clashes = {}, set()
    gnb.ues, gnb.ul_sent, gnb.ul_sent_lock = {}, {}, threading.Lock()
    gnb.gnb_id, gnb.plmn_identity, gnb.tac = 1, plmn_str_to_buf('20895'), (0xa000).to_bytes(3, 'big')
    gnb.sctp = FakeSCTP()
    return gnb


def outcome(f, *args):
    """ f(*args), or the exception it raises """
    try:
        return 'ok', f(*args)
    except Exception as e:
        return 'raised', type(e).__name__, str(e)


def pycrate_view(data):
    """ What the gNB reads from a downlink message with pycrate (procedure code, AMF and RAN UE NGAP
    IDs, NAS-PDU or None), as src/NGAPSim.py's handlers read it """
    PDU.from_aper(data)
    code = PDU.get_val()[1]['procedureCode']
    ies = {}
    for ie in PDU.get_val()[1]['value'][1]['protocolIEs']:
        ies.setdefault(ie['id'], ie['value'][1])
    if code == ngapfast.UE_CONTEXT_RELEASE:
        pair = ies[114][1]
        return code, pair['aMF-UE-NGAP-ID'], pair['rAN-UE-NGAP-ID'], None
    return code, ies.get(10), ies.get(85), ies.get(38)


def test_oais_downlink_messages_decode_as_with_pycrate(fresh):
    fast, slow = make_gnb(True), make_gnb(False)
    parsed = {}
    for data in DOWNLINK:
        got = ngapfast.downlink(data)
        want = slow._downlink(data)
        assert fast._downlink(data) == want
        if got is not None:
            assert got == pycrate_view(data)
        parsed.setdefault(data[1], []).append(got is not None)
    # Every DownlinkNASTransport parsed; the InitialContextSetupRequests once pycrate had decoded the
    # first of each capture's AMF (its GUAMI, allowed NSSAI, UE security capabilities and mobility
    # restrictions; the security key and masked IMEISV vary per UE and are checked by size)
    assert all(parsed[ngapfast.DOWNLINK_NAS_TRANSPORT]) and len(parsed[ngapfast.DOWNLINK_NAS_TRANSPORT]) == 224
    ics = parsed[ngapfast.INITIAL_CONTEXT_SETUP]
    assert len(ics) == 112 and sum(ics) >= 108 and ics[0] is False
    assert parsed[21] == [False] * 4          # NGSetupResponse: pycrate's, and nothing to do
    for data in DOWNLINK:
        if data[1] in (4, 14):
            assert ngapfast.downlink(data) == pycrate_view(data)


def test_learnt_ies_and_their_limit(fresh, monkeypatch):
    ics = [d for d in DOWNLINK if d[1] == 14]
    assert ngapfast.downlink(ics[0]) is None
    make_gnb(True)._downlink(ics[0])                 # pycrate's path, which then teaches the parser
    assert ngapfast.downlink(ics[0]) == pycrate_view(ics[0])
    assert {ie for _, ie, _ in ngapfast._learnt} == {28, 0, 119, 36}
    monkeypatch.setattr(ngapfast, '_learnt', set())
    monkeypatch.setattr(ngapfast, 'MAX_LEARNT', 2)
    ngapfast.learn(ics[0])
    assert len(ngapfast._learnt) == 2 and ngapfast.downlink(ics[0]) is None
    make_gnb(False)._downlink(ics[1])                # no learning without the fast path
    assert len(ngapfast._learnt) == 2


def test_an_ie_pycrate_decodes_only_in_part_is_not_learnt(fresh):
    """ Within a message, pycrate decodes an IE's value and goes on where that value ended, not where
    its open type ends: an IndexToRFSP with an octet more than its value passes as the last IE, and
    must not be learnt, or the parser would take a message pycrate cannot decode """
    fast, slow = make_gnb(True), make_gnb(False)
    rfsp = field(31, IGNORE, b'\x00\x06\x00')            # 7, and an octet
    last = message(DL_HEAD, ue_ids(7, 8) + [nas_ie(AUTHENTICATION_REQUEST), rfsp])
    want = (4, None, AUTHENTICATION_REQUEST, {'ran_ue_ngap_id': 8, 'amf_ue_ngap_id': 7})
    assert slow._downlink(last) == fast._downlink(last) == want
    assert ngapfast._learnt == set()
    inner = message(DL_HEAD, ue_ids(7, 8) + [nas_ie(AUTHENTICATION_REQUEST), rfsp, field(34, IGNORE, bytes(8))])
    assert outcome(fast._downlink, inner) == outcome(slow._downlink, inner)
    assert outcome(slow._downlink, inner)[0] == 'raised'
    # the canonical form is learnt
    good = message(DL_HEAD, ue_ids(7, 8) + [nas_ie(AUTHENTICATION_REQUEST), field(31, IGNORE, b'\x00\x06')])
    fast._downlink(good)
    assert ngapfast._learnt == {(4, 31, b'\x00\x06')} and ngapfast.downlink(good) == (4, 7, 8, AUTHENTICATION_REQUEST)


def ue_ids(amf_id, ran_id, crit=REJECT):
    return [field(10, crit, ngapfast.amf_ue_ngap_id(amf_id)), field(85, crit, ngapfast.ran_ue_ngap_id(ran_id))]


def nas_ie(nas, crit=REJECT):
    return field(38, crit, wrap(nas))


def message(head, ies, ext=b'\x00', count=None):
    return head + wrap(ext + (len(ies) if count is None else count).to_bytes(2, 'big') + b''.join(ies))


DL_HEAD, ICS_HEAD, REL_HEAD = b'\x00\x04\x40', b'\x00\x0e\x00', b'\x00\x29\x00'
CAUSE_DEREGISTER = field(15, IGNORE, b'\x48')
CAUSE_UNSPECIFIED = {'id': 15, 'criticality': 'ignore', 'value': ('Cause', ('misc', 'unspecified'))}


def release(ue_ngap_ids):
    """ A UEContextReleaseCommand with this UE-NGAP-IDs value """
    return message(REL_HEAD, [field(114, REJECT, ue_ngap_ids), CAUSE_DEREGISTER])


def release_command(amf_id, ran_id, cause=CAUSE_DEREGISTER):
    pair = bytes(((len(ngapfast.amf_ue_ngap_id(amf_id)) - 2) << 1,)) + ngapfast.amf_ue_ngap_id(amf_id)[1:]
    return message(REL_HEAD, [field(114, REJECT, pair + ngapfast.ran_ue_ngap_id(ran_id)), cause])


def encode(val):
    PDU.set_val(val)
    return PDU.to_aper()


def in_set_order(code, ies):
    """ The IEs in their IE set's order, as OAI's AMF sends them """
    return sorted(ies, key=lambda ie: ngapfast._DOWNLINK[code].ies[ie['id']][0])


def initial_context_setup_request(amf_id, ran_id, nas=None, key=bytes(32), extra=(), first=None):
    """ As OAI's AMF sends it, with other IEs, all in the set's order but for first (put after the
    UE NGAP IDs) """
    ies = [{'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', amf_id)},
           {'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', ran_id)},
           {'id': 28, 'criticality': 'reject', 'value': ('GUAMI', {
               'pLMNIdentity': b'\x02\xf8\x59', 'aMFRegionID': (1, 8), 'aMFSetID': (1, 10), 'aMFPointer': (1, 6)})},
           {'id': 0, 'criticality': 'reject', 'value': ('AllowedNSSAI', [
               {'s-NSSAI': {'sST': b'\xde', 'sD': b'\x00\x00\x7b'}}])},
           {'id': 119, 'criticality': 'reject', 'value': ('UESecurityCapabilities', {
               'nRencryptionAlgorithms': (0xe000, 16), 'nRintegrityProtectionAlgorithms': (0xe000, 16),
               'eUTRAencryptionAlgorithms': (0, 16), 'eUTRAintegrityProtectionAlgorithms': (0, 16)})},
           {'id': 94, 'criticality': 'reject', 'value': ('SecurityKey', (int.from_bytes(key, 'big'), 256))},
           {'id': 36, 'criticality': 'ignore', 'value': ('MobilityRestrictionList', {'servingPLMN': b'\x02\xf8\x59'})},
           {'id': 34, 'criticality': 'ignore', 'value': ('MaskedIMEISV', (0x0053062940ffff41, 64))}]
    if nas is not None:
        ies.append({'id': 38, 'criticality': 'ignore', 'value': ('NAS-PDU', nas)})
    ies = in_set_order(14, ies + list(extra))
    if first is not None:
        ies.insert(2, first)
    return encode(('initiatingMessage', {'procedureCode': 14, 'criticality': 'reject', 'value': (
        'InitialContextSetupRequest', {'protocolIEs': ies})}))


def synthesized():
    """ Downlink messages encoded with pycrate: (message, whether the parser takes it once it has
    learnt its other IEs) """
    rng = random.Random(5)
    out = []
    for n in [0, 1, 2, 125, 126, 127, 128, 129, 255, 256, 1000, 4000, 16359, 16360, 16361, 16362, 16381, 16382, 16383,
              16384, 20000, 70000]:
        nas = nas_of(n, rng)
        dl = amf_stub.downlink_nas_transport(1031, 31, nas)
        assert dl == message(DL_HEAD, ue_ids(1031, 31) + [nas_ie(nas)])
        # the message's length (and so its IEs') below 16384 octets: not fragmented
        out.append((dl, dl[3] & 0xC0 != 0xC0))
        ics = amf_stub.initial_context_setup_request(1031, 31, nas)
        out.append((ics, ics[3] & 0xC0 != 0xC0))
    # with these ids, a message of 23 octets and the NAS PDU: up to 16360 octets of NAS PDU
    assert [t for d, t in out] == [True] * 28 + [False] * 16
    ids = [(a, r) for a in AMF_IDS for r in RAN_IDS[::2]]
    ids += [(rng.randrange(2**40), rng.randrange(2**32)) for _ in range(30)]
    for amf_id, ran_id in ids:
        out.append((amf_stub.downlink_nas_transport(amf_id, ran_id, AUTHENTICATION_REQUEST), True))
        out.append((amf_stub.initial_context_setup_request(amf_id, ran_id, REGISTRATION_ACCEPT), True))
        out.append((amf_stub.ue_context_release_command(amf_id, ran_id), True))
        out.append((initial_context_setup_request(amf_id, ran_id, REGISTRATION_ACCEPT, key=nas_of(32, rng)), True))
    out.append((initial_context_setup_request(5, 6), True))                       # no NAS-PDU
    out.append((initial_context_setup_request(5, 6, b''), True))                  # an empty one
    out.append((amf_stub.downlink_nas_transport(5, 6, b''), True))
    # Other IEs of the messages, in their sets' order
    trace = {'id': 108, 'criticality': 'ignore', 'value': ('TraceActivation', {
        'nGRANTraceID': bytes(8), 'interfacesToTrace': (0x80, 8), 'traceDepth': 'minimum',
        'traceCollectionEntityIPAddress': (0x7f000001, 32)})}
    out.append((initial_context_setup_request(5, 6, REGISTRATION_ACCEPT, extra=[
        {'id': 48, 'criticality': 'reject', 'value': ('AMFName', 'OAI-AMF')},
        {'id': 110, 'criticality': 'reject', 'value': ('UEAggregateMaximumBitRate', {
            'uEAggregateMaximumBitRateDL': 10**9, 'uEAggregateMaximumBitRateUL': 10**9})},
        {'id': 31, 'criticality': 'ignore', 'value': ('IndexToRFSP', 7)}, trace]), True))
    out.append((initial_context_setup_request(5, 6, REGISTRATION_ACCEPT, first=trace), False))   # out of order
    out.append((encode(('initiatingMessage', {'procedureCode': 4, 'criticality': 'ignore', 'value': (
        'DownlinkNASTransport', {'protocolIEs': in_set_order(4, ue_ids_values(7, 8) + [
            {'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', AUTHENTICATION_REQUEST)},
            {'id': 83, 'criticality': 'ignore', 'value': ('RANPagingPriority', 5)},
            {'id': 31, 'criticality': 'ignore', 'value': ('IndexToRFSP', 7)},
            {'id': 34, 'criticality': 'ignore', 'value': ('MaskedIMEISV', (0x0053062940ffff41, 64))},
            {'id': 0, 'criticality': 'reject', 'value': ('AllowedNSSAI', [{'s-NSSAI': {'sST': b'\x01'}}])},
        ])})})), True))
    for cause in [('nas', 'deregister'), ('nas', 'normal-release'), ('radioNetwork', 'user-inactivity'),
                  ('misc', 'unspecified'), ('protocol', 'semantic-error')]:
        out.append((encode(('initiatingMessage', {'procedureCode': 41, 'criticality': 'reject', 'value': (
            'UEContextReleaseCommand', {'protocolIEs': [
                {'id': 114, 'criticality': 'reject', 'value': ('UE-NGAP-IDs', ('uE-NGAP-ID-pair', {
                    'aMF-UE-NGAP-ID': 2**40 - 1, 'rAN-UE-NGAP-ID': 2**32 - 1}))},
                {'id': 15, 'criticality': 'ignore', 'value': ('Cause', cause)}]})})), True))
    return out


def test_synthesized_downlink_messages_decode_as_with_pycrate(fresh):
    fast, slow = make_gnb(True), make_gnb(False)
    for data, takes in synthesized():
        # the first of a kind on pycrate's path, which teaches the parser the IEs it does not read
        assert outcome(fast._downlink, data) == outcome(slow._downlink, data)
        got = ngapfast.downlink(data)
        assert (got is not None) == takes, data.hex()[:120]
        if got is not None:
            assert got == pycrate_view(data)
            assert fast._downlink(data) == slow._downlink(data)


def test_the_release_command_gives_the_release_complete():
    fast, slow = make_gnb(True), make_gnb(False)
    data = release_command(2**40 - 1, 2**32 - 1)
    assert data == amf_stub.ue_context_release_command(2**40 - 1, 2**32 - 1)
    ngapfast.learn(data)
    code, answer, nas, ue = fast._downlink_fast(data)
    assert (code, nas, ue) == (41, None, {'ran_ue_ngap_id': 2**32 - 1, 'amf_ue_ngap_id': 2**40 - 1})
    assert answer == slow._downlink(data)[1] == pycrate_answer(ue_connection_release_complete, 2**40 - 1, 2**32 - 1)


# --------------------------------------------------------------------------------------------------
# Fallback: anything else takes pycrate's path, with the same result
# --------------------------------------------------------------------------------------------------

def variants():
    """ (name, message) the parser must leave to pycrate """
    nas = AUTHENTICATION_REQUEST
    ids = ue_ids(1031, 31)
    out = [
        ('message extension bit', message(DL_HEAD, ids + [nas_ie(nas)], ext=b'\x80')),
        ('message padding', message(DL_HEAD, ids + [nas_ie(nas)], ext=b'\x01')),
        ('PDU extension bit', message(b'\x80\x04\x40', ids + [nas_ie(nas)])),
        ('successfulOutcome', message(b'\x20\x04\x40', ids + [nas_ie(nas)])),
        ('unsuccessfulOutcome', message(b'\x40\x0e\x00', ids + [nas_ie(nas)])),
        ('procedure criticality', message(b'\x00\x04\x00', ids + [nas_ie(nas)])),
        ('procedure criticality padding', message(b'\x00\x04\x41', ids + [nas_ie(nas)])),
        ('IE criticality', message(DL_HEAD, ue_ids(1031, 31, IGNORE) + [nas_ie(nas)])),
        ('NAS-PDU criticality', message(DL_HEAD, ids + [nas_ie(nas, IGNORE)])),
        ('IE criticality notify', message(DL_HEAD, ue_ids(1031, 31, b'\x80') + [nas_ie(nas)])),
        ('IE criticality padding', message(DL_HEAD, ue_ids(1031, 31, b'\x01') + [nas_ie(nas)])),
        ('IE order', message(DL_HEAD, ids[::-1] + [nas_ie(nas)])),
        ('NAS-PDU first', message(DL_HEAD, [nas_ie(nas)] + ids)),
        ('IE twice', message(DL_HEAD, ids + ids[1:] + [nas_ie(nas)])),
        ('NAS-PDU twice', message(DL_HEAD, ids + [nas_ie(nas), nas_ie(b'\x7e\x00\x56')])),
        ('unknown IE', message(DL_HEAD, ids + [nas_ie(nas), field(999, IGNORE, b'\x00')])),
        ("another message's IE", message(DL_HEAD, ids + [field(121, IGNORE, bytes(19)), nas_ie(nas)])),
        ('no AMF UE NGAP ID', message(DL_HEAD, ids[1:] + [nas_ie(nas)])),
        ('no RAN UE NGAP ID', message(DL_HEAD, ids[:1] + [nas_ie(nas)])),
        ('count too large', message(DL_HEAD, ids + [nas_ie(nas)], count=4)),
        ('count too small', message(DL_HEAD, ids + [nas_ie(nas)], count=2)),
        ('AMF id of more octets', message(DL_HEAD, [field(10, REJECT, b'\x20\x00\x07'), ids[1], nas_ie(nas)])),
        ('AMF id of 6 octets', message(DL_HEAD, [field(10, REJECT, b'\xa0' + bytes(5) + b'\x01'), ids[1],
                                                 nas_ie(nas)])),
        ('AMF id padding', message(DL_HEAD, [field(10, REJECT, b'\x01\x07'), ids[1], nas_ie(nas)])),
        ('AMF id value longer', message(DL_HEAD, [field(10, REJECT, b'\x00\x07\x00'), ids[1], nas_ie(nas)])),
        ('AMF id value shorter', message(DL_HEAD, [field(10, REJECT, b'\x20\x07'), ids[1], nas_ie(nas)])),
        ('RAN id of more octets', message(DL_HEAD, [ids[0], field(85, REJECT, b'\x40\x00\x1f'), nas_ie(nas)])),
        ('RAN id padding', message(DL_HEAD, [ids[0], field(85, REJECT, b'\x20\x1f'), nas_ie(nas)])),
        ('NAS-PDU long form for a short length', message(DL_HEAD, ids + [field(38, REJECT, b'\x80' + wrap(nas))])),
        ('open type long form for a short length', message(DL_HEAD, ids + [b'\x00\x26\x00\x80' + wrap(wrap(nas))])),
        ('NAS-PDU shorter than its length', message(DL_HEAD, ids + [field(38, REJECT, wrap(nas)[:-1])])),
        ('NAS-PDU longer than its length', message(DL_HEAD, ids + [field(38, REJECT, wrap(nas) + b'\x00')])),
        ('fragmented NAS-PDU', message(DL_HEAD, ids + [nas_ie(bytes(16384))])),
        ('trailing octet', message(DL_HEAD, ids + [nas_ie(nas)]) + b'\x00'),
        ('message length short', DL_HEAD + wrap(b'\x00\x00\x03' + b''.join(ids) + nas_ie(nas))[:-1]),
        ('UE-NGAP-IDs as an AMF UE NGAP ID only', release(b'\x40\x07')),
        ('UE-NGAP-IDs pair with iE-Extensions', release(b'\x10' + b'\x07\x00\x1f' + b'\x00\x00')),
        ('UE-NGAP-IDs pair extension bit', release(b'\x20\x07\x00\x1f')),
        ('UE-NGAP-IDs pair padding', release(b'\x01\x07\x00\x1f')),
        ('UE-NGAP-IDs pair longer', release(b'\x00\x07\x00\x1f\x00')),
        ('a cause not learnt', release_command(1031, 31, field(15, IGNORE, b'\x08'))),
        ('security key of 31 octets', short_key()),
        ('PDU Session Resource Setup Request', amf_stub.pdu_session_resource_setup_request(1031, 31, nas)),
        ('NGSetupResponse', next(d for d in DOWNLINK if d[1] == 21)),
        ('ErrorIndication', encode(('initiatingMessage', {'procedureCode': 9, 'criticality': 'ignore', 'value': (
            'ErrorIndication', {'protocolIEs': [CAUSE_UNSPECIFIED]})}))),
        ('InitialContextSetupFailure', encode(('unsuccessfulOutcome', {
            'procedureCode': 14, 'criticality': 'reject', 'value': (
                'InitialContextSetupFailure', {'protocolIEs': ue_ids_values(1031, 31) + [CAUSE_UNSPECIFIED]})}))),
        ('empty', b''), ('one octet', b'\x00'), ('header only', DL_HEAD),
    ]
    return out


def short_key():
    """ An InitialContextSetupRequest whose SecurityKey holds 31 octets, its other IEs as learnt """
    good = initial_context_setup_request(5, 6, REGISTRATION_ACCEPT)
    body = good[5:] if good[3] & 0x80 else good[4:]
    key = body.index(b'\x00\x5e\x00\x20') + 4
    return ICS_HEAD + wrap(body[:key - 1] + b'\x1f' + body[key:key + 31] + body[key + 32:])


def ue_ids_values(amf_id, ran_id):
    return [{'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', amf_id)},
            {'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', ran_id)}]


def test_messages_outside_the_parser_take_pycrates_path(fresh):
    fast, slow = make_gnb(True), make_gnb(False)
    reference = message(DL_HEAD, ue_ids(1031, 31) + [nas_ie(AUTHENTICATION_REQUEST)])
    assert reference == amf_stub.downlink_nas_transport(1031, 31, AUTHENTICATION_REQUEST)
    assert ngapfast.downlink(reference) == (4, 1031, 31, AUTHENTICATION_REQUEST)
    for data in (release_command(1031, 31), initial_context_setup_request(5, 6, REGISTRATION_ACCEPT)):
        ngapfast.learn(data)
        assert ngapfast.downlink(data) is not None
    for name, data in variants():
        assert ngapfast.downlink(data) is None, name
        assert outcome(fast._downlink, data) == outcome(slow._downlink, data), name
    # every prefix of a message
    for data in (reference, release_command(2**40 - 1, 2**32 - 1),
                 initial_context_setup_request(5, 6, REGISTRATION_ACCEPT)):
        for i in range(len(data)):
            assert ngapfast.downlink(data[:i]) is None
            assert outcome(fast._downlink, data[:i]) == outcome(slow._downlink, data[:i]), (data.hex(), i)


def mutants(data, rng, n):
    for _ in range(n):
        m = bytearray(data)
        for _ in range(rng.choice([1, 1, 1, 2, 3])):
            op = rng.randrange(5)
            i = rng.randrange(len(m)) if m else 0
            if op == 0 and m:
                m[i] ^= 1 << rng.randrange(8)
            elif op == 1 and m:
                m[i] = rng.randrange(256)
            elif op == 2:
                m.insert(i, rng.randrange(256))
            elif op == 3 and m:
                del m[i]
            elif m:
                m = m[:i]
        yield bytes(m)


def test_mutated_messages_give_what_pycrates_path_gives():
    """ Bit flips, changed, inserted and deleted octets, truncations of OAI's messages and of
    synthesized ones: the gNB gets what pycrate's path gives, or the same exception """
    rng = random.Random(6)
    fast, slow = make_gnb(True), make_gnb(False)
    bases = DOWNLINK[::4] + [d for d, _ in synthesized() if len(d) < 600][::3]
    taken = 0
    for base in bases:
        for data in mutants(base, rng, 25):
            got = outcome(fast._downlink, data)
            assert got == outcome(slow._downlink, data), (base.hex(), data.hex())
            taken += ngapfast.downlink(data) is not None
    # the mutants the parser took (in the NAS PDUs, ids, keys) agreed too
    assert taken > 300


# --------------------------------------------------------------------------------------------------
# The gNB: the fast path when on, pycrate's path otherwise
# --------------------------------------------------------------------------------------------------

def test_the_gnb_sends_the_templates_bytes_without_pycrate(clock, monkeypatch):
    from src.ranlink import PipeLink
    link = PipeLink()
    gnb = make_gnb(True, link.ran_end)
    gnb.ues[31] = {'amf_ue_ngap_id': 1031}
    s_tmsi = bytes.fromhex('0141deadbeef')
    connect = Event(CONNECT, 31, ranlink.connect_payload(REGISTRATION_REQUEST, ranlink.MT_ACCESS, s_tmsi), 65)
    ul_nas = Event(UL_NAS, 31, AUTHENTICATION_REQUEST, 87)
    want = [pycrate_uplink(initial_ue_message, REGISTRATION_REQUEST,
                           {'ran_ue_ngap_id': 31, 'cause': ranlink.MT_ACCESS, 's_tmsi': s_tmsi}, gnb),
            pycrate_uplink(uplink_nas_transport, AUTHENTICATION_REQUEST,
                           {'amf_ue_ngap_id': 1031, 'ran_ue_ngap_id': 31}, gnb)]
    dl = amf_stub.downlink_nas_transport(1031, 31, AUTHENTICATION_REQUEST)
    ics = amf_stub.initial_context_setup_request(1031, 31, REGISTRATION_ACCEPT)
    want_ics = pycrate_answer(initial_context_setup_uplink, 1031, 31)

    class Broken:
        def __getattr__(self, name):
            raise AssertionError('pycrate used')
    monkeypatch.setattr(NGAP.NGAP_PDU_Descriptions, 'NGAP_PDU', Broken())
    gnb._handle_uplink(link.ran_end, connect)
    gnb._handle_uplink(link.ran_end, ul_nas)
    assert gnb.sctp.sent == want
    assert gnb._downlink(dl) == (4, None, AUTHENTICATION_REQUEST, {'ran_ue_ngap_id': 31, 'amf_ue_ngap_id': 1031})
    assert gnb._downlink(ics) == (14, want_ics, REGISTRATION_ACCEPT, {'ran_ue_ngap_id': 31, 'amf_ue_ngap_id': 1031})
    # without the fast path, pycrate's
    gnb.ngap_fastpath = False
    with pytest.raises(AssertionError, match='pycrate used'):
        gnb._handle_uplink(link.ran_end, ul_nas)
    with pytest.raises(AssertionError, match='pycrate used'):
        gnb._downlink(dl)
    link.close()


def test_without_the_fast_path_or_with_debug_logging_only_pycrate(clock, monkeypatch):
    def broken(*args, **kwargs):
        raise AssertionError('fast path used')
    monkeypatch.setattr(ngapfast, 'downlink', broken)
    monkeypatch.setattr(ngapfast, 'learn', broken)
    monkeypatch.setattr(ngapfast, 'Uplink', broken)
    dl = amf_stub.downlink_nas_transport(1031, 31, AUTHENTICATION_REQUEST)
    for gnb in (make_gnb(False), make_gnb(True)):
        level = ngapsim.logger.level
        if gnb.ngap_fastpath:
            ngapsim.logger.setLevel(logging.DEBUG)
        try:
            gnb.ues[31] = {'amf_ue_ngap_id': 1031}
            gnb._handle_uplink(None, Event(UL_NAS, 31, AUTHENTICATION_REQUEST, 87))
            assert gnb._downlink(dl)[2] == AUTHENTICATION_REQUEST
            assert len(gnb.sctp.sent) == 1
        finally:
            ngapsim.logger.setLevel(level)


def test_the_gnb_takes_the_switch(monkeypatch):
    import src.NGAPSim
    monkeypatch.setattr(src.NGAPSim.logging, 'basicConfig', lambda **kw: None)
    config = {'gtpIp': '127.0.0.1', 'mcc': '208', 'mnc': '95', 'nci': '0x10', 'idLength': 32, 'tac': 0xa000,
              'slices': [{'sst': 1}]}
    assert GNB(None, None, None, config, [], 0).ngap_fastpath is True
    assert GNB(None, None, None, config, [], 0, ngap_fastpath=False).ngap_fastpath is False


def test_run_py_has_the_switch():
    out = subprocess.run([sys.executable, 'run.py', '--help'], cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-2000:]
    assert '--ngap-fastpath, --no-ngap-fastpath' in out.stdout
