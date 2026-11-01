""" The gNB's NGAP fast path (src/ngapfast.py): the bytes pycrate encodes, and what pycrate's decoding
gives the gNB, without pycrate; pycrate's path, with the same result, for anything else.

- Uplink: the templates of the InitialUEMessage, UplinkNASTransport, InitialContextSetupResponse,
  PDUSessionResourceSetupResponse and UEContextReleaseComplete give the bytes of src/NGAPSim.py's
  pycrate builders for ids across their ranges (the boundaries 0, 255, 256, 65535, 65536, 2^32-1,
  2^40-1 among them), NAS PDUs of 0 to 140000 octets (around the length determinant's forms:
  127/128, 16383/16384), every establishment cause, with and without a 5G-S-TMSI, for gNBs of other
  PLMNs, TACs and ids, every PDU session ID, TEIDs across their range, IPv4, IPv6 and dual transport
  layer addresses, and one to 64 QoS flows; CN-TG's own uplink messages in the testbed captures are
  rebuilt byte for byte.
- Downlink: OAI's DownlinkNASTransports, InitialContextSetupRequests and
  PDUSessionResourceSetupRequests from the testbed captures (tests/data/oai_ngap_captures.json), and
  synthesized messages (long NAS PDUs, large ids, other IEs, UEContextReleaseCommands, PDU sessions
  of every ID with other tunnels, QoS flows, PDU session types, S-NSSAIs and IEs), give the gNB what
  pycrate's path gives it: the procedure, the UE NGAP IDs, the NAS PDU, the PDU session, the answer's
  bytes.
- Fallback: messages outside the parser (other procedures, extension bits, IEs out of order, of
  another criticality or unknown, non-canonical or fragmented lengths, PDU session lists the parser
  does not take, ...) and malformed or mutated ones take pycrate's path: the gNB gets the same
  result, or the same exception.
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
from src.NGAPSim import (GNB, initial_context_setup_uplink, initial_ue_message, nr_cell_identity,
                         pdu_session_resource_response, plmn_str_to_buf, ue_connection_release_complete,
                         uplink_nas_transport)
from src.ngapfast import IGNORE, REJECT, PDUSession, wrap
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


TEIDS = [0, 1, 255, 256, 65535, 65536, 2**24 - 1, 2**24, 2**32 - 1]
# Transport layer addresses: IPv4, IPv6, both (TS 38.414 §5.1)
ADDRESSES = [bytes(4), bytes((127, 0, 0, 1)), bytes((192, 168, 72, 142)), b'\xff' * 4,
             bytes(16), bytes(15) + b'\x01', bytes.fromhex('20010db8000000000000000000000001'), b'\xff' * 16,
             bytes(20), bytes((10, 0, 0, 1)) + bytes.fromhex('fd000000000000000000000000000001'), b'\xff' * 20]


def tunnel_value(address, teid):
    """ pycrate's value of a GTP tunnel """
    return 'gTPTunnel', {'transportLayerAddress': (int.from_bytes(address, 'big'), 8 * len(address)), 'gTP-TEID': teid}


def pycrate_response(amf_id, ran_id, psi, address, teid, qfis):
    """ src/NGAPSim.py's pycrate builder of the PDUSessionResourceSetupResponse (one QoS flow); with
    several flows, its message with each of them in the associated QoS flow list """
    if len(qfis) == 1:
        pdu_session_resource_response(PDU, [], {'amf_ue_ngap_id': amf_id, 'ran_ue_ngap_id': ran_id,
                                                'pdu_session_id': psi, 'qos_identifier': qfis[0],
                                                'up_transport_layer_information': tunnel_value(address, teid)})
        return PDU.to_aper()
    transfer = ('PDUSessionResourceSetupResponseTransfer', {'dLQosFlowPerTNLInformation': {
        'uPTransportLayerInformation': tunnel_value(address, teid),
        'associatedQosFlowList': [{'qosFlowIdentifier': q} for q in qfis]}})
    return encode(('successfulOutcome', {'procedureCode': 29, 'criticality': 'reject', 'value': (
        'PDUSessionResourceSetupResponse', {'protocolIEs': [
            {'id': 10, 'criticality': 'ignore', 'value': ('AMF-UE-NGAP-ID', amf_id)},
            {'id': 85, 'criticality': 'ignore', 'value': ('RAN-UE-NGAP-ID', ran_id)},
            {'id': 75, 'criticality': 'ignore', 'value': ('PDUSessionResourceSetupListSURes', [
                {'pDUSessionID': psi, 'pDUSessionResourceSetupResponseTransfer': transfer}])}]})}))


def test_the_pdu_session_resource_setup_response_is_pycrates():
    rng = random.Random(7)
    lo = bytes((127, 0, 0, 1))
    cases = [(a, r, 1, lo, r.to_bytes(4, 'big'), (1,)) for a in AMF_IDS for r in RAN_IDS]
    cases += [(1031, 31, psi, lo, b'\x00\x00\x00\x1f', (1,)) for psi in range(256)]
    cases += [(1031, 31, 1, address, teid.to_bytes(4, 'big'), (q,)) for address in ADDRESSES for teid in TEIDS
              for q in (0, 1, 63)]
    # several QoS flows: the list's bit fields across octets, up to its 64 flows
    for n in (2, 3, 4, 5, 6, 7, 8, 9, 31, 32, 63, 64):
        cases += [(1031, 31, 1, rng.choice(ADDRESSES), b'\x00\x00\x00\x1f', qfis)
                  for qfis in (tuple(rng.randrange(64) for _ in range(n)), (0,) * n, (63,) * n, tuple(range(n)))]
    cases += [(rng.randrange(2**40), rng.randrange(2**32), rng.randrange(256), rng.choice(ADDRESSES), rng.randbytes(4),
               tuple(rng.randrange(64) for _ in range(rng.randrange(1, 65)))) for _ in range(200)]
    for case in cases:
        assert ngapfast.pdu_session_resource_setup_response(*case) == pycrate_response(*case), case


def test_the_response_template_leaves_to_pycrate_what_it_does_not_cover():
    good = dict(amf_id=1031, ran_id=31, pdu_session_id=1, address=bytes((127, 0, 0, 1)), teid=b'\x00\x00\x00\x1f',
                qfis=(1,))
    assert ngapfast.pdu_session_resource_setup_response(**good) == pycrate_response(*good.values())
    # pycrate's path fails on these as well
    failing = [dict(amf_id=2**40), dict(amf_id=None), dict(ran_id=-1), dict(ran_id=2**32), dict(pdu_session_id=256),
               dict(pdu_session_id=-1), dict(pdu_session_id=None), dict(pdu_session_id='1'), dict(teid=b'\x00\x00\x1f'),
               dict(teid=b'\x00' * 5), dict(teid=None), dict(teid=bytearray(4)), dict(qfis=()), dict(qfis=('1',)),
               dict(qfis=[1.0])]
    # pycrate's path encodes these, which src/NGAPSim.py does not send (its tunnel's address is IPv4, the
    # QFI one the parser read, of 0..63): extended values, sizes outside the constraint (65 flows, which
    # pycrate encodes with a count that overflows its 6 bits), booleans for ints
    others = [dict(qfis=(64,)), dict(qfis=(-1,)), dict(qfis=(1, 200)), dict(qfis=tuple(range(64)) + (1,)),
              dict(address=b''), dict(address=b'\x7f'), dict(address=b'\x7f\x00\x00\x01\x00'), dict(address=bytes(21)),
              dict(address=bytearray(4)), dict(qfis=(True,)), dict(pdu_session_id=True)]
    for bad in failing + others:
        case = dict(good, **bad)
        assert ngapfast.pdu_session_resource_setup_response(**case) is None, bad
    for bad in failing:
        with pytest.raises(Exception):
            pycrate_response(*dict(good, **bad).values())
    for bad in [dict(qfis=None), dict(qfis=1), dict(qfis=b'\x01'), dict(address=None), dict(address='127.0.0.1')]:
        assert ngapfast.pdu_session_resource_setup_response(**dict(good, **bad)) is None, bad


def test_cntgs_uplink_messages_in_the_captures_are_rebuilt_byte_for_byte():
    """ The InitialUEMessages, UplinkNASTransports, InitialContextSetupResponses and
    PDUSessionResourceSetupResponses that CN-TG's pycrate path sent to OAI's AMF, from their values """
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
        if code == 29:
            session = ies[75][0]
            dl = session['pDUSessionResourceSetupResponseTransfer'][1]['dLQosFlowPerTNLInformation']
            address, bits = dl['uPTransportLayerInformation'][1]['transportLayerAddress']
            assert ngapfast.pdu_session_resource_setup_response(
                ies[10], ies[85], session['pDUSessionID'], address.to_bytes(bits // 8, 'big'),
                dl['uPTransportLayerInformation'][1]['gTP-TEID'],
                [flow['qosFlowIdentifier'] for flow in dl['associatedQosFlowList']]) == data
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
    assert seen == {14, 15, 29, 46}


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
    IDs, NAS-PDU or None, and the PDU session of a PDU Session Resource Setup Request), as
    src/NGAPSim.py's handlers read it """
    PDU.from_aper(data)
    code = PDU.get_val()[1]['procedureCode']
    ies = {}
    for ie in PDU.get_val()[1]['value'][1]['protocolIEs']:
        ies.setdefault(ie['id'], ie['value'][1])
    if code == ngapfast.UE_CONTEXT_RELEASE:
        pair = ies[114][1]
        return code, pair['aMF-UE-NGAP-ID'], pair['rAN-UE-NGAP-ID'], None, None
    if code == ngapfast.PDU_SESSION_RESOURCE_SETUP:
        session = ies[74][0]
        transfer = {}
        for ie in session['pDUSessionResourceSetupRequestTransfer'][1]['protocolIEs']:
            transfer.setdefault(ie['id'], ie['value'][1])
        return code, ies.get(10), ies.get(85), session['pDUSessionNAS-PDU'], PDUSession(
            session['pDUSessionID'], transfer.get(139), transfer[136][0]['qosFlowIdentifier'], transfer.get(134))
    return code, ies.get(10), ies.get(85), ies.get(38), None


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
    # The PDUSessionResourceSetupRequests once pycrate had decoded the first (the UE's and the
    # session's aggregate maximum bit rates and the QoS flows, the same for every session of the
    # five captures; the NAS-PDU, ids, PDU session ID, S-NSSAI and tunnel are read)
    setups = parsed[ngapfast.PDU_SESSION_RESOURCE_SETUP]
    assert len(setups) == 140 and setups == [False] + [True] * 139
    assert parsed[21] == [False] * 4          # NGSetupResponse: pycrate's, and nothing to do
    for data in DOWNLINK:
        if data[1] in (4, 14, 29):
            assert ngapfast.downlink(data) == pycrate_view(data)
    assert {(str(key), ie) for key, ie, _ in ngapfast._learnt if key in (29, ngapfast.TRANSFER)} == {
        ('29', 110), (ngapfast.TRANSFER, 130), (ngapfast.TRANSFER, 136)}


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
    assert ngapfast._learnt == {(4, 31, b'\x00\x06')}
    assert ngapfast.downlink(good) == (4, 7, 8, AUTHENTICATION_REQUEST, None)


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
    """ The IEs in their IE set's order (a message's, or ngapfast.TRANSFER's), as OAI's AMF sends them """
    return sorted(ies, key=lambda ie: ngapfast._LAYOUTS[code].ies[ie['id']][0])


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


# PDU Session Resource Setup Requests

PDU_HEAD = b'\x00\x1d\x00'
PDU_SESSION_ACCEPT = amf_stub.pdu_session_establishment_accept(bytes((12, 1, 0, 31)))
UPF = (0x7F000002, 32)
SNSSAI = {'sST': b'\xde', 'sD': b'\x00\x00\x7b'}
QOS = {'qosCharacteristics': ('nonDynamic5QI', {'fiveQI': 9, 'priorityLevelQos': 0}),
       'allocationAndRetentionPriority': {'priorityLevelARP': 1,
                                          'pre-emptionCapability': 'shall-not-trigger-pre-emption',
                                          'pre-emptionVulnerability': 'not-pre-emptable'}}
SESSION_AMBR = {'id': 130, 'criticality': 'reject', 'value': ('PDUSessionAggregateMaximumBitRate', {
    'pDUSessionAggregateMaximumBitRateDL': 1 << 30, 'pDUSessionAggregateMaximumBitRateUL': 1 << 30})}
UE_AMBR = {'id': 110, 'criticality': 'ignore', 'value': ('UEAggregateMaximumBitRate', {
    'uEAggregateMaximumBitRateDL': 10**9, 'uEAggregateMaximumBitRateUL': 10**9})}


def setup_request(amf_id=1031, ran_id=31, nas=PDU_SESSION_ACCEPT, psi=1, upf=UPF, teid=b'\x00\x01\x00\x1f', qfis=(1,),
                  session_type='ipv4', snssai=SNSSAI, transfer=(SESSION_AMBR,), extra=(UE_AMBR,), sessions=1,
                  with_nas=True, drop=()):
    """ A PDUSessionResourceSetupRequest encoded with pycrate, as OAI's AMF sends it (by default the AMF
    stub's for UE 31 but for the TEID): its IEs and the transfer's in their sets' order, those of drop
    left out; sessions PDU sessions, the next ones with the next PDU session IDs """
    ies = [{'id': 139, 'criticality': 'reject', 'value': ('UPTransportLayerInformation', ('gTPTunnel', {
               'transportLayerAddress': upf, 'gTP-TEID': teid}))},
           {'id': 134, 'criticality': 'reject', 'value': ('PDUSessionType', session_type)},
           {'id': 136, 'criticality': 'reject', 'value': ('QosFlowSetupRequestList', [
               {'qosFlowIdentifier': q, 'qosFlowLevelQosParameters': QOS} for q in qfis])}]
    ies = [ie for ie in ies + list(transfer) if ie['id'] not in drop]
    item = {'pDUSessionID': psi, 's-NSSAI': snssai, 'pDUSessionResourceSetupRequestTransfer': (
        'PDUSessionResourceSetupRequestTransfer', {'protocolIEs': in_set_order(ngapfast.TRANSFER, ies)})}
    if with_nas:
        item['pDUSessionNAS-PDU'] = nas
    items = [dict(item, pDUSessionID=(psi + k) % 256) for k in range(sessions)]
    ies = ue_ids_values(amf_id, ran_id) + [
        {'id': 74, 'criticality': 'reject', 'value': ('PDUSessionResourceSetupListSUReq', items)}] + list(extra)
    return encode(('initiatingMessage', {'procedureCode': 29, 'criticality': 'reject', 'value': (
        'PDUSessionResourceSetupRequest', {'protocolIEs': in_set_order(29, ies)})}))


def pdu_session_requests():
    """ PDU Session Resource Setup Requests encoded with pycrate: (message, whether the parser takes it
    once it has learnt its other IEs) """
    rng = random.Random(8)
    out = []
    ids = [(a, r) for a in AMF_IDS for r in RAN_IDS[::2]]
    ids += [(rng.randrange(2**40), rng.randrange(2**32)) for _ in range(20)]
    out += [(setup_request(amf_id, ran_id), True) for amf_id, ran_id in ids]
    out += [(setup_request(psi=psi), True) for psi in range(256)]                  # every PDU session ID
    for n in (0, 1, 127, 128, 255, 256, 4000, 16000, 16250, 16384, 20000):
        data = setup_request(nas=nas_of(n, rng))
        out.append((data, data[3] & 0xC0 != 0xC0))                                # if not fragmented
    # The UPF's tunnel: IPv4, IPv6 and dual addresses, TEIDs; addresses of other sizes go to pycrate
    out += [(setup_request(upf=(int.from_bytes(a, 'big'), 8 * len(a))), True) for a in ADDRESSES]
    out += [(setup_request(upf=(rng.randrange(1 << bits), bits)), False) for bits in (1, 8, 31, 33, 64, 127, 129, 159)]
    out += [(setup_request(teid=teid.to_bytes(4, 'big')), True) for teid in TEIDS]
    # QoS flows: the first one's QFI is read; an extended one (64 and above) goes to pycrate
    for qfis, takes in [((0,), True), ((63,), True), ((5, 1), True), ((1, 2, 3), True),
                        (tuple(range(63, -1, -1)), True), ((1, 64), True), ((64,), False), ((200, 1), False)]:
        out.append((setup_request(qfis=qfis), takes))
    out += [(setup_request(session_type=t), True) for t in ('ipv4', 'ipv6', 'ipv4v6', 'ethernet', 'unstructured')]
    out += [(setup_request(snssai=s), True) for s in ({'sST': b'\x01'}, {'sST': b'\xff', 'sD': b'\xff\xff\xff'},
                                                      {'sST': b'\x00', 'sD': bytes(3)})]
    # Other IEs of the message and of the transfer, in their sets' order, or none of the optional ones
    out.append((setup_request(transfer=(), extra=()), True))
    out.append((setup_request(extra=[
        UE_AMBR, {'id': 83, 'criticality': 'ignore', 'value': ('RANPagingPriority', 5)},
        {'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', AUTHENTICATION_REQUEST)}]), True))
    out.append((setup_request(transfer=[
        SESSION_AMBR,
        {'id': 126, 'criticality': 'reject', 'value': ('UPTransportLayerInformationList', [{'nGU-UP-TNLInformation': (
            'gTPTunnel', {'transportLayerAddress': (0x7F000003, 32), 'gTP-TEID': b'\x00\x00\x00\x09'})}])},
        {'id': 127, 'criticality': 'reject', 'value': ('DataForwardingNotPossible', 'data-forwarding-not-possible')},
        {'id': 138, 'criticality': 'reject', 'value': ('SecurityIndication', {
            'integrityProtectionIndication': 'not-needed', 'confidentialityProtectionIndication': 'preferred'})},
        {'id': 129, 'criticality': 'reject', 'value': ('NetworkInstance', 1)},
        {'id': 166, 'criticality': 'ignore', 'value': ('CommonNetworkInstance', b'internet')}]), True))
    # What the parser leaves to pycrate: two PDU sessions (src/NGAPSim.py reads the first), one without
    # its NAS-PDU (src/NGAPSim.py's handler fails), no UL tunnel or no QoS flows
    out += [(setup_request(sessions=2), False), (setup_request(with_nas=False), False),
            (setup_request(drop=(139,)), False), (setup_request(drop=(136,)), False)]
    # and all of it at random
    for _ in range(60):
        a = rng.choice(ADDRESSES)
        out.append((setup_request(
            rng.randrange(2**40), rng.randrange(2**32), nas_of(rng.randrange(300), rng), rng.randrange(256),
            (int.from_bytes(a, 'big'), 8 * len(a)), rng.randbytes(4),
            tuple(rng.randrange(64) for _ in range(rng.randrange(1, 5))),
            rng.choice(('ipv4', 'ipv6', 'ipv4v6')), rng.choice([SNSSAI, {'sST': b'\x01'}])), True))
    return out


def test_pdu_session_resource_setup_requests_decode_as_with_pycrate(fresh):
    assert setup_request(teid=(0x10000 + 31).to_bytes(4, 'big')) == amf_stub.pdu_session_resource_setup_request(
        1031, 31, PDU_SESSION_ACCEPT)
    fast, slow = make_gnb(True), make_gnb(False)
    taken = 0
    for data, takes in pdu_session_requests():
        # the first of a kind on pycrate's path, which teaches the parser the IEs it does not read
        assert outcome(fast._downlink, data) == outcome(slow._downlink, data)
        got = ngapfast.downlink(data)
        assert (got is not None) == takes, data.hex()[:160]
        if got is not None:
            taken += 1
            assert got == pycrate_view(data)
            assert fast._downlink(data) == slow._downlink(data)
    assert taken > 400


def test_the_gnbs_tunnel_is_pycrates(fresh, monkeypatch):
    """ The response's DL tunnel: the gNB's address (gtpIp, IPv4; pycrate's path fails on others, and the
    fast path leaves them to it) and the RAN UE NGAP ID as the TEID, for ids at their bounds """
    for amf_id, ran_id in [(0, 0), (2**40 - 1, 2**32 - 1), (1031, 31)]:
        data = setup_request(amf_id, ran_id)
        ngapfast.learn(data)
        for address in ('127.0.0.1', '0.0.0.0', '192.168.72.142', '255.255.255.255', '127.1', '::1', 'gnb'):
            monkeypatch.setattr(ngapsim, 'gtpIp', address)
            want = outcome(make_gnb(False)._downlink, data)
            assert outcome(make_gnb(True)._downlink, data) == want, address
            assert (want[0] == 'raised') == (address in ('::1', 'gnb'))


# The PDU Session Resource Setup Request assembled from its parts, for the variants pycrate does not encode

def aper(type_name, value):
    """ pycrate's APER encoding of a value of an NGAP IE's type """
    obj = getattr(NGAP.NGAP_IEs, type_name)
    obj.set_val(value)
    return obj.to_aper()


def gtp_tunnel(address=b'\x7f\x00\x00\x02', teid=b'\x00\x01\x00\x1f', head=None):
    """ A UPTransportLayerInformation (gTPTunnel): the choice, extension and option bits and the
    address's size less one (2 octets, its padding), the address, the TEID """
    return (((8 * len(address) - 1) << 4).to_bytes(2, 'big') if head is None else head) + address + teid


def transfer_ies(tunnel=None, session_type=b'\x00', flows=None):
    """ The AMF stub's transfer IEs (UE 31, TEID 0x1001f) """
    return [field(130, REJECT, aper('PDUSessionAggregateMaximumBitRate', SESSION_AMBR['value'][1])),
            field(139, REJECT, gtp_tunnel() if tunnel is None else tunnel),
            field(134, REJECT, session_type),
            field(136, REJECT, aper('QosFlowSetupRequestList', [
                {'qosFlowIdentifier': 1, 'qosFlowLevelQosParameters': QOS}]) if flows is None else flows)]


def transfer_of(ies, ext=b'\x00', count=None):
    """ A PDUSessionResourceSetupRequestTransfer: its extension bit and padding, the IE count, the IEs """
    return ext + (len(ies) if count is None else count).to_bytes(2, 'big') + b''.join(ies)


def session_item(ies=None, psi=1, nas=PDU_SESSION_ACCEPT, head=b'\x40', snssai=b'\x5b\xc0\x00\x00\x7b', wrapped=None):
    """ A PDUSessionResourceSetupItemSUReq: extension and option bits (the NAS-PDU's set) and padding,
    the PDU session ID, the NAS-PDU, the S-NSSAI (its extension and option bits, the SST, padding, the
    SD), the transfer (wrapped: the OCTET STRING's length and content as they are) """
    return (head + bytes((psi,)) + (wrap(nas) if head[0] & 0x40 else b'') + snssai
            + (wrap(transfer_of(transfer_ies() if ies is None else ies)) if wrapped is None else wrapped))


UE_AMBR_IE = field(110, IGNORE, aper('UEAggregateMaximumBitRate', UE_AMBR['value'][1]))


def assembled(items=None, count=None, ies=None, crit=REJECT, head=PDU_HEAD):
    """ A PDUSessionResourceSetupRequest: the UE NGAP IDs (1031, 31), its PDU sessions (the count less
    one, the items), the UE's aggregate maximum bit rate; or with these IEs """
    if ies is None:
        items = [session_item()] if items is None else items
        sessions = bytes(((len(items) if count is None else count) - 1,)) + b''.join(items)
        ies = ue_ids(1031, 31) + [field(74, crit, sessions), UE_AMBR_IE]
    return message(head, ies)


def pdu_session_variants():
    """ (name, message) the parser must leave to pycrate, even once it has learnt their other IEs """
    t = transfer_ies()
    good = transfer_of(t)
    ids = ue_ids(1031, 31)
    sessions = field(74, REJECT, b'\x00' + session_item())
    return [
        ('two PDU sessions', assembled([session_item(), session_item(psi=2)])),
        ('a PDU session without its NAS-PDU', assembled([session_item(head=b'\x00')])),
        ('PDU session extension bit', assembled([session_item(head=b'\xc0')])),
        ('PDU session iE-Extensions', assembled([session_item(head=b'\x60')])),
        ('PDU session padding', assembled([session_item(head=b'\x41')])),
        ('PDU session count of 2 for one', assembled(count=2)),
        ('PDU session NAS-PDU long form for a short length', assembled([session_item(nas=b'')[:2] + b'\x80'
                                                                       + session_item(nas=b'')[2:]])),
        ('S-NSSAI extension bit', assembled([session_item(snssai=b'\xdb\xc0\x00\x00\x7b')])),
        ('S-NSSAI iE-Extensions', assembled([session_item(snssai=b'\x7b\xc0\x00\x00\x7b')])),
        ('S-NSSAI padding', assembled([session_item(snssai=b'\x5b\xc1\x00\x00\x7b')])),
        ('S-NSSAI without SD, with its octets', assembled([session_item(snssai=b'\x1b\xc0\x00\x00\x7b')])),
        ('transfer extension bit', assembled([session_item(wrapped=wrap(transfer_of(t, ext=b'\x80')))])),
        ('transfer padding', assembled([session_item(wrapped=wrap(transfer_of(t, ext=b'\x01')))])),
        ('transfer count too large', assembled([session_item(wrapped=wrap(transfer_of(t, count=5)))])),
        ('transfer count too small', assembled([session_item(wrapped=wrap(transfer_of(t, count=3)))])),
        ('transfer trailing octet', assembled([session_item(wrapped=wrap(good + b'\x00'))])),
        ('transfer shorter than its length', assembled([session_item(wrapped=wrap(good)[:-1])])),
        ('transfer IE after its end', assembled([session_item(wrapped=bytes((len(good) - len(t[3]),)) + good)])),
        ('transfer long form for a short length', assembled([session_item(wrapped=b'\x80' + wrap(good))])),
        ('transfer empty', assembled([session_item(wrapped=b'\x00')])),
        ('transfer IE order', assembled([session_item([t[0], t[2], t[1], t[3]])])),
        ('transfer IE twice', assembled([session_item([t[0], t[1], t[1], t[2], t[3]])])),
        ('transfer IE unknown', assembled([session_item(t + [field(999, IGNORE, b'\x00')])])),
        ("a message's IE in the transfer", assembled([session_item([ids[0]] + t)])),
        ('transfer IE criticality', assembled([session_item([t[0], field(139, IGNORE, gtp_tunnel())] + t[2:])])),
        ('transfer IE criticality padding',
         assembled([session_item([t[0], field(139, b'\x01', gtp_tunnel())] + t[2:])])),
        ('no UL tunnel', assembled([session_item([t[0], t[2], t[3]])])),
        ('no QoS flows', assembled([session_item(t[:3])])),
        ('tunnel choice-Extensions', assembled([session_item(transfer_ies(gtp_tunnel(head=b'\x81\xf0')))])),
        ('tunnel extension bit', assembled([session_item(transfer_ies(gtp_tunnel(head=b'\x41\xf0')))])),
        ('tunnel iE-Extensions', assembled([session_item(transfer_ies(gtp_tunnel(head=b'\x21\xf0')))])),
        ('address extension bit', assembled([session_item(transfer_ies(gtp_tunnel(head=b'\x11\xf0')))])),
        ('tunnel padding', assembled([session_item(transfer_ies(gtp_tunnel(head=b'\x01\xf1')))])),
        ('address shorter than its size', assembled([session_item(transfer_ies(gtp_tunnel(head=b'\x07\xf0')))])),
        ('address of 40 bits', assembled([session_item(transfer_ies(gtp_tunnel(address=bytes(5))))])),
        ('TEID of 3 octets', assembled([session_item(transfer_ies(gtp_tunnel(teid=b'\x00\x01\x1f')))])),
        ('TEID of 5 octets', assembled([session_item(transfer_ies(gtp_tunnel(teid=b'\x00\x00\x01\x00\x1f')))])),
        ('PDU session type extension bit', assembled([session_item(transfer_ies(session_type=b'\x80'))])),
        ('PDU session type 5', assembled([session_item(transfer_ies(session_type=b'\x50'))])),
        ('PDU session type 7', assembled([session_item(transfer_ies(session_type=b'\x70'))])),
        ('PDU session type padding', assembled([session_item(transfer_ies(session_type=b'\x01'))])),
        ('PDU session type of 2 octets', assembled([session_item(transfer_ies(session_type=b'\x00\x00'))])),
        ('extended QFI', assembled([session_item(transfer_ies(flows=aper('QosFlowSetupRequestList', [
            {'qosFlowIdentifier': 64, 'qosFlowLevelQosParameters': QOS}])))])),
        ('PDU session list criticality', assembled(crit=IGNORE)),
        ('no PDU session list', assembled(ies=ids + [UE_AMBR_IE])),
        ('PDU session list twice', assembled(ies=ids + [sessions, sessions, UE_AMBR_IE])),
        ('PDU session list after the UE AMBR', assembled(ies=ids + [UE_AMBR_IE, sessions])),
        ('no AMF UE NGAP ID', assembled(ies=ids[1:] + [sessions, UE_AMBR_IE])),
        ('successfulOutcome', assembled(head=b'\x20\x1d\x00')),
        ('procedure criticality', assembled(head=b'\x00\x1d\x40')),
    ]


def test_pdu_session_requests_outside_the_parser_take_pycrates_path(fresh):
    fast, slow = make_gnb(True), make_gnb(False)
    reference = assembled()
    assert reference == setup_request(teid=b'\x00\x01\x00\x1f')
    ngapfast.learn(reference)
    assert ngapfast.downlink(reference) == pycrate_view(reference)
    for name, data in pdu_session_variants():
        ngapfast.learn(data)
        assert ngapfast.downlink(data) is None, name
        assert outcome(fast._downlink, data) == outcome(slow._downlink, data), name
    # every prefix of a message
    for i in range(len(reference)):
        assert ngapfast.downlink(reference[:i]) is None
        assert outcome(fast._downlink, reference[:i]) == outcome(slow._downlink, reference[:i]), i


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
        ('PDU Session Resource Setup Request, its other IEs not learnt',
         amf_stub.pdu_session_resource_setup_request(1031, 31, nas)),
        ('PDU Session Resource Release Command', encode(('initiatingMessage', {
            'procedureCode': 28, 'criticality': 'reject', 'value': ('PDUSessionResourceReleaseCommand', {
                'protocolIEs': ue_ids_values(1031, 31) + [
                    {'id': 79, 'criticality': 'reject', 'value': ('PDUSessionResourceToReleaseListRelCmd', [{
                        'pDUSessionID': 1, 'pDUSessionResourceReleaseCommandTransfer': (
                            'PDUSessionResourceReleaseCommandTransfer',
                            {'cause': ('nas', 'normal-release')})}])}]})}))),
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
    assert ngapfast.downlink(reference) == (4, 1031, 31, AUTHENTICATION_REQUEST, None)
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
    bases += [d for d, _ in pdu_session_requests() if len(d) < 600][::12] + [assembled()]
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
    setup = amf_stub.pdu_session_resource_setup_request(1031, 31, PDU_SESSION_ACCEPT)
    want_setup = make_gnb(False)._downlink(setup)
    ngapfast.learn(setup)                   # its UE AMBR, session AMBR and QoS flows, as pycrate's path would

    class Broken:
        def __getattr__(self, name):
            raise AssertionError('pycrate used')
    monkeypatch.setattr(NGAP.NGAP_PDU_Descriptions, 'NGAP_PDU', Broken())
    gnb._handle_uplink(link.ran_end, connect)
    gnb._handle_uplink(link.ran_end, ul_nas)
    assert gnb.sctp.sent == want
    assert gnb._downlink(dl) == (4, None, AUTHENTICATION_REQUEST, {'ran_ue_ngap_id': 31, 'amf_ue_ngap_id': 1031})
    assert gnb._downlink(ics) == (14, want_ics, REGISTRATION_ACCEPT, {'ran_ue_ngap_id': 31, 'amf_ue_ngap_id': 1031})
    assert gnb._downlink(setup) == want_setup
    assert want_setup[3]['ul_up_transport_layer_information'] == (
        'gTPTunnel', {'transportLayerAddress': (0x7F000002, 32), 'gTP-TEID': (0x10000 + 31).to_bytes(4, 'big')})
    assert want_setup[1] == pycrate_response(1031, 31, 1, bytes((127, 0, 0, 1)), (31).to_bytes(4, 'big'), (1,))
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
    monkeypatch.setattr(ngapfast, 'pdu_session_resource_setup_response', broken)
    dl = amf_stub.downlink_nas_transport(1031, 31, AUTHENTICATION_REQUEST)
    setup = amf_stub.pdu_session_resource_setup_request(1031, 31, PDU_SESSION_ACCEPT)
    for gnb in (make_gnb(False), make_gnb(True)):
        level = ngapsim.logger.level
        if gnb.ngap_fastpath:
            ngapsim.logger.setLevel(logging.DEBUG)
        try:
            gnb.ues[31] = {'amf_ue_ngap_id': 1031}
            gnb._handle_uplink(None, Event(UL_NAS, 31, AUTHENTICATION_REQUEST, 87))
            assert gnb._downlink(dl)[2] == AUTHENTICATION_REQUEST
            assert gnb._downlink(setup)[2] == PDU_SESSION_ACCEPT
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
