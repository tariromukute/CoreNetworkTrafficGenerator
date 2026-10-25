""" The UE simulator and the gNB on the UE-RAN link: what each sends and does with what it receives.

Run from the repository root (needs pycrate and CryptoMobile, as src/UESim.py does):

    python3 -m pytest tests/test_ue_ran_wiring.py
"""
import logging
import queue
import threading
import time
from multiprocessing import Value
from types import SimpleNamespace

from pycrate_asn1dir import NGAP

import src.NGAPSim as ngapsim
from src import ranlink
from src.NGAPSim import GNB, initial_ue_message, plmn_str_to_buf, uplink_nas_transport
from src.ranlink import CONNECT, DL_NAS, RELEASE, SECURITY, UL_NAS, UP_CONTROL, Event, PipeLink
from src.UESim import UESim

REGISTRATION_REQUEST = bytes.fromhex('7e004179000d0102f8590000000000000000132e04f0f0f0f0')
AUTHENTICATION_RESPONSE = bytes.fromhex('7e00572d1038edd5c92db1a0f041f710eb93be0316')
PROTECTED = bytes.fromhex('7e02a82c79eb017e0043')


# The UE simulator's side

def make_sim(link):
    sim = UESim.__new__(UESim)               # only what sending and the reader use
    sim.link = link.ue_end
    sim.exit_program = Value('i', 0)
    sim.send_lock = threading.Lock()
    sim.worker_queues = []
    return sim


def test_the_initial_registration_request_connects_and_the_rest_is_ul_nas():
    link = PipeLink()
    sim = make_sim(link)
    sim._send_nas(31, REGISTRATION_REQUEST, 65)
    sim._send_nas(31, AUTHENTICATION_RESPONSE, 87)
    sim._send_nas(31, PROTECTED, 67)
    sim._send_up_control(31, b'\x0c\x01\x01\x07', '208950000000031')
    got = [link.ran_end.recv(1) for _ in range(4)]
    assert got[0] == Event(CONNECT, 31, ranlink.connect_payload(REGISTRATION_REQUEST), 65)
    assert ranlink.parse_connect(got[0].payload) == (ranlink.MO_SIGNALLING, None, REGISTRATION_REQUEST)
    assert got[1] == Event(UL_NAS, 31, AUTHENTICATION_RESPONSE, 87)
    assert got[2] == Event(UL_NAS, 31, PROTECTED, 67)
    assert got[3].kind == UP_CONTROL and got[3].ue_id == 31
    assert ranlink.parse_up_control(got[3].payload) == (ranlink.UP_SESSION, b'\x0c\x01\x01\x07', '208950000000031')
    link.close()


def test_the_reader_hands_dl_nas_and_release_to_the_ues_worker():
    link = PipeLink()
    sim = make_sim(link)
    got = queue.Queue()
    sim._handle_downlink = lambda data, ue_id, received_at=None, ul_sent=None: got.put((data, ue_id, received_at, ul_sent))
    sim._load_ngap_to_ue_thread()
    link.ran_end.send(DL_NAS, 31, b'nas', 0, 2.5, [(65, 2.25)])
    link.ran_end.send(SECURITY, 31)                         # not for the NAS-only UE
    link.ran_end.send(RELEASE, 31, b'', 0, 3.5, [(102, 3.25)])
    link.ran_end.send(DL_NAS, 32, b'unstamped')
    out = sorted(got.get(timeout=5) for _ in range(3))
    sim.exit_program.value = 1
    # The release is the UE's (R)AN Connection Release (b'F'), as the gNB's b'F' was
    assert out == [(b'F', 31, 3.5, [(102, 3.25)]), (b'nas', 31, 2.5, [(65, 2.25)]), (b'unstamped', 32, None, None)]
    assert got.empty()
    link.close()


def test_a_closed_link_does_not_stop_the_ue_simulator(caplog):
    link = PipeLink()
    sim = make_sim(link)
    link.ran_end.close()
    link.ue_end.attach()
    with caplog.at_level(logging.WARNING):
        sim._send_nas(31, AUTHENTICATION_RESPONSE, 87)     # logged, not raised
    assert 'link to the gNB has ended' in caplog.text
    link.close()


# The gNB's side

class FakeSCTP:
    def __init__(self, gnb):
        self.gnb, self.sent = gnb, []

    def send(self, data):
        # the stamps the gNB holds when the message leaves
        self.sent.append((data, {k: list(v) for k, v in self.gnb.ul_sent.items()}))


def make_gnb(links):
    gnb = GNB.__new__(GNB)                 # only what the uplink and downlink paths use
    gnb.links = links
    gnb.ue_links, gnb.clashes = {}, set()
    gnb.ues, gnb.ul_sent, gnb.ul_sent_lock = {}, {}, threading.Lock()
    gnb.gnb_id, gnb.plmn_identity, gnb.tac = 1, plmn_str_to_buf('20895'), (0xa000).to_bytes(3, 'big')
    gnb.sctp = FakeSCTP(gnb)
    gnb.userplane = SimpleNamespace(sessions=[], add_session=lambda s: gnb.userplane.sessions.append(s))
    return gnb


def encode(build, nas, ue, gnb):
    pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    build(pdu, [{'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', nas)}], ue, gnb)
    return pdu.to_aper()


def test_connect_and_ul_nas_give_the_same_ngap_bytes_as_before(monkeypatch):
    monkeypatch.setattr(ngapsim.time, 'time', lambda: 1761400000.0)
    link = PipeLink()
    gnb = make_gnb([link.ran_end])
    gnb._handle_uplink(link.ran_end, Event(CONNECT, 31, ranlink.connect_payload(REGISTRATION_REQUEST), 65))
    gnb.ues[31] = {'amf_ue_ngap_id': 1031}
    gnb._handle_uplink(link.ran_end, Event(UL_NAS, 31, AUTHENTICATION_RESPONSE, 87))
    # What the gNB built before the link, from (NAS PDU, UE ID, message code)
    before = [encode(initial_ue_message, REGISTRATION_REQUEST, {'amf_ue_ngap_id': None, 'ran_ue_ngap_id': 31}, gnb),
              encode(uplink_nas_transport, AUTHENTICATION_RESPONSE, {'amf_ue_ngap_id': 1031, 'ran_ue_ngap_id': 31}, gnb)]
    assert [data for data, _ in gnb.sctp.sent] == before
    # Each message is stamped before it is sent (G7b)
    assert [stamps for _, stamps in gnb.sctp.sent] == [{31: [(65, 1761400000.0)]},
                                                       {31: [(65, 1761400000.0), (87, 1761400000.0)]}]
    link.close()


def test_the_initial_ue_message_carries_the_cause_and_the_5g_s_tmsi():
    gnb = make_gnb([])
    pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    pdu.from_aper(encode(initial_ue_message, REGISTRATION_REQUEST, {'ran_ue_ngap_id': 31}, gnb))
    ies = {ie['id']: ie['value'][1] for ie in pdu.get_val()[1]['value'][1]['protocolIEs']}
    assert ies[90] == 'mo-Signalling' and 26 not in ies
    ue = {'ran_ue_ngap_id': 31, 'cause': ranlink.MT_ACCESS, 's_tmsi': bytes.fromhex('0141deadbeef')}
    pdu.from_aper(encode(initial_ue_message, REGISTRATION_REQUEST, ue, gnb))
    ies = {ie['id']: ie['value'][1] for ie in pdu.get_val()[1]['value'][1]['protocolIEs']}
    assert ies[90] == 'mt-Access'
    assert ies[26] == {'aMFSetID': (5, 10), 'aMFPointer': (1, 6), 'fiveG-TMSI': bytes.fromhex('deadbeef')}


def test_up_control_hands_the_session_to_the_user_plane():
    link = PipeLink()
    gnb = make_gnb([link.ran_end])
    gnb.ues[31] = {'amf_ue_ngap_id': 1031, 'qfi': 1, 'ul_teid': 0x10001, 'dl_teid': 31,
                   'upf_address': '127.0.0.2', 'pdu_session_id': 1}
    gnb._handle_uplink(link.ran_end, Event(UP_CONTROL, 31, ranlink.up_control_payload(b'\x0c\x01\x00\x1f', '208950000000031')))
    [s] = gnb.userplane.sessions
    assert (s.supi, s.ue_ip, s.pdu_session_id, s.ul_teid, s.qfi, s.upf_address, s.dl_teid, s.ran_ue_ngap_id,
            s.amf_ue_ngap_id) == ('208950000000031', '12.1.0.31', 1, 0x10001, 1, '127.0.0.2', 31, 31, 1031)
    assert gnb.sctp.sent == []
    link.close()


def test_downlink_goes_back_on_the_link_the_ue_came_on():
    links = [PipeLink() for _ in range(3)]
    ends = [link.ran_end for link in links]
    gnb = make_gnb(ends)
    for k, end in enumerate(ends):
        for ue in (31 + 10 * k, 32 + 10 * k):
            gnb._claim(end, ue)
    gnb._stamp_uplink(42, 87, 5.0)
    gnb._to_ue(DL_NAS, 42, b'to 42', 5.5)
    gnb._to_ue(RELEASE, 51, b'', 6.5)
    gnb._to_ue(DL_NAS, 99, b'to no one', 7.5)      # never seen, several links: dropped
    assert links[1].ue_end.recv(1) == Event(DL_NAS, 42, b'to 42', 0, 5.5, [(87, 5.0)])
    assert links[2].ue_end.recv(1) == Event(RELEASE, 51, b'', 0, 6.5, [])
    assert all(link.ue_end.recv(0.1) is None for link in links)
    assert gnb.ul_sent == {}
    for link in links:
        link.close()


def test_with_one_link_every_downlink_goes_on_it():
    link = PipeLink()
    gnb = make_gnb([link.ran_end])
    gnb._to_ue(DL_NAS, 99, b'unknown', 1.0)          # as the one pipe took every message
    assert link.ue_end.recv(1) == Event(DL_NAS, 99, b'unknown', 0, 1.0, [])
    link.close()


def test_a_ue_id_on_two_links_is_reported_not_mixed(caplog, monkeypatch):
    monkeypatch.setattr(ngapsim.time, 'time', lambda: 1761400000.0)
    links = [PipeLink() for _ in range(2)]
    gnb = make_gnb([link.ran_end for link in links])
    gnb._handle_uplink(links[0].ran_end, Event(CONNECT, 31, ranlink.connect_payload(REGISTRATION_REQUEST), 65))
    with caplog.at_level(logging.ERROR):
        gnb._handle_uplink(links[1].ran_end, Event(CONNECT, 31, ranlink.connect_payload(REGISTRATION_REQUEST), 65))
        gnb._handle_uplink(links[1].ran_end, Event(UL_NAS, 31, AUTHENTICATION_RESPONSE, 87))
    assert len(gnb.sctp.sent) == 1                   # only the first link's
    assert gnb.clashes == {31}
    assert caplog.text.count('RAN UE NGAP ID 31 comes from two UE simulators') == 1
    gnb._to_ue(DL_NAS, 31, b'nas', 1.0)              # still the first link's UE
    assert links[0].ue_end.recv(1).payload == b'nas'
    assert links[1].ue_end.recv(0.1) is None
    for link in links:
        link.close()


def test_the_uplink_thread_serves_every_link_and_lets_closed_ones_go(monkeypatch):
    monkeypatch.setattr(ngapsim.time, 'time', lambda: 1761400000.0)
    links = [PipeLink() for _ in range(2)]
    gnb = make_gnb([link.ran_end for link in links])
    gnb.waiter = links[0].ran_end.waiter(gnb.links)
    threading.Thread(target=gnb._ue_to_ngap_thread_function, daemon=True).start()
    links[0].ue_end.send(CONNECT, 31, ranlink.connect_payload(REGISTRATION_REQUEST), 65)
    links[1].ue_end.send(CONNECT, 41, ranlink.connect_payload(REGISTRATION_REQUEST), 65)
    links[1].ue_end.close()
    links[1].ran_end.attach()                        # this process lets go of the UE side's end: it has gone
    deadline = time.monotonic() + 5                 # time.time() stands still here
    while (len(gnb.sctp.sent) < 2 or len(gnb.waiter) > 1) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(gnb.sctp.sent) == 2 and gnb.waiter.links == [links[0].ran_end]
    assert gnb.ue_links == {31: links[0].ran_end, 41: links[1].ran_end}
    for link in links:
        link.close()


# run.py

def test_a_gnbs_ues_are_split_in_turn():
    import run
    ues = {i: f'ue{i}' for i in range(31, 41)}
    assert run.split_ues(ues, 1) == [ues]
    parts = run.split_ues(ues, 3)
    assert [list(p) for p in parts] == [[31, 34, 37, 40], [32, 35, 38], [33, 36, 39]]
    assert [list(p) for p in run.split_ues({31: 'a', 32: 'b'}, 4)] == [[31], [32]]


def test_inflight_is_shared_per_gnb():
    import run
    assert [run.share(10, 1, 0)] == [10]
    assert [run.share(10, 3, j) for j in range(3)] == [4, 3, 3]
    assert [run.share(2, 4, j) for j in range(4)] == [1, 1, 1, 1]     # at least one each
    assert [run.share(0, 4, j) for j in range(4)] == [0, 0, 0, 0]     # the open loop stays open


def test_the_ue_simulators_of_a_gnb_keep_its_start_schedule():
    from src.pacing import start_offsets
    import run
    ues = {i: i for i in range(31, 41)}
    interval = 0.02
    gnb = dict(zip(ues, start_offsets(len(ues), interval)))
    parts = run.split_ues(ues, 3)
    split = {}
    for k, part in enumerate(parts):
        for ue, offset in zip(part, start_offsets(len(part), interval * len(parts))):
            split[ue] = offset + interval * k
    assert split.keys() == gnb.keys()
    assert all(abs(split[u] - gnb[u]) < 1e-9 for u in ues)
