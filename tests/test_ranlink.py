""" The UE-RAN link (src/ranlink.py): its framing, and the contract every link keeps.

The contract tests take a link type from LINKS (a class whose instances have ue_end, a RanLink, and
ran_end, a UeLink, and take stop and interval): PipeLink and ShmLink. tests/test_shmlink.py stresses
ShmLink's rings.

Run from the repository root:

    python3 -m pytest tests/test_ranlink.py
"""
import multiprocessing
import os
import random
import struct
import threading
import time

import pytest

from src import ranlink
from src.ranlink import (CONNECT, DATA, DL_NAS, KIND_NAMES, RELEASE, SECURITY, UL_NAS, UP_CONTROL, Event,
                         FrameError, LinkClosed, LinkStopped, PipeLink, decode, encode)
from src.shmlink import ShmLink, supported

LINKS = [PipeLink, pytest.param(ShmLink, marks=pytest.mark.skipif(not supported(), reason='ShmLink needs Linux on x86-64'))]

KINDS = sorted(KIND_NAMES)
STAMPS = [None, [], [(65, 1761400000.25)], [(65, 1.5), (67, 2.75), (94, 3.0)]]
TIMES = [None, 0.0, 1761400000.123456]
LENGTHS = [0, 1, 255, 256, 16367, 16368, 65535, 65536, 70000]


# Framing

@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('received_at', TIMES)
@pytest.mark.parametrize('stamps', STAMPS)
def test_every_kind_round_trips(kind, received_at, stamps):
    payload = os.urandom(97)
    event = Event(kind, 31, payload, 65, received_at, stamps)
    assert decode(encode(*event)) == event


@pytest.mark.parametrize('length', LENGTHS)
def test_payload_lengths(length):
    payload = os.urandom(length)
    for event in (Event(UL_NAS, 7, payload, 67), Event(DL_NAS, 7, payload, 0, 2.5, [(67, 2.25)])):
        frame = encode(*event)
        assert decode(frame) == event
        assert decode(memoryview(frame)) == event      # as a shared-memory ring would give it


def test_field_boundaries():
    for ue_id in (0, 1, 2**31, 2**32 - 1):
        for code in (0, 65, 0xFFFF):
            event = Event(CONNECT, ue_id, b'\x7e\x00\x41', code)
            assert decode(encode(*event)) == event
    with pytest.raises(struct.error):
        encode(UL_NAS, 2**32, b'')          # a RAN UE NGAP ID is 32 bits


def test_the_layout():
    assert encode(UL_NAS, 31, b'abc', 65) == struct.pack('=BBHIHHI', 1, UL_NAS, 0, 31, 65, 0, 3) + b'abc'
    frame = encode(DL_NAS, 31, b'nas', 0, 1.5, [(65, 1.25), (67, 1.375)])
    assert frame[:16] == struct.pack('=BBHIHHI', 1, DL_NAS, 3, 31, 0, 0, 3)
    assert frame[16:24] == struct.pack('=d', 1.5)
    assert frame[24:27] == b'nas'
    assert frame[27:] == struct.pack('=HHdHd', 2, 65, 1.25, 67, 1.375)
    assert encode(RELEASE, 31, b'', 0, None, []) == struct.pack('=BBHIHHIH', 1, RELEASE, 2, 31, 0, 0, 0, 0)


def test_version_and_kind_are_checked():
    frame = bytearray(encode(UL_NAS, 31, b'abc', 65))
    frame[0] = 2
    with pytest.raises(FrameError, match='version'):
        decode(bytes(frame))
    for kind in (0, max(KINDS) + 1, 255):
        frame = bytearray(encode(UL_NAS, 31, b'abc', 65))
        frame[1] = kind
        with pytest.raises(FrameError, match='kind'):
            decode(bytes(frame))


def test_lengths_are_checked():
    frame = encode(DL_NAS, 31, b'abc', 0, 1.0, [(65, 1.0)])
    for bad in (frame[:10], frame[:20], frame[:-1], frame + b'\x00', encode(UL_NAS, 31, b'abc') + b'x'):
        with pytest.raises(FrameError):
            decode(bad)


def test_connect_payload():
    nas = bytes.fromhex('7e004179000d0102f8590000000000000000132e04f0f0f0f0')
    payload = ranlink.connect_payload(nas)
    assert payload[:8] == bytes([ranlink.MO_SIGNALLING, 0]) + bytes(6)
    assert ranlink.parse_connect(payload) == (ranlink.MO_SIGNALLING, None, nas)
    s_tmsi = bytes.fromhex('0140deadbeef')
    payload = ranlink.connect_payload(nas, ranlink.MT_ACCESS, s_tmsi)
    assert payload[:8] == bytes([ranlink.MT_ACCESS, 1]) + s_tmsi
    assert ranlink.parse_connect(payload) == (ranlink.MT_ACCESS, s_tmsi, nas)
    with pytest.raises(ValueError):
        ranlink.connect_payload(nas, s_tmsi=b'\x01\x02')
    with pytest.raises(FrameError):
        ranlink.parse_connect(b'\x03\x00')


def test_up_control_and_data_payloads():
    for address, supi in ((b'\x0c\x01\x01\x07', '208950000000031'), (bytes(range(16)), None)):
        payload = ranlink.up_control_payload(address, supi)
        assert ranlink.parse_up_control(payload) == (ranlink.UP_SESSION, address, supi)
    with pytest.raises(FrameError):
        ranlink.parse_up_control(b'\x01\x04\x0c')
    packet = os.urandom(1400)
    assert ranlink.parse_data(ranlink.data_payload(1, 9, packet)) == (1, 9, packet)


def test_connect_only_for_the_initial_registration_request():
    from src.NGAPSim import is_plain_registration_request as gnbs
    assert gnbs is ranlink.is_plain_registration_request      # one predicate, shared
    assert ranlink.is_plain_registration_request(b'\x7e\x00\x41\x79')
    assert not ranlink.is_plain_registration_request(b'\x7e\x02\x00\x00\x00\x00\x00\x7e\x00\x41')
    assert not ranlink.is_plain_registration_request(b'\x7e\x00\x43')


# The contract

def drain(end, n, timeout=10.0):
    got, deadline = [], time.time() + timeout
    while len(got) < n and time.time() < deadline:
        event = end.recv(0.1)
        if event is not None:
            got.append(event)
    return got


def all_kinds():
    """ One event of each kind and direction, as the UE simulator and the gNB send them """
    nas = bytes.fromhex('7e00572d1038edd5c92db1a0f041f710eb93be0316')
    up = [Event(CONNECT, 31, ranlink.connect_payload(nas), 65), Event(UL_NAS, 31, nas, 87),
          Event(UP_CONTROL, 31, ranlink.up_control_payload(b'\x0c\x01\x01\x07', '208950000000031')),
          Event(SECURITY, 31, os.urandom(32)), Event(RELEASE, 31), Event(DATA, 31, ranlink.data_payload(1, 9, os.urandom(60)))]
    down = [Event(DL_NAS, 31, nas, 0, 1761400000.5, [(65, 1761400000.25)]), Event(DL_NAS, 32, nas, 0, 2.0, []),
            Event(DL_NAS, 33, nas), Event(RELEASE, 31, b'', 0, 3.0, [(102, 2.5)]), Event(SECURITY, 31),
            Event(DATA, 31, ranlink.data_payload(1, 9, os.urandom(1400)))]
    return up, down


@pytest.mark.parametrize('link_type', LINKS)
def test_events_arrive_unchanged_both_ways(link_type):
    link = link_type()
    up, down = all_kinds()
    for event in up:
        link.ue_end.send(*event)
    for event in down:
        link.ran_end.send(*event)
    assert drain(link.ran_end, len(up)) == up
    assert drain(link.ue_end, len(down)) == down
    assert link.ran_end.recv(0.05) is None and link.ue_end.recv(0.05) is None
    link.close()


@pytest.mark.parametrize('link_type', LINKS)
def test_large_events_both_ways(link_type):
    link = link_type()
    events = [Event(DL_NAS, 31, os.urandom(n), 0, 1.0, [(65, 0.5)]) for n in (16368, 16369, 70000, 300000)]
    got = []
    reader = threading.Thread(target=lambda: got.extend(drain(link.ue_end, len(events))))
    reader.start()
    for event in events:
        link.ran_end.send(*event)
    reader.join(10)
    assert got == events
    link.close()


@pytest.mark.parametrize('link_type', LINKS)
def test_each_ues_order_is_kept_with_interleaved_ues_and_concurrent_senders(link_type):
    link = link_type()
    lock = threading.Lock()                 # as the UE simulator's workers send
    ues, n = list(range(31, 47)), 200

    def worker(mine):
        for i in range(n):
            for ue in mine:
                with lock:
                    link.ue_end.send(UL_NAS, ue, i.to_bytes(4, 'big') + os.urandom(random.randrange(60)), 87)

    workers = [threading.Thread(target=worker, args=(ues[w::4],)) for w in range(4)]
    for t in workers:
        t.start()
    got = drain(link.ran_end, n * len(ues), timeout=30)
    for t in workers:
        t.join()
    assert len(got) == n * len(ues)
    for ue in ues:
        assert [int.from_bytes(e.payload[:4], 'big') for e in got if e.ue_id == ue] == list(range(n))
    # and back, interleaved, from the adapter's one sender, while the UE side reads
    got = []
    reader = threading.Thread(target=lambda: got.extend(drain(link.ue_end, n * len(ues), timeout=30)))
    reader.start()
    for i in range(n):
        for ue in ues:
            link.ran_end.send(DL_NAS, ue, i.to_bytes(4, 'big'), 0, float(i), [(87, float(i))])
    reader.join(30)
    for ue in ues:
        mine = [e for e in got if e.ue_id == ue]
        assert [int.from_bytes(e.payload, 'big') for e in mine] == list(range(n))
        assert [e.stamps for e in mine] == [[(87, float(i))] for i in range(n)]
    link.close()


def _ue_process(link, links, ues, n, results):
    """ A UE emulator in a process of its own: it sends n messages per UE and checks the answers,
    reading while it sends, as the UE simulator does """
    for other in links:
        if other is not link:
            other.close()
    link.ue_end.attach()
    got = []
    reader = threading.Thread(target=lambda: got.extend(drain(link.ue_end, n * len(ues), timeout=30)))
    reader.start()
    for i in range(n):
        for ue in ues:
            payload = i.to_bytes(4, 'big')
            if i == 0:
                link.ue_end.send(CONNECT, ue, ranlink.connect_payload(payload), 65)
            else:
                link.ue_end.send(UL_NAS, ue, payload, 66)
    reader.join(30)
    ok = (len(got) == n * len(ues) and all(e.ue_id in ues for e in got)
          and all([int.from_bytes(e.payload, 'big') for e in got if e.ue_id == ue] == list(range(n)) for ue in ues))
    results.put((tuple(ues), ok))


@pytest.mark.parametrize('link_type', LINKS)
def test_one_adapter_serves_several_links(link_type):
    """ Many-to-one: three UE-emulator processes, each on its own link, one adapter waiting on all of
    them and answering each UE on the link its messages came on """
    ctx = multiprocessing.get_context('fork')
    links = [link_type() for _ in range(3)]
    groups = [list(range(31 + 10 * k, 36 + 10 * k)) for k in range(3)]
    n = 100
    results = ctx.Queue()
    procs = [ctx.Process(target=_ue_process, args=(link, links, ues, n, results)) for link, ues in zip(links, groups)]
    for p in procs:
        p.start()
    for link in links:
        link.ran_end.attach()
    ends = [link.ran_end for link in links]
    waiter = ends[0].waiter(ends)
    owner, seen = {}, 0
    deadline = time.time() + 30
    while seen < 3 * 5 * n and time.time() < deadline:
        for end in waiter.wait(0.5):
            event = end.recv()
            assert owner.setdefault(event.ue_id, end) is end      # a UE stays on its link
            seen += 1
            payload = ranlink.parse_connect(event.payload)[2] if event.kind == CONNECT else event.payload
            owner[event.ue_id].send(DL_NAS, event.ue_id, payload, 0, time.time(), [(event.code, time.time())])
    assert seen == 3 * 5 * n
    assert {ue: ends.index(end) for ue, end in owner.items()} == {ue: k for k, ues in enumerate(groups) for ue in ues}
    outcome = dict(results.get(timeout=30) for _ in procs)
    for p in procs:
        p.join(10)
    assert outcome == {tuple(ues): True for ues in groups}
    # Each UE process has gone: its link ends at the adapter, which stops waiting on it
    closed = set()
    deadline = time.time() + 10
    while len(closed) < 3 and time.time() < deadline:
        for end in waiter.wait(0.5):
            with pytest.raises(LinkClosed):
                end.recv()
            waiter.remove(end)
            closed.add(id(end))
    assert len(closed) == 3 and len(waiter) == 0


def _fill(end, size=8192, limit=10000):
    """ Send frames until one blocks (in a thread); the thread, and the frames it sent """
    sent, done = [], threading.Event()
    errors = []

    def run():
        try:
            for i in range(limit):
                end.send(UL_NAS, 31, i.to_bytes(4, 'big') + bytes(size - 4), 87)
                sent.append(i)
        except Exception as e:
            errors.append(e)
        done.set()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    while True:                 # until the count stops growing: the link is full
        before = len(sent)
        time.sleep(0.2)
        if len(sent) == before:
            break
    return t, sent, done, errors


@pytest.mark.parametrize('link_type', LINKS)
def test_a_full_link_blocks_the_sender_then_drains(link_type):
    link = link_type(interval=0.05)
    t, sent, done, errors = _fill(link.ue_end, limit=2000)
    assert not done.is_set() and 0 < len(sent) < 2000     # blocked, not dropping
    got = drain(link.ran_end, 2000, timeout=30)
    t.join(10)
    assert done.is_set() and not errors
    assert [int.from_bytes(e.payload[:4], 'big') for e in got] == list(range(2000))
    link.close()


@pytest.mark.parametrize('link_type', LINKS)
def test_the_exit_flag_unblocks_a_blocked_sender(link_type):
    stop = threading.Event()
    link = link_type(stop=stop.is_set, interval=0.05)
    t, sent, done, errors = _fill(link.ue_end)
    assert not done.is_set()
    stop.set()
    assert done.wait(2)
    assert len(errors) == 1 and isinstance(errors[0], LinkStopped)
    # Nothing half sent: the frames sent before arrive whole, and the link still works
    got = drain(link.ran_end, len(sent))
    assert [int.from_bytes(e.payload[:4], 'big') for e in got] == sent
    stop.clear()
    link.ue_end.send(UL_NAS, 31, b'after', 87)
    assert link.ran_end.recv(1) == Event(UL_NAS, 31, b'after', 87)
    link.close()


@pytest.mark.parametrize('link_type', LINKS)
def test_the_exit_flag_unblocks_a_large_frame(link_type):
    stop = threading.Event()
    link = link_type(stop=stop.is_set, interval=0.05)
    t, sent, done, errors = _fill(link.ran_end, size=300000)
    stop.set()
    assert done.wait(2)
    assert len(errors) == 1 and isinstance(errors[0], LinkStopped)
    # The frames before it arrive whole; a frame cut short ends the link instead of garbling it
    got, ended = [], False
    deadline = time.time() + 3
    while time.time() < deadline:
        try:
            event = link.ue_end.recv(0.2)
        except LinkClosed:
            ended = True
            break
        if event is not None:
            got.append(event)
    assert [int.from_bytes(e.payload[:4], 'big') for e in got] == sent
    assert ended == link.ran_end.closed
    link.close()


def _send_then_exit(link, events):
    link.ue_end.attach()
    for event in events:
        link.ue_end.send(*event)


@pytest.mark.parametrize('link_type', LINKS)
def test_a_peers_exit_ends_the_link(link_type):
    ctx = multiprocessing.get_context('fork')
    link = link_type()
    events = [Event(UL_NAS, 31, b'last words', 87)]
    p = ctx.Process(target=_send_then_exit, args=(link, events))
    p.start()
    link.ran_end.attach()
    p.join(10)
    assert link.ran_end.recv(5) == events[0]       # what the peer sent still arrives
    with pytest.raises(LinkClosed):
        link.ran_end.recv(5)                         # then the end, not a block
    with pytest.raises(LinkClosed):
        link.ran_end.send(DL_NAS, 31, b'to no one')
    link.close()


@pytest.mark.parametrize('link_type', LINKS)
def test_closing_one_end_ends_the_other(link_type):
    link = link_type()
    link.ran_end.close()
    with pytest.raises(LinkClosed):
        link.ran_end.recv(0.1)                       # this end
    link.ue_end.attach()                             # the UE side's process lets go of the adapter's end
    with pytest.raises(LinkClosed):
        link.ue_end.recv(1)
    with pytest.raises(LinkClosed):
        link.ue_end.send(UL_NAS, 31, b'x', 87)
    link.close()
