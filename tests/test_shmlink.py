""" ShmLink's rings under stress (src/shmlink.py). G11's contract tests (tests/test_ranlink.py) run on
ShmLink as well; these look at what a ring adds:

- millions of small frames between two processes, every byte checked (torn or reordered indices
  would show as a frame that is not one, or the wrong one);
- the ring's end: frames that stop at, cross and fill it, and frames larger than the ring;
- a full ring: the producer sleeps and is woken by the consumer, not by its timeout;
- a producer killed mid-run, also in the middle of a frame larger than the ring;
- several sender threads on one end without a lock of their own;
- many links on one waiter;
- no lost wake-up in a long ping-pong where each side sleeps between messages;
- the 64-bit index words are read and written whole, across processes;
- the fence between a flag's store and an index's load (a Lock's acquire and release) orders them.

Run from the repository root (Linux on x86-64):

    python3 -m pytest tests/test_shmlink.py
"""
import gc
import mmap
import multiprocessing
import os
import random
import signal
import threading
import time

import pytest

from src import shmlink
from src.ranlink import DL_NAS, UL_NAS, Event, LinkClosed, LinkStopped, PipeLink, decode, encode
from src.shmlink import ShmLink

pytestmark = pytest.mark.skipif(not shmlink.supported(), reason='ShmLink needs Linux on x86-64')

ctx = multiprocessing.get_context('fork')


def frame_of(i):
    """ Frame i of a stream: its kind, UE, code and payload (8 to 120 bytes) follow from i """
    payload = i.to_bytes(8, 'little') * (1 + i % 15)
    return Event(UL_NAS if i % 2 else DL_NAS, i % 1000, payload, i % 65536)


def check_stream(end, n, timeout=120):
    """ Receive frames 0 .. n-1 in order on end, each byte as sent; the first mismatch, or None """
    deadline = time.time() + timeout
    i = 0
    while i < n:
        event = end.recv(1)
        if event is None:
            if time.time() > deadline:
                return f'only {i} of {n} frames came'
            continue
        if event != frame_of(i):
            return f'frame {i} is {event[:2]}, {len(event.payload)} bytes'
        i += 1
    return None


def _produce(link, n, mine):
    mine.attach()
    for i in range(n):
        mine.send(*frame_of(i))


@pytest.mark.parametrize('size', [4096, shmlink.RING_SIZE])
def test_millions_of_small_frames(size):
    """ Two million frames on a 4 KiB ring, a million on the default one, from a producer process, the
    consumer checking every frame: the small ring wraps every few dozen frames and keeps the producer
    waiting for room, the default one lets it run ahead """
    n = 2_000_000 if size == 4096 else 1_000_000
    link = ShmLink(size=size)
    p = ctx.Process(target=_produce, args=(link, n, link.ue_end))
    p.start()
    link.ran_end.attach()
    try:
        assert check_stream(link.ran_end, n) is None
        with pytest.raises(LinkClosed):
            link.ran_end.recv(10)             # then the producer has exited
    finally:
        p.join(10)
        link.close()


def test_frames_at_every_offset_of_the_ring_end():
    """ In one process, on a 256-byte ring: every frame length that fits (16 to 252 bytes, records of
    24 to 256 bytes), starting at every 8-byte offset before the ring's end, so that frames stop short
    of it, at it, cross it at every point, and fill the ring """
    link = ShmLink(size=256)
    ue, ran = link.ue_end, link.ran_end

    def move_to(offset):
        """ Fill the ring up to offset with records of 24 bytes or more """
        gap = (offset - ue._tail) % 256
        for rec in ([gap] if gap >= 24 else [128, gap + 128]) if gap else []:
            filler = encode(UL_NAS, 0, bytes(rec - 24))      # a frame of rec - 8 bytes: a record of rec
            ue.send_frame(filler)
            assert ran.recv(0) == decode(filler)
        assert ue._tail % 256 == offset

    sent = 0
    for offset in range(0, 256, 8):
        for n in range(16, 253):
            move_to(offset)
            payload = os.urandom(n - 16)
            ue.send(DL_NAS, 7, payload, 9)
            assert ran.recv(0) == Event(DL_NAS, 7, payload, 9)
            sent += 1
    assert sent == 32 * 237
    assert ran.recv(0) is None and ue._tail == ran._head
    link.close()


@pytest.mark.parametrize('n', [253, 256, 257, 1000, 3 * 256 + 5, 100000])
def test_frames_larger_than_the_ring_stream_through_it(n):
    """ A frame larger than the ring goes through it in pieces, a reader thread collecting them; small
    frames before and after it keep their place """
    link = ShmLink(size=256)
    events = [Event(UL_NAS, 1, b'before'), Event(DL_NAS, 2, os.urandom(n), 3, 1.5, [(65, 1.25)]),
              Event(UL_NAS, 3, b'after')]
    got = []

    def read():
        while len(got) < len(events):
            event = link.ran_end.recv(5)
            if event is None:
                return
            got.append(event)
    reader = threading.Thread(target=read)
    reader.start()
    for event in events:
        link.ue_end.send(*event)
    reader.join(10)
    assert got == events
    assert link.ran_end._partial is None
    link.close()


def test_a_full_ring_wakes_its_producer():
    """ The producer of a full ring sleeps until the consumer has made room: with a 60 s interval, only
    the consumer's wake-up can resume it in time. Also for a record of more than half the ring (woken
    again until it fits), and when the consumer empties the ring and then waits itself """
    for size, frame_len in ((4096, 100), (4096, 3000)):
        link = ShmLink(size=size, interval=60)
        frame = encode(UL_NAS, 1, bytes(frame_len - 16))
        sent = []
        t = threading.Thread(target=lambda: [link.ue_end.send_frame(frame) or sent.append(i) for i in range(200)],
                             daemon=True)
        t.start()
        deadline = time.time() + 5
        while link.ue_end._w[link.ue_end._o_wwait] == 0 and time.time() < deadline:
            time.sleep(0.01)
        assert link.ue_end._w[link.ue_end._o_wwait] == 1        # it waits for room
        start = time.time()
        got = 0
        while got < 200 and time.time() - start < 10:
            if link.ran_end.recv(1) is not None:
                got += 1
        t.join(5)
        assert got == 200 and len(sent) == 200 and time.time() - start < 5
        link.close()
    # The ring holds one record; the producer waits to send a record that needs all of it, which it
    # can once the consumer has taken that one
    link = ShmLink(size=4096, interval=60)
    link.ue_end.send_frame(encode(UL_NAS, 1, bytes(100)))
    big = encode(UL_NAS, 2, bytes(4096 - 4 - 16))
    t = threading.Thread(target=link.ue_end.send_frame, args=(big,), daemon=True)
    t.start()
    time.sleep(0.2)
    assert t.is_alive()
    start = time.time()
    assert link.ran_end.recv(5).ue_id == 1
    assert link.ran_end.recv(5).ue_id == 2
    t.join(5)
    assert time.time() - start < 2
    link.close()


def _send_forever(link, size):
    link.ue_end.attach()
    i = 0
    while True:
        link.ue_end.send(UL_NAS, 1, i.to_bytes(8, 'little') + bytes(size), 87)
        i += 1


@pytest.mark.parametrize('size', [40, 1000, 5000])
def test_a_producer_killed_mid_run(size):
    """ SIGKILL to a producer sending as fast as it can: every frame it published arrives whole and in
    order, then the link ends (the socket's end of file: no closed flag was set). With 5000-byte frames
    on a 4 KiB ring it dies in the middle of a frame, which is not delivered. """
    link = ShmLink(size=4096)
    p = ctx.Process(target=_send_forever, args=(link, size))
    p.start()
    link.ran_end.attach()
    got = 0
    killed = False
    start = time.time()
    with pytest.raises(LinkClosed):
        while time.time() - start < 30:
            event = link.ran_end.recv(1)
            if event is None:
                continue
            assert int.from_bytes(event.payload[:8], 'little') == got and len(event.payload) == size + 8
            got += 1
            if got == 2000 and not killed:
                os.kill(p.pid, signal.SIGKILL)
                killed = True
    p.join(5)
    assert killed and got >= 2000 and link.ran_end._partial is None
    assert link.ran_end._w[shmlink._CLOSED[shmlink.UE]] == 0   # seen through the socket, not a flag
    link.close()


def _wait_then_answer(link, n, then_sleep=False):
    link.ran_end.attach()
    waiter = link.ran_end.waiter([link.ran_end])
    for _ in range(n):
        while not waiter.wait(5):
            pass
        event = link.ran_end.recv()
        link.ran_end.send(DL_NAS, event.ue_id, event.payload, 0, 1.0, [(event.code, 2.0)])
    if then_sleep:
        time.sleep(60)


@pytest.mark.parametrize('killed', [False, True])
def test_the_gnb_sides_exit_ends_the_ue_sides_wait(killed):
    """ The UE side waits in recv() while the gNB side's process exits, or is killed: LinkClosed at
    once, for its sends too """
    link = ShmLink()
    p = ctx.Process(target=_wait_then_answer, args=(link, 10, killed))
    p.start()
    link.ue_end.attach()
    for i in range(10):
        link.ue_end.send(UL_NAS, i, b'x', 87)
        assert link.ue_end.recv(5) == Event(DL_NAS, i, b'x', 0, 1.0, [(87, 2.0)])
    if killed:
        threading.Timer(0.3, os.kill, (p.pid, signal.SIGKILL)).start()
    start = time.monotonic()
    with pytest.raises(LinkClosed):
        link.ue_end.recv(20)
    assert time.monotonic() - start < 5
    with pytest.raises(LinkClosed):
        link.ue_end.send(UL_NAS, 1, b'x', 87)
    p.join(5)
    link.close()


def test_no_lost_wake_up_in_a_long_ping_pong():
    """ 100,000 round trips, each side sleeping between messages (the UE side in recv, the gNB side in
    its waiter): a lost wake-up would stall a round trip for the 5 s timeout """
    n = 100_000
    link = ShmLink()
    p = ctx.Process(target=_wait_then_answer, args=(link, n))
    p.start()
    link.ue_end.attach()
    worst = 0.0
    start = time.time()
    for i in range(n):
        t = time.monotonic()
        link.ue_end.send(UL_NAS, i % 1000, i.to_bytes(4, 'little'), 87)
        event = link.ue_end.recv(5)
        assert event is not None and event.payload == i.to_bytes(4, 'little')
        worst = max(worst, time.monotonic() - t)
    p.join(10)
    assert worst < 1.0, f'a round trip took {worst:.3f} s'
    assert time.time() - start < 60
    link.close()


def _send_on_threads(link, threads, n):
    link.ue_end.attach()

    def worker(k):
        for i in range(n):
            link.ue_end.send(UL_NAS, k, i.to_bytes(4, 'little'), 87)     # no lock of the caller's
    ts = [threading.Thread(target=worker, args=(k,)) for k in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


def test_concurrent_senders_on_one_end():
    """ Four threads send on the UE end at once, with no lock of their own (the end's send lock):
    nothing is lost or mixed, each thread's order is kept """
    threads, n = 4, 50_000
    link = ShmLink(size=8192)
    p = ctx.Process(target=_send_on_threads, args=(link, threads, n))
    p.start()
    link.ran_end.attach()
    seen = [0] * threads
    for _ in range(threads * n):
        event = link.ran_end.recv(10)
        assert event is not None
        assert int.from_bytes(event.payload, 'little') == seen[event.ue_id]
        seen[event.ue_id] += 1
    assert seen == [n] * threads
    p.join(10)
    link.close()


def _send_on_many(links, n):
    for link in links:
        link.ue_end.attach()

    def worker(k):
        for i in range(n):
            links[k].ue_end.send(UL_NAS, k, i.to_bytes(4, 'little'), 87)
    ts = [threading.Thread(target=worker, args=(k,)) for k in range(len(links))]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


def test_many_links_on_one_waiter():
    """ Sixteen links, their producers threads of one process, one waiter on their adapter ends; when
    the process exits, each link ends and leaves the waiter """
    k, n = 16, 5000
    links = [ShmLink(size=4096) for _ in range(k)]
    p = ctx.Process(target=_send_on_many, args=(links, n))
    p.start()
    ends = [link.ran_end for link in links]
    for end in ends:
        end.attach()
    waiter = ends[0].waiter(ends)
    seen = [0] * k
    deadline = time.time() + 60
    while sum(seen) < k * n and time.time() < deadline:
        for end in waiter.wait(1):
            event = end.recv()
            assert end is ends[event.ue_id]
            assert int.from_bytes(event.payload, 'little') == seen[event.ue_id]
            seen[event.ue_id] += 1
    assert seen == [n] * k
    p.join(10)
    while len(waiter) and time.time() < deadline:
        for end in waiter.wait(1):
            with pytest.raises(LinkClosed):
                end.recv()
            waiter.remove(end)
    assert len(waiter) == 0
    for link in links:
        link.close()


def test_a_waiter_times_out_and_takes_one_link_type():
    link = ShmLink()
    waiter = link.ran_end.waiter([link.ran_end])
    start = time.monotonic()
    assert waiter.wait(0.2) == []
    assert 0.15 < time.monotonic() - start < 1
    pipe = PipeLink()
    with pytest.raises(TypeError, match='one link type'):
        waiter.add(pipe.ran_end)
    with pytest.raises(TypeError, match='one link type'):
        pipe.ran_end.waiter([pipe.ran_end, link.ran_end])
    link.close()
    pipe.close()


WORD = 120     # a word no ring uses (byte 960 of the header)


def _write_patterns(words, stop_at):
    a, b = 0x0123456789ABCDEF, 0xFEDCBA9876543210
    while time.time() < stop_at:
        for _ in range(10000):
            words[WORD] = a
            words[WORD] = b


def test_index_words_are_read_and_written_whole():
    """ A process writes two 64-bit values that differ in every byte into one index word as fast as it
    can, another reads it: never a mix of the two (a store or load in pieces would show at once) """
    link = ShmLink()
    words = link._shared.words
    words[WORD] = 0x0123456789ABCDEF
    stop_at = time.time() + 1.0
    p = ctx.Process(target=_write_patterns, args=(words, stop_at))
    p.start()
    ok = {0x0123456789ABCDEF, 0xFEDCBA9876543210}
    reads = 0
    bad = set()
    while time.time() < stop_at:
        for _ in range(10000):
            v = words[WORD]
            if v not in ok:
                bad.add(v)
        reads += 10000
    p.join(5)
    assert not bad and reads > 100000
    link.close()


X, Y, GO, R1, ACK, READY, NEXT, STOP = (8 * k for k in range(8))     # words, each on a cache line of its own


def _store_buffering_p1(m, cpu):
    """ P1 of the store-buffering litmus: y = 1; fence; r1 = x """
    os.sched_setaffinity(0, {cpu})
    fence = threading.Lock()
    rnd = random.Random(1).randrange
    i = 1
    while True:
        d = rnd(3)
        while m[NEXT] != i - 1:              # P0 has read its r0 of the last round
            if m[STOP]:
                os._exit(0)
        m[Y] = 0
        m[READY] = i
        while m[GO] != i:
            m[X]                             # x's line in this core's cache: P0's store must fetch it
            if m[STOP]:
                os._exit(0)
        for _ in range(d):
            pass
        m[Y] = 1
        fence.acquire()
        fence.release()
        m[R1] = m[X]
        m[ACK] = i
        i += 1


@pytest.mark.skipif(len(os.sched_getaffinity(0)) < 2, reason='needs two CPUs')
def test_the_fence_orders_a_store_before_a_load():
    """ The store-buffering litmus on shared memory, in two processes on two CPUs:
        P0: x = 1; fence; r0 = y        P1: y = 1; fence; r1 = x
    r0 == r1 == 0 needs a load performed before the older store is seen, which x86-64 allows: it would
    be a lost wake-up between a waiting flag and an index. With ShmLink's fence (a process-local Lock's
    acquire and release) it must never happen. Without the fence this harness saw it 26 times in 10**6
    rounds on the development host. Runs for about two seconds. """
    cpus = sorted(os.sched_getaffinity(0))
    m = memoryview(mmap.mmap(-1, 4096)).cast('Q')
    p = ctx.Process(target=_store_buffering_p1, args=(m, cpus[-1]), daemon=True)
    p.start()
    mine = os.sched_getaffinity(0)
    os.sched_setaffinity(0, {cpus[-2]})
    fence = threading.Lock()
    rnd = random.Random(2).randrange
    both = rounds = 0
    stop_at = time.monotonic() + 2.0
    try:
        for i in range(1, 10**7):
            if time.monotonic() > stop_at:
                break
            d = rnd(3)
            m[X] = 0
            while m[READY] != i:
                m[Y]
            m[GO] = i                            # P1 goes
            for _ in range(d):
                pass
            m[X] = 1
            fence.acquire()
            fence.release()
            r0 = m[Y]
            while m[ACK] != i:
                pass
            both += r0 == 0 and m[R1] == 0
            rounds += 1
            m[NEXT] = i
    finally:
        m[STOP] = 1
        os.sched_setaffinity(0, mine)
        p.join(5)
    assert rounds > 10000
    assert both == 0, f'r0 == r1 == 0 in {both} of {rounds} rounds'


def test_the_exit_flag_ends_a_large_frame_cut_short():
    """ stop() while a frame larger than the ring is half through it closes the producer's end; the
    consumer gets LinkClosed, not half a frame """
    stop = threading.Event()
    link = ShmLink(stop=stop.is_set, interval=0.05, size=4096)
    errors = []

    def send():
        try:
            link.ue_end.send(UL_NAS, 1, bytes(10000))
        except Exception as e:
            errors.append(e)
    t = threading.Thread(target=send)
    t.start()
    time.sleep(0.2)
    stop.set()
    t.join(2)
    assert len(errors) == 1 and isinstance(errors[0], LinkStopped) and link.ue_end.closed
    with pytest.raises(LinkClosed):
        while True:
            assert link.ran_end.recv(1) is None
    link.close()


def test_closing_lets_go_of_the_link_in_this_process_only():
    """ ShmLink.close() (a process that uses neither end) closes this process's descriptors and the
    mapping, and does not end the link for the processes that use it; nothing is left in /dev/shm """
    def fds():
        return set(os.listdir('/proc/self/fd'))
    gc.collect()
    before = fds()
    shm_before = set(os.listdir('/dev/shm')) if os.path.isdir('/dev/shm') else set()
    link = ShmLink()
    assert len(fds() - before) >= 6          # four eventfds, two sockets
    words = link._shared.words
    link.close()
    assert fds() - before == set()
    with pytest.raises(LinkClosed):
        link.ue_end.recv(0)
    with pytest.raises(LinkClosed):
        link.ran_end.send(DL_NAS, 1, b'x')
    with pytest.raises(ValueError):
        words[0]                              # released
    if os.path.isdir('/dev/shm'):
        assert set(os.listdir('/dev/shm')) == shm_before


def test_a_link_is_inherited_not_pickled():
    import pickle
    link = ShmLink()
    for obj in (link, link.ue_end, link.ran_end):
        with pytest.raises(TypeError, match='fork'):
            pickle.dumps(obj)
    link.close()


def test_only_where_the_rings_are_ordered(monkeypatch):
    monkeypatch.setattr(shmlink.platform, 'machine', lambda: 'aarch64')
    assert not shmlink.supported()
    with pytest.raises(RuntimeError, match='x86-64'):
        ShmLink()
    monkeypatch.undo()
    for size in (32, 1000, 3 * 4096):
        with pytest.raises(ValueError, match='power of two'):
            ShmLink(size=size)
