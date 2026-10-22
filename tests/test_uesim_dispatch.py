""" UESim's downlink dispatch: a UE's messages are handled in order, by one worker at a time.

Run from the repository root (needs pycrate and CryptoMobile, as src/UESim.py does):

    python3 -m pytest tests/test_uesim_dispatch.py
"""
import random
import threading
import time
from multiprocessing import Pipe, Value

from src.UESim import UESim


def make_sim():
    gnb_end, sim_end = Pipe(duplex=True)
    sim = UESim.__new__(UESim)               # only what the dispatch uses
    sim.ue_to_ngap = sim_end
    sim.exit_program = Value('i', 0)
    sim.send_lock = threading.Lock()
    sim.worker_queues = []
    return sim, gnb_end


def test_each_ues_messages_are_handled_in_order_by_one_worker():
    sim, gnb = make_sim()
    seen, seen_lock = [], threading.Lock()

    def handle(data, ue_id, received_at=None):
        time.sleep(random.random() / 1000)   # interleave the workers
        with seen_lock:
            seen.append((ue_id, data, threading.current_thread().name))
    sim._handle_downlink = handle
    sim._load_ngap_to_ue_thread()

    ues, n = (31, 32, 33), 50
    for i in range(n):
        for ue in ues:
            gnb.send((f"m{i}".encode(), ue))
    deadline = time.time() + 10
    while len(seen) < n * len(ues) and time.time() < deadline:
        time.sleep(0.01)
    sim.exit_program.value = 1

    assert len(seen) == n * len(ues)
    for ue in ues:
        mine = [(d, t) for u, d, t in seen if u == ue]
        assert [d for d, _ in mine] == [f"m{i}".encode() for i in range(n)]   # in order
        assert len({t for _, t in mine}) == 1                                  # one worker


def test_a_failing_message_does_not_stop_the_worker():
    sim, gnb = make_sim()
    handled = []

    def handle(data, ue_id, received_at=None):
        if data == b"bad":
            raise ValueError("malformed")
        handled.append(data)
    sim._handle_downlink = handle
    sim._load_ngap_to_ue_thread()

    for data in (b"one", b"bad", b"two"):
        gnb.send((data, 31))
    deadline = time.time() + 5
    while len(handled) < 2 and time.time() < deadline:
        time.sleep(0.01)
    sim.exit_program.value = 1
    assert handled == [b"one", b"two"]


def test_the_gnbs_receive_time_reaches_the_handler():
    sim, gnb = make_sim()
    got = []
    sim._handle_downlink = lambda data, ue_id, received_at=None: got.append((data, received_at))
    sim._load_ngap_to_ue_thread()

    gnb.send((b"stamped", 31, 1234.5))
    gnb.send((b"unstamped", 32))           # an older gNB: the UE simulator takes the time itself
    deadline = time.time() + 5
    while len(got) < 2 and time.time() < deadline:
        time.sleep(0.01)
    sim.exit_program.value = 1
    assert sorted(got) == [(b"stamped", 1234.5), (b"unstamped", None)]
