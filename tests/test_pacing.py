""" When UEs start: the absolute schedule and the closed loop's limit on UEs in flight.

Run from the repository root:

    python3 -m pytest tests/test_pacing.py
"""
import random
import threading
import time

from src.pacing import InFlight, start_offsets


def test_fixed_interval():
    assert start_offsets(4, 0.5) == [0.0, 0.5, 1.0, 1.5]


def test_all_at_once():
    assert start_offsets(3, 0) == [0.0, 0.0, 0.0]


def test_poisson_mean_gap_and_repeatability():
    a = start_offsets(20000, 0.02, poisson=True, rng=random.Random(1))
    b = start_offsets(20000, 0.02, poisson=True, rng=random.Random(1))
    assert a == b
    gaps = [y - x for x, y in zip(a, a[1:])]
    assert abs(sum(gaps) / len(gaps) - 0.02) < 0.02 * 0.03
    assert len(set(gaps)) > 1


def test_inflight_blocks_until_a_ue_finishes():
    inflight = InFlight(2, timeout=60)
    assert inflight.acquire(1) and inflight.acquire(2)
    started = threading.Event()
    threading.Thread(target=lambda: inflight.acquire(3) and started.set(), daemon=True).start()
    assert not started.wait(0.2)                  # a third would exceed the limit
    assert inflight.release(1)
    assert started.wait(2)
    assert not inflight.release(1)                # released once only


def test_inflight_acquire_stops():
    inflight = InFlight(1, timeout=60)
    assert inflight.acquire(1)
    assert not inflight.acquire(2, stop=lambda: True)


def test_inflight_expires_lost_ues():
    now = [100.0]
    inflight = InFlight(2, timeout=10, clock=lambda: now[0])
    inflight.acquire(1)
    now[0] = 105.0
    inflight.acquire(2)
    now[0] = 111.0
    assert inflight.expire() == [1]               # 11 s late; UE 2 only 6 s
    assert not inflight.release(1)
    assert inflight.acquire(3)                     # its place is free again
