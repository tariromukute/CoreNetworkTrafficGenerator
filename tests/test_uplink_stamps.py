""" Uplink messages are timed when the gNB sends them: the gNB returns the time with the UE's next
downlink message, and the UE simulator records it in place of the time the message was built.

Run from the repository root (needs pycrate and CryptoMobile, as src/UESim.py does):

    python3 -m pytest tests/test_uplink_stamps.py
"""
import threading
from types import SimpleNamespace

import src.UESim
from src.NGAPSim import GNB
from src.UESim import UESim


def make_gnb():
    gnb = GNB.__new__(GNB)                 # only what the stamps use
    gnb.ul_sent, gnb.ul_sent_lock = {}, threading.Lock()
    return gnb


def test_the_gnb_returns_each_ues_stamps_once_in_order():
    gnb = make_gnb()
    gnb._stamp_uplink(7, 65, 1.0)
    gnb._stamp_uplink(8, 65, 2.0)
    gnb._stamp_uplink(7, 67, 3.0)
    assert gnb._take_uplink_stamps(7) == [(65, 1.0), (67, 3.0)]
    assert gnb._take_uplink_stamps(7) == []
    assert gnb._take_uplink_stamps(8) == [(65, 2.0)]


def test_the_ue_simulator_records_the_gnbs_send_times(monkeypatch):
    monkeypatch.setattr(src.UESim, 'g_verbose', 1, raising=False)
    ue = SimpleNamespace(procedure_times={65: 0.5, 67: 0.75})
    ue.next_action = lambda data, msg_type: (None, ue, None)
    sim = UESim.__new__(UESim)
    sim.ue_list = {7: ue}

    sim.dispatcher(b'F', 7, 2.0, [(65, 1.0)])   # a Connection Release: no parse needed
    assert ue.procedure_times == {65: 1.0, 67: 0.75}
    sim.dispatcher(b'F', 7, 3.0)                # an older gNB: the times stay as built
    assert ue.procedure_times == {65: 1.0, 67: 0.75}
