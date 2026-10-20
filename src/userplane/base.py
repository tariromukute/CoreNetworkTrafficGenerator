""" What a user plane provider is given, and what it must do with it. """
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class Session:
    """ A PDU session that is up: what a generator needs to send the UE's traffic. """
    supi: Optional[str]
    ue_ip: str
    pdu_session_id: Optional[int]
    ul_teid: int                    # the UPF's uplink F-TEID
    qfi: int
    upf_address: Optional[str]      # the UPF's N3 address
    dl_teid: Optional[int]          # the gNB's downlink F-TEID
    gnb_address: Optional[str]      # the gNB's N3 address given to the 5GC (gtpIp)
    ran_ue_ngap_id: int
    amf_ue_ngap_id: Optional[int]
    t: float                        # when the gNB learned the session was up

    @property
    def key(self) -> str:
        return f"{self.ran_ue_ngap_id}-{self.pdu_session_id}"


@dataclass
class Context:
    """ What the providers may need to know about the traffic generator itself. """
    folder: str                     # the output directory (-f)
    verbose: int = 0
    num_pkts: int = 1 << 20         # -n, the XDP generator's packets per second
    num_cpus: int = 1


class UserPlaneProvider(ABC):
    """ Gives PDU sessions user plane traffic, or records them for something else to.

    A provider is created and used in the user plane process only (see UserPlane), one call at
    a time, so it needs no locking. add_session() is called once per session as it comes up,
    remove_session() when the gNB releases the UE. An exception in a call is logged and the
    session stays with the other providers. """

    def __init__(self, config: dict, context: Context):
        self.config = config
        self.context = context

    def start(self) -> None:
        """ Called once, before the first session. """

    @abstractmethod
    def add_session(self, session: Session) -> None:
        """ Start the session's traffic (or record it). """

    def remove_session(self, session: Session) -> None:
        """ Stop the session's traffic. """

    def stats(self) -> dict:
        return {}

    def stop(self) -> None:
        """ Called once, at the end of the run: stop all traffic, release resources. """
