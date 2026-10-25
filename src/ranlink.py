""" The UE-RAN link: the events between CN-TG's UE emulator and a RAN-side adapter.

The UE emulator (NAS and the UE's state machine) is the same in every mode. It talks to a RAN adapter
through a link, the UE's NAS-AS boundary: today's gNB (src/NGAPSim.py) towards an AMF, later an F1
adapter (the UEs' RRC and PDCP, and a DU) towards a CU. A link has two ends:

    RanLink   the UE emulator's end: it sends CONNECT, UL_NAS, UP_CONTROL ... and receives DL_NAS, RELEASE ...
    UeLink    the adapter's end, one per UE-emulator process; an adapter may serve several (many-to-one)
              and waits on all of them at once (UeLink.waiter())

Events (a frame each):

    CONNECT     UE to RAN   connection setup: establishment cause, 5G-S-TMSI if any, the initial NAS PDU
    UL_NAS      UE to RAN   a NAS PDU
    DL_NAS      RAN to UE   a NAS PDU, when the RAN received it, the UE's pending uplink send times
    SECURITY    both        AS security: started (RAN to UE); K_gNB, 32 octets (UE to RAN)
    RELEASE     both        connection release, an optional cause (today's b'F' from the gNB)
    DATA        both        PDU session ID, QFI and an IP packet
    UP_CONTROL  UE to RAN   CN-TG's user-plane request: a PDU session's address (today's ue_to_upf messages)

A frame, in native byte order (both ends are on one host):

    offset  size  field
    0       1     version (1)
    1       1     kind
    2       2     flags (bit 0: received_at present; bit 1: uplink stamps follow the payload)
    4       4     UE id (the RAN-UE-NGAP-ID for the gNB adapter)
    8       2     message code (5GMM/5GSM type, as the UE simulator's msg_code; 0 if none)
    10      2     reserved
    12      4     payload length
    16      8     received_at (double, seconds), with flag 0
    ...           the payload
    ...           with flag 1: a count (u16) and that many (message code u16, time double) pairs

Semantics: reliable and ordered per UE in each direction; a full link blocks the sender until it
drains, or until the run's exit flag (stop) is set, checked every interval seconds; nothing is
dropped; either side's close() ends the link, and the peer gets LinkClosed instead of blocking.

PipeLink carries the frames over a multiprocessing.Pipe (send_bytes/recv_bytes). A ShmLink (rings in
shared memory, eventfd wake-ups) or a SocketLink (an adapter on another host, network byte order)
implements the same ends.
"""
import os
import select
import socket
import struct
from multiprocessing import Pipe
from typing import NamedTuple, Optional

VERSION = 1

# Event kinds
CONNECT = 1
UL_NAS = 2
DL_NAS = 3
SECURITY = 4
RELEASE = 5
DATA = 6
UP_CONTROL = 7
KIND_NAMES = {CONNECT: 'CONNECT', UL_NAS: 'UL_NAS', DL_NAS: 'DL_NAS', SECURITY: 'SECURITY',
              RELEASE: 'RELEASE', DATA: 'DATA', UP_CONTROL: 'UP_CONTROL'}

# Flags
F_RECEIVED_AT = 0x1
F_STAMPS = 0x2

# RRC establishment causes, numbered as TS 38.331's EstablishmentCause and TS 38.413's
# RRCEstablishmentCause enumerate them
EMERGENCY = 0
HIGH_PRIORITY_ACCESS = 1
MT_ACCESS = 2
MO_SIGNALLING = 3
MO_DATA = 4
MO_VOICE_CALL = 5
MO_VIDEO_CALL = 6
MO_SMS = 7
MPS_PRIORITY_ACCESS = 8
MCS_PRIORITY_ACCESS = 9

# UP_CONTROL requests
UP_SESSION = 1      # a PDU session is up at this address: start its traffic

HEADER = struct.Struct('=BBHIHHI')
_TIME = struct.Struct('=d')
_COUNT = struct.Struct('=H')
_STAMP = struct.Struct('=Hd')
_CONNECT = struct.Struct('=BB6s')       # cause, 5G-S-TMSI present, 5G-S-TMSI
_UP_CONTROL = struct.Struct('=BB')      # request, address length; then the address and the SUPI
_DATA = struct.Struct('=BB')            # PDU session ID, QFI; then the IP packet
_pack_header = HEADER.pack
_unpack_header = HEADER.unpack_from
_pack_time = _TIME.pack
_pack_count = _COUNT.pack
_pack_stamp = _STAMP.pack
_NO_S_TMSI = bytes(6)

# The header of a plain 5GMM message (TS 24.501 §9.1.1, §9.3): the extended protocol discriminator,
# the security header type (low half of the second octet) and the message type.
FGMM_EPD = 0x7E
FGMM_REGISTRATION_REQUEST = 0x41


def is_plain_registration_request(nas_pdu: bytes) -> bool:
    """ The UE's initial Registration Request starts a connection (CONNECT: the gNB's Initial UE
    Message); every other NAS message goes in UL_NAS (an Uplink NAS Transport). Read from the header,
    without parsing the message. """
    return (len(nas_pdu) >= 3 and nas_pdu[0] == FGMM_EPD and nas_pdu[1] & 0x0F == 0
            and nas_pdu[2] == FGMM_REGISTRATION_REQUEST)


class FrameError(ValueError):
    """ A frame that is not one: another version, an unknown kind, a wrong length """


class LinkClosed(Exception):
    """ The link has ended: the peer closed its end (or exited), or this end was closed """


class LinkStopped(Exception):
    """ A send blocked on a full link gave up because the run is ending (stop() became true) """


class Event(NamedTuple):
    """ An event, its fields in the order encode() and send() take them """
    kind: int
    ue_id: int
    payload: bytes = b''
    code: int = 0
    received_at: Optional[float] = None
    stamps: Optional[list] = None   # [(message code, time), ...], oldest first


def encode(kind, ue_id, payload=b'', code=0, received_at=None, stamps=None) -> bytes:
    """ The frame of an event. received_at and stamps are sent when not None (stamps may be empty). """
    if received_at is None and stamps is None:
        return _pack_header(VERSION, kind, 0, ue_id, code, 0, len(payload)) + payload
    flags = 0
    parts = [b'']
    if received_at is not None:
        flags = F_RECEIVED_AT
        parts.append(_pack_time(received_at))
    parts.append(payload)
    if stamps is not None:
        flags |= F_STAMPS
        parts.append(_pack_count(len(stamps)))
        parts.extend([_pack_stamp(c, t) for c, t in stamps])
    parts[0] = _pack_header(VERSION, kind, flags, ue_id, code, 0, len(payload))
    return b''.join(parts)


def decode(buf) -> Event:
    """ The event in a frame (bytes or a memoryview); the payload is a bytes copy. """
    try:
        version, kind, flags, ue_id, code, _, length = _unpack_header(buf, 0)
    except struct.error:
        raise FrameError(f"a frame of {len(buf)} bytes is shorter than its header") from None
    if version != VERSION:
        raise FrameError(f"frame version {version}, not {VERSION}")
    if kind not in KIND_NAMES:
        raise FrameError(f"unknown event kind {kind}")
    off = 16
    received_at = None
    if flags & F_RECEIVED_AT:
        if len(buf) < 24:
            raise FrameError("a frame without its received_at")
        received_at = _TIME.unpack_from(buf, 16)[0]
        off = 24
    end = off + length
    stamps = None
    if flags & F_STAMPS:
        if len(buf) < end + 2:
            raise FrameError("a frame without its uplink stamps")
        n = _COUNT.unpack_from(buf, end)[0]
        if len(buf) != end + 2 + 10 * n:
            raise FrameError(f"a frame of {len(buf)} bytes, not {end + 2 + 10 * n}")
        stamps = [_STAMP.unpack_from(buf, end + 2 + 10 * i) for i in range(n)]
    elif len(buf) != end:
        raise FrameError(f"a frame of {len(buf)} bytes, not {end}")
    return Event(kind, ue_id, bytes(buf[off:end]), code, received_at, stamps)


# The payloads that have a structure

def connect_payload(nas_pdu: bytes, cause=MO_SIGNALLING, s_tmsi: Optional[bytes] = None) -> bytes:
    """ CONNECT's payload: the establishment cause, the 5G-S-TMSI (6 octets: AMF Set ID, AMF Pointer,
    5G-TMSI) when the UE has a 5G-GUTI, and the initial NAS PDU """
    if s_tmsi is not None and len(s_tmsi) != 6:
        raise ValueError(f"a 5G-S-TMSI has 6 octets, not {len(s_tmsi)}")
    return _CONNECT.pack(cause, s_tmsi is not None, s_tmsi or _NO_S_TMSI) + nas_pdu


def parse_connect(payload: bytes):
    """ (establishment cause, 5G-S-TMSI or None, NAS PDU) from CONNECT's payload """
    if len(payload) < 8:
        raise FrameError(f"a CONNECT payload of {len(payload)} bytes")
    cause, present, s_tmsi = _CONNECT.unpack_from(payload, 0)
    return cause, (s_tmsi if present else None), payload[8:]


def up_control_payload(address: bytes, supi: Optional[str] = None, request=UP_SESSION) -> bytes:
    """ UP_CONTROL's payload: the request, the PDU session's address (4 or 16 octets) and the SUPI """
    return _UP_CONTROL.pack(request, len(address)) + address + (supi or '').encode()


def parse_up_control(payload: bytes):
    """ (request, address, SUPI or None) from UP_CONTROL's payload """
    if len(payload) < 2 or len(payload) < 2 + payload[1]:
        raise FrameError(f"an UP_CONTROL payload of {len(payload)} bytes")
    request, n = _UP_CONTROL.unpack_from(payload, 0)
    return request, payload[2:2 + n], (payload[2 + n:].decode() or None)


def data_payload(pdu_session_id: int, qfi: int, packet: bytes) -> bytes:
    """ DATA's payload: the PDU session ID, the QoS flow and the IP packet """
    return _DATA.pack(pdu_session_id, qfi) + packet


def parse_data(payload: bytes):
    """ (PDU session ID, QFI, IP packet) from DATA's payload """
    if len(payload) < 2:
        raise FrameError(f"a DATA payload of {len(payload)} bytes")
    pdu_session_id, qfi = _DATA.unpack_from(payload, 0)
    return pdu_session_id, qfi, payload[2:]


# The link's ends

class Endpoint:
    """ One end of a link. send() blocks while the link is full; recv() returns None on a timeout and
    raises LinkClosed once the link has ended. One thread sends and one receives at a time (the UE
    simulator's workers send under a lock). """

    def send(self, kind, ue_id, payload=b'', code=0, received_at=None, stamps=None):
        raise NotImplementedError

    def recv(self, timeout=None) -> Optional[Event]:
        raise NotImplementedError

    def fileno(self) -> int:
        """ A descriptor that polls readable when an event (or the link's end) is there """
        raise NotImplementedError

    def attach(self):
        """ Called in the process that uses this end: it lets go of the peer's end there, so that the
        peer's exit ends the link """

    def close(self):
        raise NotImplementedError


class RanLink(Endpoint):
    """ The UE emulator's end of a link: it sends CONNECT, UL_NAS, UP_CONTROL (and SECURITY, RELEASE,
    DATA) and receives DL_NAS, RELEASE (and SECURITY, DATA). UE ids are the emulator's own. """


class UeLink(Endpoint):
    """ A RAN adapter's end of a link to one UE-emulator process. UE ids are scoped to their link: the
    adapter keys its UEs by (link, UE id). """

    @classmethod
    def waiter(cls, links):
        """ A Waiter on these links of this kind, for an adapter that serves several """
        return PollWaiter(links)


class Waiter:
    """ Waits on several of an adapter's links at once """

    def __init__(self, links=()):
        self.links = []
        for link in links:
            self.add(link)

    def add(self, link):
        self.links.append(link)

    def remove(self, link):
        self.links.remove(link)

    def wait(self, timeout=None) -> list:
        """ The links with an event (or their end) to read, at most after timeout seconds """
        raise NotImplementedError

    def __len__(self):
        return len(self.links)


class PollWaiter(Waiter):
    """ One poll() on the links' descriptors (a pipe end, an eventfd, a socket), as
    multiprocessing.connection.wait() does, with the poll object kept from one wait to the next """

    def __init__(self, links=()):
        self._poll = select.poll()
        self._by_fd = {}
        super().__init__(links)

    def add(self, link):
        fd = link.fileno()
        self._poll.register(fd, select.POLLIN)
        self._by_fd[fd] = link
        super().add(link)

    def remove(self, link):
        for fd, other in list(self._by_fd.items()):
            if other is link:
                self._poll.unregister(fd)
                del self._by_fd[fd]
        super().remove(link)

    def wait(self, timeout=None) -> list:
        by_fd = self._by_fd
        return [by_fd[fd] for fd, _ in self._poll.poll(None if timeout is None else timeout * 1000)]


# PipeLink: the frames over a multiprocessing.Pipe

def _set_send_timeout(fd, seconds):
    """ A blocking send on the socket gives up after seconds (SO_SNDTIMEO), so that a sender blocked
    on a full link can look at the exit flag """
    sk = socket.socket(fileno=fd)
    try:
        sec = int(seconds)
        sk.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                      struct.pack('ll', sec, int((seconds - sec) * 1e6)))
    finally:
        sk.detach()


# Connection.send_bytes() writes the length and a frame of at most this size in one write(), which the
# kernel takes whole or not at all; a larger frame goes in two (multiprocessing/connection.py)
_ONE_WRITE = 16384


class PipeEndpoint(Endpoint):
    """ One end of a PipeLink: a multiprocessing Connection, and the peer's Connection in this process
    until attach() closes it """

    def __init__(self, conn, peer_conn, stop=None):
        self._conn = conn
        self._peer_conn = peer_conn
        self._stop = stop
        self._fd = conn.fileno()
        self._poll = select.poll()
        self._poll.register(self._fd, select.POLLIN)

    def fileno(self):
        return self._fd

    @property
    def closed(self):
        return self._conn.closed

    def attach(self):
        self._peer_conn.close()

    def close(self):
        self._conn.close()

    def send(self, kind, ue_id, payload=b'', code=0, received_at=None, stamps=None):
        self.send_frame(encode(kind, ue_id, payload, code, received_at, stamps))

    def send_frame(self, frame):
        """ Send a frame; while the link is full, block until it drains or stop() """
        if len(frame) > _ONE_WRITE:
            return self._send_large(frame)
        send_bytes = self._conn.send_bytes
        while True:
            try:
                return send_bytes(frame)
            except BlockingIOError:     # full for SO_SNDTIMEO: nothing was written
                if self._stop is not None and self._stop():
                    raise LinkStopped() from None
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                raise LinkClosed(str(e)) from e

    def _send_large(self, frame):
        """ A large frame as send_bytes() would write it (its length, then the frame), resumed after
        each partial write; stop() before the first byte leaves the link usable, after it ends the link """
        buf = memoryview(struct.pack('!i', len(frame)) + frame)
        if self._conn.closed:
            raise LinkClosed("the link's end is closed")
        sent = 0
        while sent < len(buf):
            try:
                sent += os.write(self._fd, buf[sent:])
            except BlockingIOError:
                if self._stop is not None and self._stop():
                    if sent:
                        self.close()
                    raise LinkStopped() from None
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                raise LinkClosed(str(e)) from e

    def recv(self, timeout=None):
        if self._conn.closed:
            raise LinkClosed("the link's end is closed")
        if timeout is not None and not self._poll.poll(timeout * 1000):
            return None
        try:
            buf = self._conn.recv_bytes()
        except (EOFError, OSError) as e:
            raise LinkClosed(str(e) or "the peer closed the link") from e
        return decode(buf)


class PipeRanLink(PipeEndpoint, RanLink):
    """ The UE emulator's end of a PipeLink """


class PipeUeLink(PipeEndpoint, UeLink):
    """ An adapter's end of a PipeLink """


class PipeLink:
    """ A link over a duplex multiprocessing.Pipe: ue_end (a RanLink) for the UE-emulator process,
    ran_end (a UeLink) for the adapter's. A full link blocks the sender until it drains, looking at
    stop() every interval seconds. """

    def __init__(self, stop=None, interval=0.5):
        ue_conn, ran_conn = Pipe(duplex=True)
        for conn in (ue_conn, ran_conn):
            _set_send_timeout(conn.fileno(), interval)
        self.ue_end = PipeRanLink(ue_conn, ran_conn, stop)
        self.ran_end = PipeUeLink(ran_conn, ue_conn, stop)

    def close(self):
        """ Close both ends in this process (e.g. in a process that uses neither) """
        self.ue_end.close()
        self.ran_end.close()
