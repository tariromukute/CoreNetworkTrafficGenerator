""" ShmLink: the UE-RAN link (src/ranlink.py) over shared memory.

A drop-in for PipeLink: ue_end (a RanLink) for the UE-emulator process, ran_end (a UeLink) for the
adapter's, with the same send(), recv(timeout), close(), attach(), LinkClosed and LinkStopped, and
UeLink.waiter() for an adapter that serves several links (ShmWaiter: one epoll over their eventfds).
The frames are ranlink's (encode/decode), unchanged.

The memory
    Per link, one anonymous shared mapping (MAP_SHARED), made before run.py forks the UE simulator and
    gNB processes, which inherit it. It has no name: nothing to unlink, nothing left behind when a run
    crashes (the kernel frees it with its last process), and nothing in /dev/shm, so a container needs
    no --shm-size or --ipc for it (the pages count towards the container's memory). The ends are
    inherited by fork (run.py's start method), not pickled.

        0                 the header, 4 KiB of 64-bit words, each on a cache line of its own:
                          a magic word; each end's closed flag; per ring, its tail (the producer's
                          position), the producer's flag that it waits for room, its head (the
                          consumer's position), the consumer's flag that it waits for data
        4 KiB             the UE-to-RAN ring (size bytes, a power of two; RING_SIZE by default)
        4 KiB + size      the RAN-to-UE ring

    Positions count bytes since the start. A record starts at a multiple of 8: the frame's length (u32),
    the frame, padding to 8. A frame that reaches the ring's end goes on at its start (two copies). A
    record larger than the ring streams through it: the producer publishes what fits and waits for room,
    the consumer collects it; a stop() before its first byte leaves the link usable, after it the
    producer closes its end, so that the consumer gets LinkClosed, not half a frame.

Ordering
    The producer writes a record, then the tail; the consumer reads the tail, then the record, then
    writes the head. This needs the record's stores seen before the tail's, the indices written and
    read whole, the consumer's loads of the record not before its load of the tail and its store of the
    head not before them. x86-64 (TSO) keeps stores in program order and loads in order with older loads
    and does not move stores before older loads, so plain stores and loads in program order suffice:
      - memoryview.cast('Q')[i] reads and writes the word with one 8-byte mov (the image's python3.12:
        pack_single's 'Q' case is `mov %r15,(%r13)`, unpack_single's `mov (%r12),%rdi`), and the words
        are 8-aligned (a page-aligned mapping), so they are atomic;
      - the record's copy (memcpy) and the index's store are separate C calls in separate bytecodes, in
        program order; glibc's memcpy fences its non-temporal stores (multi-megabyte copies only).
    No C helper is needed. Other architectures (aarch64) reorder stores, and ShmLink refuses to run there.

Wake-ups
    Each ring has an eventfd for data, which its consumer waits on, and one for room, which a producer
    that found it full waits on. A consumer with nothing to read sets its waiting flag, reads the tail
    again and only then blocks; a producer signals after it published only if the flag is set. So a busy
    link costs no syscall per message. The data eventfds are waited on with edge-triggered epoll, which
    reports each signal once, so they are never read back (one syscall less per wake-up). A producer
    that waits for room is woken once the ring is half empty, not at each record taken (as the kernel
    wakes a socket's writer), so that a producer ahead of its consumer does not cost a wake-up a record.
    Flag and index are a Dekker pair, and x86-64 may perform a load before an older store is seen (store
    buffering), which would lose a wake-up: so each side has a full fence between its store and its
    load, a process-local threading.Lock's acquire and release (glibc's sem_trywait and sem_post:
    lock-prefixed instructions). Without it the store-buffering outcome shows in pure Python across two
    processes (26 times in 10**6 rounds on the development host), with it never
    (tests/test_shmlink.py, test_the_fence_orders_a_store_before_a_load).
      - The producer's fence is the release of its send lock, which also serialises several senders (the
        UE simulator's workers) on the one ring.
      - The consumer reads the producer's waiting flag after each record without a fence: a flag it
        misses then it sees at its next record or, at the latest, after the fenced arming before it
        blocks, which looks at it again.

The end of a link
    close() sets the end's closed flag and signals the peer's two eventfds. A process's exit or crash is
    seen through a socketpair that carries nothing: each end keeps one socket, attach() lets go of the
    peer's in this process, and the peer's last copy closing makes it poll readable (end of file), in
    the same wait as the eventfd. What the peer published before stays readable; then LinkClosed.

Back-pressure: a full ring blocks the sender until there is room, looking at stop() every interval
seconds (as PipeLink); nothing is dropped.
"""
import mmap
import os
import platform
import select
import socket
import struct
import threading
import time

from src.ranlink import Endpoint, FrameError, LinkClosed, LinkStopped, RanLink, UeLink, Waiter, decode, encode

# Bytes per direction: about 370 CONNECTs or 500 short NAS messages, as many as the pipe held (278 frames).
# A deeper ring changes a burst's order: the UE simulator's init() would queue every CONNECT ahead of the
# UEs' next messages (a pipe that is full makes it wait, and the workers' answers get in between).
RING_SIZE = 32 * 1024
HEADER_SIZE = 4096
MAGIC = int.from_bytes(b'SHMLINK1', 'little')

UE, RAN = 0, 1              # the ends; ring r carries the frames of end r to end 1 - r

_LINE = 8                   # 64-bit words per 64-byte cache line
_MAGIC = 0
_CLOSED = (1 * _LINE, 2 * _LINE)
_TAIL, _WWAIT, _HEAD, _RWAIT = 0, _LINE, 2 * _LINE, 3 * _LINE   # a ring's words, from its base


def _ring_base(r):
    return (3 + 4 * r) * _LINE


_LEN = struct.Struct('=I')
_pack_len = _LEN.pack_into
_unpack_len = _LEN.unpack_from
_EDGE = select.EPOLLIN | select.EPOLLET      # an eventfd's wake-ups, each signal once: never read back
_LEVEL = select.EPOLLIN                       # a socket's end of file


def supported():
    """ Whether ShmLink runs here: Linux (eventfd) on x86-64 (its store ordering, see Ordering) """
    return hasattr(os, 'eventfd') and platform.machine().lower() in ('x86_64', 'amd64')


def _signal(fd):
    """ Wake the waiter on this eventfd. Its count is never read back (edge-triggered epoll); at its
    maximum, after 2**64 - 2 signals, it is reset first. """
    try:
        os.eventfd_write(fd, 1)
    except BlockingIOError:
        _drain(fd)
        os.eventfd_write(fd, 1)


def _drain(fd):
    try:
        os.eventfd_read(fd)
    except BlockingIOError:
        pass


class _Shared:
    """ What a link's ends share in one process: the mapping and its views, the eventfds and the two
    sockets. Each descriptor is closed once (close_fd), so a number the process reuses is not closed
    again; what is left goes with close(), or with the last end. """

    def __init__(self, size):
        self.size = size
        self.mm = mmap.mmap(-1, HEADER_SIZE + 2 * size)
        self.view = memoryview(self.mm)
        self.words = self.view[:HEADER_SIZE].cast('Q')
        self.words[_MAGIC] = MAGIC
        flags = os.EFD_NONBLOCK | os.EFD_CLOEXEC
        self.data_fds = (os.eventfd(0, flags), os.eventfd(0, flags))
        self.room_fds = (os.eventfd(0, flags), os.eventfd(0, flags))
        a, b = socket.socketpair()
        self.sock_fds = (a.detach(), b.detach())
        self.open_fds = set(self.data_fds + self.room_fds + self.sock_fds)

    def close_fd(self, fd):
        if fd in self.open_fds:
            self.open_fds.discard(fd)
            os.close(fd)

    def close(self):
        for fd in list(self.open_fds):
            self.close_fd(fd)
        if self.mm is None:
            return
        for view in (self.words, self.view):
            view.release()
        try:
            self.mm.close()
        except BufferError:     # a view still in use somewhere: the mapping goes with it
            pass
        self.mm = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class ShmEndpoint(Endpoint):
    """ One end of a ShmLink: the producer of one ring, the consumer of the other. send() may be called
    from several threads at once (a lock); one thread receives at a time. """

    # fileno() (the eventfd) is readable only while this end has said it waits: ShmWaiter does that
    pollable = False

    def __init__(self, shared, end, stop, interval):
        self._shared = shared
        self._w = w = shared.words
        self._mm = shared.mm                # the rings' bytes, addressed in the mapping (a slice is one copy)
        self._cap = shared.size
        self._mask = self._cap - 1
        self._half = self._cap // 2         # a producer waiting for room is woken once the ring is half empty
        self._obase = HEADER_SIZE + end * self._cap          # the ring this end produces into
        self._oend = self._obase + self._cap
        self._ibase = HEADER_SIZE + (1 - end) * self._cap    # the ring it consumes
        self._iend = self._ibase + self._cap
        ob, ib = _ring_base(end), _ring_base(1 - end)
        self._o_tail, self._o_wwait, self._o_head, self._o_rwait = ob + _TAIL, ob + _WWAIT, ob + _HEAD, ob + _RWAIT
        self._i_tail, self._i_wwait, self._i_head, self._i_rwait = ib + _TAIL, ib + _WWAIT, ib + _HEAD, ib + _RWAIT
        self._my_closed, self._peer_closed = _CLOSED[end], _CLOSED[1 - end]
        self._data_in, self._data_out = shared.data_fds[1 - end], shared.data_fds[end]
        self._room_out, self._room_in = shared.room_fds[end], shared.room_fds[1 - end]
        self._sock, self._peer_sock = shared.sock_fds[end], shared.sock_fds[1 - end]
        self._stop = stop
        self._interval_ms = interval * 1000
        self._send_lock = threading.Lock()   # several senders; its release is the producer's fence
        self._wfence = threading.Lock()      # the producer's fence while it holds the send lock
        self._rfence = threading.Lock()      # the consumer's
        self._tail, self._out_head = w[self._o_tail], w[self._o_head]   # the producer's
        self._head, self._in_tail = w[self._i_head], w[self._i_tail]     # the consumer's
        self._partial = None                 # a streamed record being collected: [buffer, filled, frame length]
        self._closed = False
        self._peer_gone = False
        self._data_ep = None                 # an epoll of the process that uses the end: made at its first wait
        self._data_ep_pid = None
        self._room_poll = select.poll()
        self._room_poll.register(self._room_out, select.POLLIN)
        self._room_poll.register(self._sock, select.POLLIN)

    def __reduce__(self):
        raise TypeError("a ShmLink's ends are inherited by fork, not pickled (run.py's start method)")

    def fileno(self):
        return self._data_in

    @property
    def closed(self):
        return self._closed

    def attach(self):
        self._shared.close_fd(self._peer_sock)

    def close(self):
        """ End the link: the peer reads what this end sent before, then gets LinkClosed """
        if self._closed:
            return
        self._closed = True
        try:
            self._w[self._my_closed] = 1
            _signal(self._data_out)
            _signal(self._room_in)
        except (ValueError, OSError):       # ShmLink.close() has let go of the link here
            pass
        self._shared.close_fd(self._sock)

    def _gone(self):
        if self._closed:
            return LinkClosed("the link's end is closed")
        return LinkClosed("the peer closed the link")

    # Sending

    def send(self, kind, ue_id, payload=b'', code=0, received_at=None, stamps=None):
        self.send_frame(encode(kind, ue_id, payload, code, received_at, stamps))

    def send_frame(self, frame):
        """ Send a frame; while the ring is full, block until there is room or stop() """
        n = len(frame)
        rec = (n + 11) & -8
        cap = self._cap
        lock = self._send_lock
        lock.acquire()
        try:
            w = self._w
            if self._closed or w[self._peer_closed] or self._peer_gone:
                raise self._gone()
            tail = self._tail
            if rec > cap - (tail - self._out_head):
                self._out_head = w[self._o_head]
                if rec > cap - (tail - self._out_head):
                    if rec > cap:
                        return self._send_streamed(frame, n, rec)
                    self._wait_room(rec)
            mm = self._mm
            pos = self._obase + (tail & self._mask)
            _pack_len(mm, pos, n)
            pos += 4
            end = pos + n
            if end <= self._oend:
                mm[pos:end] = frame
            else:                           # on at the ring's start
                k = self._oend - pos
                frame = memoryview(frame)
                mm[pos:self._oend] = frame[:k]
                mm[self._obase:self._obase + n - k] = frame[k:]
            tail += rec
            self._tail = tail
            w[self._o_tail] = tail          # publishes the record
        except (ValueError, OSError):
            if self._closed:
                raise self._gone() from None
            raise
        finally:
            lock.release()                  # a full fence: the tail is seen before the flag is read
        if w[self._o_rwait]:
            _signal(self._data_out)

    def _wait_room(self, need):
        """ Wait, holding the send lock, until the ring has need bytes of room; LinkStopped if stop()
        while it is full, LinkClosed if the link ends """
        w, cap, tail = self._w, self._cap, self._tail
        fence = self._wfence
        while True:
            if self._closed or w[self._peer_closed] or self._peer_gone:
                raise self._gone()
            head = w[self._o_head]
            if cap - (tail - head) >= need:
                self._out_head = head
                return
            if self._stop is not None and self._stop():
                raise LinkStopped()
            w[self._o_wwait] = 1
            fence.acquire()
            fence.release()
            try:
                if cap - (tail - w[self._o_head]) < need and not w[self._peer_closed]:
                    for fd, _ in self._room_poll.poll(self._interval_ms):
                        if fd == self._room_out:
                            _drain(fd)
                        else:
                            self._peer_gone = True
            finally:
                w[self._o_wwait] = 0

    def _send_streamed(self, frame, n, rec):
        """ A record larger than the ring, published as room comes (the send lock held) """
        w, cap, mask, mm, base = self._w, self._cap, self._mask, self._mm, self._obase
        src = memoryview(_LEN.pack(n) + frame)
        total = 4 + n
        fence = self._wfence
        sent = 0                        # the record's bytes published so far
        tail = self._tail
        while sent < rec:
            need = 8 if sent == 0 else 1      # a record's length is never split
            free = cap - (tail - self._out_head)
            if free < need:
                self._out_head = w[self._o_head]
                free = cap - (tail - self._out_head)
                if free < need:
                    try:
                        self._wait_room(need)
                    except LinkStopped:
                        if sent:
                            self.close()        # the consumer must not take half a frame for one
                        raise
                    continue
            take = min(free, rec - sent)
            a, b = sent, min(sent + take, total)      # the padding needs no copy
            if a < b:
                pos = tail & mask
                first = min(b - a, cap - pos)
                mm[base + pos:base + pos + first] = src[a:a + first]
                if first < b - a:
                    mm[base:base + b - a - first] = src[a + first:b]
            tail += take
            sent += take
            self._tail = tail
            w[self._o_tail] = tail
            fence.acquire()
            fence.release()
            if w[self._o_rwait]:
                _signal(self._data_out)

    # Receiving

    def recv(self, timeout=None):
        if self._closed:
            raise LinkClosed("the link's end is closed")
        try:
            if self._partial is None:
                head = self._head
                tail = self._in_tail
                if tail == head:
                    tail = self._in_tail = self._w[self._i_tail]
                if tail != head:
                    mm = self._mm
                    pos = self._ibase + (head & self._mask)
                    n = _unpack_len(mm, pos)[0]
                    end = pos + 4 + n
                    if end <= self._iend:          # whole before the ring's end (so not streamed)
                        frame = mm[pos + 4:end]     # copied out: the producer may reuse the bytes now
                        head += (n + 11) & -8
                        self._head = head
                        w = self._w
                        w[self._i_head] = head
                        if w[self._i_wwait] and tail - head <= self._half:
                            _signal(self._room_in)
                        return decode(frame)
                    event = self._take(head)
                    if event is not None:
                        return event
            return self._recv_wait(timeout)
        except FrameError:
            raise
        except (ValueError, OSError):
            if self._closed:
                raise LinkClosed("the link's end is closed") from None
            raise

    def _take(self, head):
        """ The record at head: its event, or None when it streams and has not all come yet """
        mm, cap = self._mm, self._cap
        pos = self._ibase + (head & self._mask)
        n = _unpack_len(mm, pos)[0]
        rec = (n + 11) & -8
        if rec > cap:
            self._partial = [bytearray(rec - 4), 0, n]
            self._advance(head + 4)
            return self._collect()
        pos += 4
        end = pos + n
        if end <= self._iend:
            frame = mm[pos:end]
        else:
            frame = mm[pos:self._iend] + mm[self._ibase:self._ibase + end - self._iend]
        self._advance(head + rec)
        return decode(frame)

    def _advance(self, head):
        """ Free the ring up to head; wake a producer that waits for room once the ring is half empty
        (not at each record, which would cost a wake-up per record while the producer is ahead) """
        self._head = head
        w = self._w
        w[self._i_head] = head
        if w[self._i_wwait] and self._in_tail - head <= self._half:
            _signal(self._room_in)

    def _collect(self):
        """ Copy what has come of a streamed record; its event once it is whole """
        buf, filled, n = self._partial
        mm, base, cap = self._mm, self._ibase, self._cap
        head = self._head
        tail = self._in_tail = self._w[self._i_tail]
        take = min(tail - head, len(buf) - filled)
        pos = head & self._mask
        first = min(take, cap - pos)
        buf[filled:filled + first] = mm[base + pos:base + pos + first]
        if first < take:
            buf[filled + first:filled + take] = mm[base:base + take - first]
        filled += take
        self._advance(head + take)
        if filled < len(buf):
            self._partial[1] = filled
            return None
        self._partial = None
        return decode(memoryview(buf)[:n])

    def _recv_wait(self, timeout):
        deadline = None if timeout is None else time.monotonic() + timeout
        w = self._w
        while True:
            ended = w[self._peer_closed] or self._peer_gone    # before the tail: what came before the end is seen
            tail = self._in_tail = w[self._i_tail]
            if tail != self._head:
                event = self._take(self._head) if self._partial is None else self._collect()
                if event is not None:
                    return event
                continue
            if ended:
                self._partial = None
                raise LinkClosed("the peer closed the link")
            if self._closed:
                raise LinkClosed("the link's end is closed")
            remaining = None
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
            self._wait_data(remaining)

    def _arm(self):
        """ Say this end waits for data: the producer signals from its next record on """
        self._w[self._i_rwait] = 1

    def _disarm(self):
        self._w[self._i_rwait] = 0

    def _after_fence(self):
        """ After the fence that follows _arm(): wake a producer whose flag the records' checks missed;
        whether recv() would not block """
        w = self._w
        if w[self._i_wwait]:
            _signal(self._room_in)
        return self._ready()

    def _ready(self):
        """ Whether recv() would not block: a record (or the rest of one) to read, or the link's end """
        if self._in_tail != self._head or self._closed or self._peer_gone:
            return True
        w = self._w
        return w[self._i_tail] != self._head or w[self._peer_closed] != 0

    def _wait_data(self, timeout):
        if self._data_ep_pid != os.getpid():     # not an epoll inherited from the process that made the link
            self._data_ep = select.epoll()
            self._data_ep.register(self._data_in, _EDGE)
            self._data_ep.register(self._sock, _LEVEL)
            self._data_ep_pid = os.getpid()
        self._arm()
        self._rfence.acquire()
        self._rfence.release()
        try:
            if self._after_fence():
                return
            for fd, events in self._data_ep.poll(-1 if timeout is None else timeout):
                if fd != self._data_in or events & (select.EPOLLERR | select.EPOLLHUP):
                    self._peer_gone = True
        finally:
            self._disarm()


class ShmRanLink(ShmEndpoint, RanLink):
    """ The UE emulator's end of a ShmLink """


class ShmUeLink(ShmEndpoint, UeLink):
    """ An adapter's end of a ShmLink """

    @classmethod
    def waiter(cls, links):
        return ShmWaiter(links)


class ShmWaiter(Waiter):
    """ Waits on several ShmLinks' adapter ends: their rings first (no syscall while one has a record),
    then one epoll over their eventfds and sockets, each end armed """

    def __init__(self, links=()):
        self._epoll = select.epoll()
        self._by_fd = {}
        self._fence = threading.Lock()
        super().__init__(links)

    def add(self, link):
        if not isinstance(link, ShmUeLink):
            raise TypeError(f"a ShmLink's waiter cannot wait on a {type(link).__name__}: one link type per adapter")
        self._epoll.register(link._data_in, _EDGE)
        self._epoll.register(link._sock, _LEVEL)
        self._by_fd[link._data_in] = self._by_fd[link._sock] = link
        super().add(link)

    def remove(self, link):
        for fd, other in list(self._by_fd.items()):
            if other is link:
                try:
                    self._epoll.unregister(fd)
                except (OSError, ValueError):
                    pass
                del self._by_fd[fd]
        super().remove(link)

    def wait(self, timeout=None) -> list:
        links = self.links
        ready = [link for link in links if link._ready()]
        if ready:
            return ready
        if not links:
            if timeout:
                time.sleep(timeout)
            return ready
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            for link in links:
                link._arm()
            self._fence.acquire()
            self._fence.release()
            try:
                ready = [link for link in links if link._after_fence()]
                if not ready:
                    remaining = -1 if deadline is None else max(0.0, deadline - time.monotonic())
                    for fd, events in self._epoll.poll(remaining):
                        link = self._by_fd.get(fd)
                        if link is None:
                            continue
                        if fd != link._data_in or events & (select.EPOLLERR | select.EPOLLHUP):
                            link._peer_gone = True
                    ready = [link for link in links if link._ready()]
            finally:
                for link in links:
                    if not link._closed:
                        link._disarm()
            if ready or (deadline is not None and time.monotonic() >= deadline):
                return ready


class ShmLink:
    """ A link over shared memory: ue_end (a RanLink) for the UE-emulator process, ran_end (a UeLink)
    for the adapter's, each ring size bytes (a power of two). A full ring blocks the sender until there
    is room, looking at stop() every interval seconds. """

    def __init__(self, stop=None, interval=0.5, size=RING_SIZE):
        if not supported():
            raise RuntimeError(f"ShmLink needs Linux on x86-64 (here {platform.system()} on {platform.machine()}): "
                               "its rings rely on x86-64's store ordering; use the pipe link")
        if size < 64 or size & (size - 1):
            raise ValueError(f"a ring's size is a power of two of 64 bytes or more, not {size}")
        self.size = size
        self._shared = _Shared(size)
        self.ue_end = ShmRanLink(self._shared, UE, stop, interval)
        self.ran_end = ShmUeLink(self._shared, RAN, stop, interval)

    def __reduce__(self):
        raise TypeError("a ShmLink is inherited by fork, not pickled (run.py's start method)")

    def close(self):
        """ Let go of both ends in this process (e.g. one that uses neither): the link's state is not
        touched, so the processes that use the ends carry on """
        for end in (self.ue_end, self.ran_end):
            end._closed = True
        self._shared.close()
