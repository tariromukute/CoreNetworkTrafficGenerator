""" When the UE simulator starts each UE: on an absolute schedule (fixed interval or Poisson), and, in a
closed loop, with at most K UEs in their procedures at once. """
import threading
import time


def start_offsets(n, interval, poisson=False, rng=None):
    """ The start time of each of n UEs, in seconds from the first.

    The schedule is absolute: a UE that starts late does not push the later ones back, so the offered
    rate stays 1/interval. With poisson, the gaps are exponential with mean interval (rng: a
    random.Random, for a repeatable schedule).
    """
    offsets, t = [], 0.0
    for k in range(n):
        offsets.append(t)
        t += rng.expovariate(1 / interval) if poisson and interval > 0 else interval
    return offsets


class InFlight:
    """ At most limit UEs in their procedures at once (a closed loop).

    acquire() blocks until a UE may start; release() frees its place when it has finished; expire()
    frees the places of UEs that have not finished within timeout seconds, so that a lost UE does not
    hold its place for ever.
    """

    def __init__(self, limit, timeout, clock=time.monotonic):
        self.limit = limit
        self.timeout = timeout
        self.clock = clock
        self.started = {}               # UE ID -> when it started
        self.cond = threading.Condition()

    def acquire(self, ue_id, stop=lambda: False):
        """ Wait for a place for ue_id; False if stop() became true first. """
        with self.cond:
            while len(self.started) >= self.limit:
                if stop():
                    return False
                self.cond.wait(0.5)
            self.started[ue_id] = self.clock()
            return True

    def release(self, ue_id):
        """ ue_id has finished; True if it held a place. """
        with self.cond:
            if self.started.pop(ue_id, None) is None:
                return False
            self.cond.notify()
            return True

    def expire(self):
        """ Free the places of the UEs started more than timeout seconds ago; return their IDs. """
        with self.cond:
            now = self.clock()
            late = [u for u, t in self.started.items() if now - t > self.timeout]
            for u in late:
                del self.started[u]
            if late:
                self.cond.notify(len(late))
            return late
