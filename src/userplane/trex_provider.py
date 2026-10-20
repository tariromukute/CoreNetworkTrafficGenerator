""" The TRex provider: each PDU session's uplink from a TRex server, added as the session comes up. """
import json
import logging
import os
import select
import subprocess
import sys

from .base import Context, Session, UserPlaneProvider

logger = logging.getLogger('__TRexProvider__')


class TRexProvider(UserPlaneProvider):
    """ Gives each session a stream of its own on a TRex server (stateless mode), started when the
    session comes up and stopped when the UE is released, while the other sessions keep sending.

    Configuration (an entry of userPlane.providers):

        type: trex
        server: 192.168.70.151      # the TRex server (its RPC port, 4501)
        port: 0                     # the TRex port that sends the uplink (on N3)
        trexClient: /opt/trex-client   # TRex's automation/trex_control_plane/interactive and external_libs
        srcIp: 192.168.72.142       # outer source: TRex's N3 address
        dstIp: 10.50.73.135         # inner destination (a host in the data network)
        dstPort: 5001
        pps: 1000                   # per session
        payload: 1400
        sequence: true              # count frames in the first 4 payload bytes
        sample: 0                   # only the first K sessions to come up get a stream (0: all)
        log: <folder>/trex-sessions.jsonl   # when each stream started and stopped

    TRex's client brings its own scapy, so it runs in a worker (trex_worker.py) in an isolated
    interpreter, driven over a pipe. """

    def __init__(self, config: dict, context: Context):
        super().__init__(config, context)
        self.sample = int(config.get('sample', 0))
        self.started = 0
        self.log_path = config.get('log') or os.path.join(context.folder, 'trex-sessions.jsonl')
        self.proc = None

    def start(self) -> None:
        c = self.config
        worker = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'trex_worker.py')
        cmd = [c.get('python', sys.executable), '-I', worker,
               '--trex-client', c['trexClient'], '--server', str(c.get('server', '127.0.0.1')),
               '--port', str(c.get('port', 0)), '--src-ip', c['srcIp'], '--dst-ip', c['dstIp'],
               '--dst-port', str(c.get('dstPort', 5001)), '--pps', str(c.get('pps', 1000)),
               '--payload', str(c.get('payload', 1400)), '--log', self.log_path,
               '--core-mask', str(c.get('coreMask', 1)),
               '--sequence' if c.get('sequence', True) else '--no-sequence']
        os.makedirs(os.path.dirname(self.log_path) or '.', exist_ok=True)
        open(self.log_path, 'w').close()
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        hello = self._reply(timeout=60)
        print(f"User plane: TRex at {hello.get('server')}, port {hello.get('port')}; "
              f"{self.sample or 'all'} sessions at {c.get('pps', 1000)} pps each")

    def add_session(self, session: Session) -> None:
        if self.sample and self.started >= self.sample:
            return
        self._call({'op': 'add', 'id': session.key, 'teid': session.ul_teid, 'qfi': session.qfi,
                    'ue_ip': session.ue_ip, 'upf': session.upf_address or self.config['upfAddress']})
        self.started += 1

    def remove_session(self, session: Session) -> None:
        self._call({'op': 'remove', 'id': session.key})

    def stats(self) -> dict:
        return self._call({'op': 'stats'})

    def stop(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        try:
            r = self._call({'op': 'stop'})
            print(f"User plane: TRex stopped, {r.get('sessions')} sessions, {r.get('tx_packets')} frames sent")
        finally:
            try:
                self.proc.stdin.close()
                self.proc.wait(10)
            except Exception:
                self.proc.kill()

    def _call(self, msg: dict, timeout: float = 30) -> dict:
        if self.proc is None or self.proc.poll() is not None:
            raise RuntimeError("the TRex worker is not running")
        self.proc.stdin.write(json.dumps(msg) + '\n')
        self.proc.stdin.flush()
        return self._reply(timeout)

    def _reply(self, timeout: float) -> dict:
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not ready:
            raise RuntimeError(f"no reply from the TRex worker in {timeout} s")
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError(f"the TRex worker exited (status {self.proc.wait()})")
        reply = json.loads(line)
        if not reply.get('ok'):
            raise RuntimeError(f"TRex worker: {reply.get('error')}")
        return reply
