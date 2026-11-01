""" The gNB's user plane: one process that hands each PDU session to the configured providers. """
import importlib
import logging
import multiprocessing
import signal
import traceback
from dataclasses import asdict

from .base import Context, Session

logger = logging.getLogger('__UserPlane__')


def create_provider(config: dict, context: Context):
    """ The provider for one entry of userPlane.providers, by its type: file, xdp, trex, or
    'package.module:Class' for a provider defined elsewhere. Imported only when used, so that a
    provider's dependencies (BCC, TRex's client) are needed only by those who use it. """
    kind = config.get('type')
    if kind and ':' in kind:
        module, _, cls = kind.partition(':')
        return getattr(importlib.import_module(module), cls)(config, context)
    if kind == 'file':
        from .file_provider import FileProvider
        return FileProvider(config, context)
    if kind == 'xdp':
        from .xdp_provider import XdpProvider
        return XdpProvider(config, context)
    if kind == 'trex':
        from .trex_provider import TRexProvider
        return TRexProvider(config, context)
    raise ValueError(f"unknown user plane provider type {kind!r} (file, xdp, trex or module:Class)")


def providers_from_config(server_config: dict) -> list:
    """ userPlane.providers from the gNB's configuration. Without a userPlane section, the
    gtpuConfig section configures the XDP generator, as before. """
    user_plane = server_config.get('userPlane')
    if user_plane is not None:
        return list(user_plane.get('providers') or [])
    return [{'type': 'xdp', **server_config['gtpuConfig']}]


class UserPlane():
    """ Runs the user plane providers in a process of their own, fed through a queue.

    The gNB processes call add_session() when a UE's PDU session is up and release_ue() when
    the UE's context is released; both only enqueue. So a slow provider (an RPC to a traffic
    generator) never holds up NGAP, and all gNB processes share one instance of each provider.
    Sessions are handed over in the order they came up, and each provider sees every session. """

    def __init__(self, provider_configs: list, context: Context):
        self.provider_configs = provider_configs
        self.context = context
        self.queue = multiprocessing.Queue()
        self.process = None

    # In the main process
    def start(self) -> None:
        # A daemon: if CN-TG dies, it goes too (a provider's worker sees its pipe close)
        self.process = multiprocessing.Process(name='userplane', target=self._run, daemon=True)
        self.process.start()

    def stop(self, timeout: float = 30) -> None:
        if self.process is None:
            return
        self.queue.put(('stop', None))
        self.process.join(timeout)
        if self.process.is_alive():
            logger.error("User plane process did not stop in time; terminating it")
            self.process.terminate()

    # In the gNB processes
    def add_session(self, session: Session) -> None:
        self.queue.put(('add', asdict(session)))

    def release_ue(self, ran_ue_ngap_id: int) -> None:
        self.queue.put(('release', ran_ue_ngap_id))

    # In the user plane process
    def _run(self) -> None:
        # Ctrl-C reaches every process; the main process decides when the user plane stops
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        providers = []
        for config in self.provider_configs:
            try:
                provider = create_provider(config, self.context)
                provider.start()
                providers.append(provider)
                print(f"User plane: {config.get('type')} provider started")
            except Exception as e:
                logger.error(f"User plane: {config.get('type')} provider failed to start: {e}")
                traceback.print_exc()
        sessions = {}
        while True:
            op, arg = self.queue.get()
            if op == 'add':
                session = Session(**arg)
                sessions[session.key] = session
                self._each(providers, 'add_session', session)
            elif op == 'release':
                for key in [k for k, s in sessions.items() if s.ran_ue_ngap_id == arg]:
                    self._each(providers, 'remove_session', sessions.pop(key))
            elif op == 'stop':
                break
        for provider in providers:
            try:
                provider.stop()
            except Exception as e:
                logger.error(f"User plane: stopping {type(provider).__name__}: {e}")

    @staticmethod
    def _each(providers, method, session):
        for provider in providers:
            try:
                getattr(provider, method)(session)
            except Exception as e:
                logger.error(f"User plane: {type(provider).__name__}.{method}({session.key}): {e}")
