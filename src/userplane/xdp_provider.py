""" The XDP provider: CN-TG's own GTP-U generator (src/bpf/xdpgen.bpf.c). """
import logging

from .base import Context, Session, UserPlaneProvider

logger = logging.getLogger('__XdpProvider__')


class XdpProvider(UserPlaneProvider):
    """ Generates the sessions' uplink in an XDP program on `interface` (gtpuConfig's keys:
    interface, srcMac, dstMac, srcIp, dstIp), all sessions round-robin, up to -n packets per
    second, on half the CPUs. Sessions are added to the program's map as they come up;
    removal is not supported (the map is an array the program walks by index). """

    def __init__(self, config: dict, context: Context):
        super().__init__(config, context)
        # BCC is needed only by those who use this provider
        from src.bpf.XDPLoader import Trafficgen
        from src.GTPU import GTPU, GTPUConfig
        self.trafficgen = Trafficgen(config['interface'])
        self.gtpu = GTPU(GTPUConfig(src_mac=config['srcMac'], dst_mac=config['dstMac'],
                                    src_ip=config['srcIp'], dst_ip=config['dstIp'],
                                    cpu_cores=range(max(1, context.num_cpus // 2)),
                                    num_pkts=config.get('numPkts', context.num_pkts)),
                         self.trafficgen, context.verbose)
        self._warned = False

    def start(self) -> None:
        # The program and its maps: add_ue_record() and run() need them
        self.trafficgen.load()

    def add_session(self, session: Session) -> None:
        self.trafficgen.add_ue_record(session.ue_ip, session.ul_teid, session.qfi)
        if not self.gtpu.generate:
            self.gtpu.start()

    def remove_session(self, session: Session) -> None:
        if not self._warned:
            logger.warning("XDP provider: removing a session is not supported; its traffic continues")
            self._warned = True

    def stats(self) -> dict:
        return {f"{k[0]}/{k[1]}": v for k, v in self.trafficgen.get_stats().items()}

    def stop(self) -> None:
        self.gtpu.stop()
