#!/usr/bin/env python3
""" CN-TG's TRex worker: drives a TRex server (stateless API) for the trex user plane provider.

TRexProvider runs it in an isolated interpreter (python3 -I): TRex's client puts its own scapy,
pyzmq and PyYAML first on sys.path, so it cannot share a process with CN-TG's. It imports only
the standard library and TRex's client (--trex-client: a copy of TRex's
automation/trex_control_plane/interactive and external_libs directories).

One request per line on stdin, one reply per line on stdout, JSON:

    {"op": "add", "id": "31-1", "teid": 1, "qfi": 1, "ue_ip": "12.1.0.2", "upf": "192.168.72.134"}
    {"op": "remove", "id": "31-1"}
    {"op": "stats"}
    {"op": "stop"}

and {"ok": true, ...} or {"ok": false, "error": "..."}; the first line, once connected, is
{"ok": true, "op": "hello", ...}. When stdin closes (the provider is gone), all streams stop. Each session is a TRex profile of its own on the port
(e.g. "0.s31_1"): it starts and stops while the other sessions keep sending (TRex's dynamic
profiles). Its stream is the UE's uplink, GTP-U to the UPF with the session's TEID and QFI;
with --sequence, the first 4 bytes of the inner UDP payload count the stream's frames.
--log records when each session's stream started and stopped (JSON lines, host time).
"""
import argparse
import importlib
import importlib.util
import json
import os
import sys
import time
import types


def load_trex(client_dir):
    # TRex 3.06's client imports imp (removed in Python 3.12), for load_source and reload only
    try:
        import imp  # noqa: F401
    except ImportError:
        imp = types.ModuleType('imp')

        def load_source(name, path):
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            sys.modules[name] = module
            return module
        imp.load_source = load_source
        imp.reload = importlib.reload
        sys.modules['imp'] = imp
    os.environ.setdefault('TREX_EXT_LIBS', os.path.join(client_dir, 'external_libs'))
    sys.path.insert(0, os.path.join(client_dir, 'interactive'))
    from trex.stl import api
    return api


def build_stream(api, index, req, a):
    from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    # Both UDP checksums 0, so the counter needs no fix-up; TRex fills the MACs (port L3 mode)
    inner = IP(src=req['ue_ip'], dst=a.dst_ip) / UDP(sport=40000 + index % 20000, dport=a.dst_port, chksum=0) / (a.payload * 'x')
    pkt = (Ether() / IP(src=a.src_ip, dst=req['upf']) / UDP(sport=2152, dport=2152, chksum=0) /
           GTP_U_Header(teid=int(req['teid'])) / GTPPDUSessionContainer(type=1, QFI=int(req['qfi'])) / inner)
    vm = None
    if a.sequence:
        vm = api.STLScVmRaw([api.STLVmFlowVar(name='seq', min_value=0, max_value=0xFFFFFFFF, size=4, op='inc'),
                             api.STLVmWrFlowVar(fv_name='seq', pkt_offset=len(pkt) - a.payload)])
    return api.STLStream(packet=api.STLPktBuilder(pkt=pkt, vm=vm), mode=api.STLTXCont(pps=a.pps), name=f"s{req['id']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--trex-client', required=True)
    ap.add_argument('--server', default='127.0.0.1')
    ap.add_argument('--sync-port', type=int, default=4501)
    ap.add_argument('--async-port', type=int, default=4500)
    ap.add_argument('--port', type=int, default=0, help="the TRex port that sends the uplink")
    ap.add_argument('--src-ip', required=True, help="outer source: the gNB's N3 address as TRex sends it")
    ap.add_argument('--dst-ip', required=True, help="inner destination")
    ap.add_argument('--dst-port', type=int, default=5001)
    ap.add_argument('--pps', type=float, default=1000.0, help="per session")
    ap.add_argument('--payload', type=int, default=1400, help="inner UDP payload bytes (>= 4 with --sequence)")
    ap.add_argument('--sequence', action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument('--core-mask', type=lambda s: int(s, 0), default=0x1,
                    help="TRex cores for each stream; one core keeps a stream's frames in order (0: TRex's default)")
    ap.add_argument('--log', default=None)
    a = ap.parse_args()

    # Replies go to the real stdout; anything TRex's client prints goes to stderr
    out = os.fdopen(os.dup(1), 'w', buffering=1)
    sys.stdout = sys.stderr
    log = open(a.log, 'a', buffering=1) if a.log else None

    def reply(**kv):
        out.write(json.dumps(kv) + '\n')

    def record(**kv):
        if log:
            log.write(json.dumps({'t': time.time(), **kv}) + '\n')

    try:
        api = load_trex(a.trex_client)
        client = api.STLClient(server=a.server, sync_port=a.sync_port, async_port=a.async_port, verbose_level='error')
        client.connect()
        client.reset(ports=[a.port])
    except Exception as e:
        reply(ok=False, op='hello', error=f"{type(e).__name__}: {e}")
        return 1
    reply(ok=True, op='hello', server=a.server, port=a.port)

    profiles = {}
    core_mask = [a.core_mask] if a.core_mask else None
    stopped = False
    for line in sys.stdin:
        if not line.strip():
            continue
        req = {}
        try:
            req = json.loads(line)
            op = req['op']
            if op == 'add':
                profile = f"{a.port}.s{str(req['id']).replace('-', '_')}"
                client.add_streams(build_stream(api, len(profiles), req, a), ports=[profile])
                client.start(ports=[profile], core_mask=core_mask)
                profiles[req['id']] = profile
                record(op='start', id=req['id'], profile=profile, ue_ip=req['ue_ip'], teid=req['teid'], pps=a.pps)
                reply(ok=True, op=op, id=req['id'], profile=profile)
            elif op == 'remove':
                profile = profiles.pop(req['id'], None)
                if profile:
                    client.stop(ports=[profile])
                    client.remove_all_streams(ports=[profile])
                    record(op='stop', id=req['id'], profile=profile)
                reply(ok=True, op=op, id=req['id'], found=profile is not None)
            elif op == 'stats':
                s = client.get_stats(ports=[a.port])[a.port]
                reply(ok=True, op=op, sessions=len(profiles), tx_packets=s['opackets'], tx_bytes=s['obytes'],
                      tx_pps=s.get('tx_pps'))
            elif op == 'stop':
                s = client.get_stats(ports=[a.port])[a.port]
                client.stop(ports=[a.port])
                record(op='stop-all', sessions=len(profiles), tx_packets=s['opackets'])
                reply(ok=True, op=op, sessions=len(profiles), tx_packets=s['opackets'])
                stopped = True
                break
            else:
                reply(ok=False, op=op, error=f"unknown op {op!r}")
        except Exception as e:
            reply(ok=False, op=req.get('op'), id=req.get('id'), error=f"{type(e).__name__}: {e}")
    try:
        if not stopped:        # stdin closed without a stop: the provider is gone, so is the traffic
            client.stop(ports=[a.port])
            record(op='stop-all', sessions=len(profiles), reason='stdin closed')
        client.disconnect()
    except Exception:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
