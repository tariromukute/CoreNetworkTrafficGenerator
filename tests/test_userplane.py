""" The user plane providers' interface: the service process, and the file provider.

Run from the repository root:

    python3 -m pytest tests/test_userplane.py
"""
import json
import time
from multiprocessing import Process

import pytest

from src.userplane import Context, Session, UserPlane, UserPlaneProvider, create_provider, providers_from_config
from src.userplane.file_provider import FileProvider


def session(n, psi=1):
    return Session(supi=f'20895{n:010d}', ue_ip=f'12.1.0.{n % 250 + 2}', pdu_session_id=psi, ul_teid=n, qfi=1,
                   upf_address='192.168.72.134', dl_teid=n, gnb_address='192.168.72.142',
                   ran_ue_ngap_id=n, amf_ue_ngap_id=n, t=time.time())


class Recorder(UserPlaneProvider):
    """ Writes every call it gets to config['path'], one JSON line each. """
    def _write(self, **kv):
        with open(self.config['path'], 'a') as f:
            f.write(json.dumps(kv) + '\n')

    def start(self):
        self._write(op='start')

    def add_session(self, s):
        self._write(op='add', key=s.key)

    def remove_session(self, s):
        self._write(op='remove', key=s.key)

    def stop(self):
        self._write(op='stop')


class Failing(UserPlaneProvider):
    def add_session(self, s):
        raise RuntimeError('generator down')


def calls(path):
    return [json.loads(line) for line in open(path)]


def test_sessions_reach_the_providers_in_order_and_releases_remove_them(tmp_path):
    path = str(tmp_path / 'calls.jsonl')
    up = UserPlane([{'type': f'{__name__}:Recorder', 'path': path}], Context(folder=str(tmp_path)))
    up.start()
    up.add_session(session(31))
    up.add_session(session(32))
    up.add_session(session(32, psi=2))        # a second PDU session of the same UE
    up.release_ue(32)                         # UE context release: both of its sessions go
    up.add_session(session(33))               # added while 31 is still up
    up.stop()
    assert [(c['op'], c.get('key')) for c in calls(path)] == [
        ('start', None), ('add', '31-1'), ('add', '32-1'), ('add', '32-2'),
        ('remove', '32-1'), ('remove', '32-2'), ('add', '33-1'), ('stop', None)]


def test_a_failing_provider_does_not_stop_the_others(tmp_path):
    path = str(tmp_path / 'calls.jsonl')
    up = UserPlane([{'type': f'{__name__}:Failing'}, {'type': f'{__name__}:Recorder', 'path': path}],
                   Context(folder=str(tmp_path)))
    up.start()
    up.add_session(session(31))
    up.stop()
    assert [c['op'] for c in calls(path)] == ['start', 'add', 'stop']


def test_without_a_user_plane_section_gtpu_config_is_the_xdp_generator():
    gtpu = {'interface': 'eth2', 'srcMac': 'a', 'dstMac': 'b', 'srcIp': '1.1.1.1', 'dstIp': '2.2.2.2'}
    assert providers_from_config({'gtpuConfig': gtpu}) == [{'type': 'xdp', **gtpu}]
    assert providers_from_config({'gtpuConfig': gtpu, 'userPlane': {'providers': [{'type': 'file'}]}}) == [{'type': 'file'}]


def test_unknown_provider_type():
    with pytest.raises(ValueError):
        create_provider({'type': 'nope'}, Context(folder='.'))


def test_file_provider_writes_one_line_per_session(tmp_path):
    path = tmp_path / 'out' / 'sessions.jsonl'
    p = FileProvider({'path': str(path)}, Context(folder=str(tmp_path)))
    p.start()
    p.add_session(session(31))
    p.add_session(session(32))
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [r['supi'] for r in rows] == ['208950000000031', '208950000000032']
    assert rows[0]['ue_ip'] == '12.1.0.33' and rows[0]['ul_teid'] == 31 and rows[0]['qfi'] == 1
    assert rows[0]['upf_address'] == '192.168.72.134' and rows[0]['gnb_address'] == '192.168.72.142'


def test_file_provider_starts_empty_in_the_output_folder(tmp_path):
    (tmp_path / 'sessions.jsonl').write_text('{"left": "over"}\n')
    FileProvider({}, Context(folder=str(tmp_path))).start()
    assert (tmp_path / 'sessions.jsonl').read_text() == ''


def _append_many(path, first, count):
    p = FileProvider({'path': path}, Context(folder='.'))   # already created, as in the user plane process
    for i in range(first, first + count):
        p.add_session(session(i))


def test_file_lines_stay_whole_with_several_writers(tmp_path):
    path = str(tmp_path / 'sessions.jsonl')
    FileProvider({'path': path}, Context(folder=str(tmp_path))).start()
    procs = [Process(target=_append_many, args=(path, p * 200, 200)) for p in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    rows = [json.loads(line) for line in open(path)]
    assert sorted(r['ran_ue_ngap_id'] for r in rows) == list(range(800))
