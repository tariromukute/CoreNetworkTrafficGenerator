""" End to end over the UE-RAN link: CN-TG (run.py) registers UEs, establishes a PDU session each and
deregisters them against a scripted AMF (tests/amf_stub.py), with one or several UE simulators per gNB,
over each link type (--link pipe, shm), with the gNB's NGAP fast path and without it
(--no-ngap-fastpath).

The uplink NGAP messages of each UE, the User Location Information's time stamp apart, must be the
same with any number of UE simulators per gNB, either link and either NGAP path, and the same as
before the link (705abd9, two pipes of pickled tuples per gNB): REFERENCE is their digest from that
commit's run.py.
Every UE must finish, and the UE simulators' results files must hold every UE once.

Run from the repository root (needs pysctp, the kernel's SCTP module and what run.py needs; about 15 s
per run):

    python3 -m pytest tests/test_ue_ran_e2e.py
"""
import csv
import glob
import hashlib
import json
import os
import subprocess
import sys

import pytest
import yaml

sys.path.insert(0, os.path.dirname(__file__))

NUM_UES = 6
FIRST_SUPI = 208950000000031
# The digest of the uplink NGAP messages per UE from 705abd9's run.py, for NUM_UES UEs (with the
# pycrate and CryptoMobile of the perf-max-load image)
REFERENCE = 'df42451cce21fdae82635635c9e4b96019c8f0e24e68f4345197bb14b99c8415'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ue_config(n):
    return {'ue_profiles': [{
        'supi': str(FIRST_SUPI), 'mcc': '208', 'mnc': '95', 'count': n,
        'procedures': ['5GMMRegistrationRequest', '5GSMPDUSessionEstabRequest', '5GMMMODeregistrationRequest'],
        'key': '0C0A34601D4F07677303652C0462535B', 'op': '63bfa50ee6523365ff14c1f45f88737d', 'opType': 'OPC',
        'amf': '8000', 'imei': '356938035643803', 'imeiSv': '0035609204079514',
        'sessions': [{'type': 'IPv4', 'apn': 'default', 'slice': {'sst': 222, 'sd': 123}}],
        'configuredNssai': [{'sst': 222, 'sd': 123}], 'defaultNssai': [{'sst': 222, 'sd': 123}]}]}


def gnb_config(port, folder):
    return {'mcc': '208', 'mnc': '95', 'nci': '0x000000010', 'idLength': 32, 'tac': 0xa000,
            'linkIp': '127.0.0.1', 'ngapIp': '127.0.0.1', 'gtpIp': '127.0.0.1',
            'amfConfigs': [{'address': '127.0.0.1', 'port': port}],
            'slices': [{'sst': 222, 'sd': 123}],
            'userPlane': {'providers': [{'type': 'file', 'path': os.path.join(folder, 'sessions.jsonl')}]}}


def run_cntg(folder, args=(), tree=ROOT, n=NUM_UES, timeout=120):
    """ run.py from tree against an AMFStub until every UE has finished; the stub's records and run.py's
    output """
    from amf_stub import AMFStub
    os.makedirs(folder, exist_ok=True)
    amf = AMFStub().start()
    try:
        with open(os.path.join(folder, 'ue.yaml'), 'w') as f:
            yaml.safe_dump(ue_config(n), f)
        with open(os.path.join(folder, 'gnb.yaml'), 'w') as f:
            yaml.safe_dump(gnb_config(amf.port, folder), f)
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(
            [p for p in os.environ.get('PYTHONPATH', '').split(os.pathsep) if p and os.path.abspath(p) != ROOT] + [tree]))
        cmd = [sys.executable, '-B', 'run.py', '-u', os.path.join(folder, 'ue.yaml'),
               '-g', os.path.join(folder, 'gnb.yaml'), '-f', folder, '--gnbs', '1', '--no-pin', '-p', '0.2', *args]
        proc = subprocess.run(cmd, cwd=tree, env=env, capture_output=True, text=True, timeout=timeout)
    finally:
        amf.stop()
    return amf, proc


def digest(records):
    return hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()


def results_ues(folder):
    """ The UEs in the UE simulators' results files: [(json file, UE), ...] and the csv files' UEs """
    rows = []
    for path in sorted(glob.glob(os.path.join(folder, 'procedure_times_*.json'))):
        with open(path) as f:
            rows += [(os.path.basename(path), ue['UE']) for ue in json.load(f)]
    csv_ues = []
    for path in sorted(glob.glob(os.path.join(folder, 'procedure_times_*.csv'))):
        with open(path) as f:
            reader = csv.reader(f)
            next(reader)
            csv_ues += [row[0] for row in reader]
    return rows, csv_ues


def sctp_available():
    import socket
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP).close()
        return True
    except OSError:
        return False


def shm_available():
    from src.shmlink import supported
    return supported()


@pytest.mark.skipif(not sctp_available(), reason="needs the kernel's SCTP module")
@pytest.mark.parametrize('link', ['pipe', pytest.param('shm', marks=pytest.mark.skipif(
    not shm_available(), reason='ShmLink needs Linux on x86-64'))])
@pytest.mark.parametrize('per_ran', [1, 3])
@pytest.mark.parametrize('ngap', ['--ngap-fastpath', '--no-ngap-fastpath'])
def test_every_ue_finishes_with_the_same_ngap_bytes(tmp_path, per_ran, link, ngap):
    folder = str(tmp_path / f'k{per_ran}-{link}{ngap}')
    amf, proc = run_cntg(folder, ['--ue-procs-per-ran', str(per_ran), '--link', link, ngap])
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    assert not amf.errors
    ues = [f'0/{i}' for i in range(31, 31 + NUM_UES)]
    assert sorted(amf.released) == sorted((0, int(u.split('/')[1])) for u in ues)
    records = amf.records()
    assert sorted(records) == sorted(ues + ['0/setup'])
    # Initial UE Message, Authentication Response, Security Mode Complete, Initial Context Setup
    # Response, Registration Complete, PDU Session Establishment Request, PDU Session Resource Setup
    # Response, Deregistration Request, UE Context Release Complete
    assert all(len(records[u]) == 9 for u in ues)
    assert digest(records) == REFERENCE
    # One pair of results files per UE simulator, every UE in one of them
    names = sorted(os.path.basename(p) for p in glob.glob(os.path.join(folder, 'procedure_times_*')))
    assert names == sorted(f'procedure_times_{j}.{ext}' for j in range(per_ran) for ext in ('csv', 'json'))
    rows, csv_ues = results_ues(folder)
    ue_ids = list(range(31, 31 + NUM_UES))          # the UE column: the SUPI's last ten digits
    assert sorted(ue for _, ue in rows) == ue_ids
    assert sorted(int(ue) for ue in csv_ues) == ue_ids
