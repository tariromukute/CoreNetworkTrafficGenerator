""" Each gNB process is a gNB of its own: its gNB ID, RAN node name and NR cell identity follow its index.

Run from the repository root (needs pycrate, as src/NGAPSim.py does):

    python3 -m pytest tests/test_gnb_identity.py
"""
from types import SimpleNamespace

from pycrate_asn1dir import NGAP
from src.NGAPSim import initial_ue_message, ng_setup_request, plmn_str_to_buf

def gnb(index):
    return SimpleNamespace(gnb_id=1 + index, mcc='208', mnc='95', plmn_identity=plmn_str_to_buf('20895'),
                           tac=(0xa000).to_bytes(3, 'big'), tai_slice_support_list=[{'sST': b'\x01'}])

def encode_decode(build, *args):
    pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    build(pdu, [], *args)
    pdu.from_aper(pdu.to_aper())
    return {ie['id']: ie['value'][1] for ie in pdu.get_val()[1]['value'][1]['protocolIEs']}

def test_first_gnb_keeps_the_old_identity():
    v = encode_decode(ng_setup_request, gnb(0))
    assert v[27][1]['gNB-ID'] == ('gNB-ID', (1, 32))
    assert v[82] == 'CNTG-gnb-208-95-1'

def test_later_gnbs_differ():
    assert encode_decode(ng_setup_request, gnb(3))[27][1]['gNB-ID'] == ('gNB-ID', (4, 32))
    assert encode_decode(ng_setup_request, gnb(3))[82] == 'CNTG-gnb-208-95-4'

def test_cell_identity_carries_the_gnb_id():
    v = encode_decode(initial_ue_message, {'ran_ue_ngap_id': 31}, gnb(2))
    assert v[121][1]['nR-CGI']['nRCellIdentity'] == (3 << 4, 36)
