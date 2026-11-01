""" Reused NAS message objects (src/nascache.py): the UE simulator sends the same bytes, and decodes the
same values, as with a fresh pycrate object per message.

The UEs differ in identity (PLMN, MSIN), keys, slices, sessions, IMEISV and the algorithms the AMF
picks, and the downlink messages in the optional IEs they carry; the UEs' steps are interleaved in a
random order, so that a value left over from one UE or message would show in the next.

Run from the repository root (needs pycrate and CryptoMobile, as src/UESim.py does):

    python3 -m pytest tests/test_message_cache.py
"""
import random
import threading
import time
from binascii import unhexlify
from multiprocessing import Array

import pytest
from CryptoMobile.Milenage import Milenage
from CryptoMobile.conv import conv_501_A2, conv_501_A4, conv_501_A6, conv_501_A7, conv_501_A8
from pycrate_mobile.NAS5G import parse_NAS5G as pycrate_parse_NAS5G
from pycrate_mobile.TS24008_IE import encode_bcd
from pycrate_mobile.TS24501_FGMM import (
    FGMMAuthenticationRequest, FGMMAuthenticationResponse, FGMMConfigurationUpdateCommand,
    FGMMDLNASTransport, FGMMMODeregistrationAccept, FGMMMODeregistrationRequest, FGMMRegistrationAccept,
    FGMMRegistrationComplete, FGMMRegistrationReject, FGMMRegistrationRequest, FGMMSecProtNASMessage,
    FGMMSecurityModeCommand, FGMMSecurityModeComplete, FGMMULNASTransport)
from pycrate_mobile.TS24501_FGSM import FGSMPDUSessionEstabAccept, FGSMPDUSessionEstabRequest
from pycrate_mobile.TS24501_IE import FGSIDTYPE_IMEISV

import src.UESim
from src import nascache
from src.nascache import MessageTemplate
from src.UE import UE
from src.UESim import UESim
from src.UEUtils import FGMMState, byte_xor, nas_plaintext, security_prot_decrypt, security_prot_encrypt_ciphered


# --------------------------------------------------------------------------------------------------
# The builders as they were before src/nascache.py (73f0ec3): a fresh pycrate object per message
# --------------------------------------------------------------------------------------------------

def ref_registration_request(ue, IEs, Msg=None):
    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65}
    IEs['NAS_KSI'] = {'TSC': 0, 'Value': 7}
    IEs['5GSRegType'] = {'FOR': 1, 'Value': 1}
    IEs['5GSID'] = {'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': {'PLMN': ue.mcc + ue.mnc,
                                                                           'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': encode_bcd(ue.msin)}}
    IEs['UESecCap'] = {'5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0,
                       '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0, '5G-IA6': 0, '5G-IA7': 0,
                       'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0,
                       'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0}
    Msg = FGMMRegistrationRequest(val=IEs)
    ue.MsgInBytes = Msg.to_bytes()
    ue.set_state(FGMMState.REGISTERED_INITIATED)
    ue.set_procedure(65)
    ue.start_time = time.time()
    return Msg, '5GMMRegistrationRequest'


def ref_registration_complete(ue, IEs, Msg=None):
    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 67}
    Msg, = FGMMRegistrationComplete(val=IEs)
    ue.MsgInBytes = Msg.to_bytes()
    SecMsg = security_prot_encrypt_ciphered(ue, Msg)
    ue.set_state(FGMMState.REGISTERED)
    return SecMsg, '5GMMRegistrationComplete'


def ref_mo_deregistration_request(ue, IEs, Msg=None):
    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 69}
    IEs['NAS_KSI'] = {'TSC': 0, 'Value': 7}
    IEs['DeregistrationType'] = {'SwitchOff': 0, 'ReregistrationRequired': 0, 'AccessType': 1 }
    IEs['5GSID'] = {'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': {'PLMN': ue.mcc + ue.mnc,
                                                                           'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': encode_bcd(ue.msin)}}
    Msg = FGMMMODeregistrationRequest(val=IEs)
    ue.MsgInBytes = Msg.to_bytes()
    ue.set_state(FGMMState.DEREGISTERED_INITIATED)
    SecMsg = security_prot_encrypt_ciphered(ue, Msg)
    return SecMsg, '5GMMMODeregistrationRequest'


def ref_deregistration_complete(ue, IEs, Msg=None):
    ue.set_state(FGMMState.DEREGISTERED)
    return None, '5GMMANConnectionReleaseComplete'


def ref_authentication_response(ue, IEs, Msg):
    OP = unhexlify(ue.op)
    key = unhexlify(ue.key)

    sqn_xor_ak, amf, mac = Msg['AUTN']['AUTN'].get_val()
    _, rand = Msg['RAND'].get_val()
    abba = Msg['ABBA']['V'].get_val()

    Mil = Milenage(OP)
    if ue.op_type == 'OPC':
        Mil.set_opc(OP)
    AK = Mil.f5star(key, rand)

    SQN = byte_xor(AK, sqn_xor_ak)

    Mil.f1(unhexlify(ue.key), rand, SQN=SQN, AMF=amf)
    RES, CK, IK, _ = Mil.f2345(key, rand)
    Res = conv_501_A4(CK, IK, ue.sn_name, rand, RES)

    IEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 87}
    IEs['RES'] = Res
    Msg = FGMMAuthenticationResponse(val=IEs)
    ue.MsgInBytes = Msg.to_bytes()
    ue.k_ausf = conv_501_A2(CK, IK, ue.sn_name, sqn_xor_ak)
    ue.k_seaf = conv_501_A6(ue.k_ausf, ue.sn_name)
    ue.k_amf = conv_501_A7(ue.k_seaf, ue.supi.encode('ascii'), abba)
    ue.set_state(FGMMState.AUTHENTICATED_INITIATED)
    return Msg, '5GMMAuthenticationResponse'


def ref_security_mode_complete(ue, IEs, Msg):
    NASSecAlgo = Msg['NASSecAlgo']['NASSecAlgo'].get_val_d()
    ue.CiphAlgo = NASSecAlgo['CiphAlgo']
    ue.IntegAlgo = NASSecAlgo['IntegAlgo']
    ue.k_nas_enc = conv_501_A8(ue.k_amf, alg_type=1, alg_id=NASSecAlgo['CiphAlgo'])
    ue.k_nas_enc = ue.k_nas_enc[16:]
    k_nas_int = conv_501_A8(ue.k_amf, alg_type=2, alg_id=NASSecAlgo['IntegAlgo'])
    ue.set_k_nas_int(k_nas_int)
    ue.k_nas_int = ue.k_nas_int[16:]
    RegIEs = {}
    RegIEs['5GMMHeader'] = {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65}
    RegIEs['NAS_KSI'] = {'TSC': 0, 'Value': 7}
    RegIEs['5GSRegType'] = {'FOR': 1, 'Value': 1}
    RegIEs['5GSID'] = {'spare': 0, 'Fmt': 0, 'spare': 0, 'Type': 1, 'Value': {'PLMN': ue.mcc + ue.mnc,
                                                                              'RoutingInd': b'\x00\x00', 'spare': 0, 'ProtSchemeID': 0, 'HNPKID': 0, 'Output': encode_bcd(ue.msin)}}
    RegIEs['UESecCap'] = {'5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1, '5G-EA4': 0, '5G-EA5': 0, '5G-EA6': 0, '5G-EA7': 0, '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1, '5G-IA4': 0, '5G-IA5': 0,
                          '5G-IA6': 0, '5G-IA7': 0, 'EEA0': 1, 'EEA1_128': 1, 'EEA2_128': 1, 'EEA3_128': 1, 'EEA4': 0, 'EEA5': 0, 'EEA6': 0, 'EEA7': 0, 'EIA0': 1, 'EIA1_128': 1, 'EIA2_128': 1, 'EIA3_128': 1, 'EIA4': 0, 'EIA5': 0, 'EIA6': 0, 'EIA7': 0}
    RegIEs['5GSUpdateType'] = {
        'EPS-PNB-CIoT': 0, '5GS-PNB-CIoT': 0, 'NG-RAN-RCU': 0, 'SMSRequested': 0}
    RegIEs['5GMMCap'] = {'SGC': 0, '5G-HC-CP-CIoT': 0, 'N3Data': 0,
                         '5G-CP-CIoT': 0, 'RestrictEC': 0, 'LPP': 0, 'HOAttach': 0, 'S1Mode': 0}
    RegIEs['NSSAI'] = [{'SNSSAI': s} for s in ue.nssai]

    RegMsg = FGMMRegistrationRequest(val=RegIEs)
    IEs['5GMMHeader'] = { 'EPD': 126, 'spare': 0, 'SecHdr': 0 }
    IEs['IMEISV'] = {'Type': FGSIDTYPE_IMEISV, 'Digit1': int(ue.imeiSv[0]), 'Digits': ue.imeiSv[1:]}
    IEs['NASContainer'] = { }

    Msg = FGMMSecurityModeComplete(val=IEs)
    Msg['NASContainer']['V'].set_val(RegMsg.to_bytes())
    ue.MsgInBytes = Msg.to_bytes()
    ue.ul_nas_count = 0
    SecMsg = security_prot_encrypt_ciphered(ue, Msg)
    ue.set_state(FGMMState.SECURITY_MODE_INITIATED)
    return SecMsg, '5GMMSecurityModeComplete'


def ref_pdu_session_establishment_request(ue, IEs, Msg):
    IEs['5GSMHeader'] = {'EPD': 46,  'PDUSessID': 1, 'PTI': 1, 'Type': 193}
    IEs['PDUSessType'] = { 'Value': 1 }
    IEs['SSCMode'] = { 'Value': 1 }
    Msg = FGSMPDUSessionEstabRequest(val=IEs)
    ue.MsgInBytes = Msg.to_bytes()
    ULIEs = {}
    ULIEs['FGMMHeader'] = {'EPD': 46, 'spare': 0, 'SecHdr': 0, 'Type': 103 }
    ULIEs['PayloadContainerType'] = { 'V': 1 }
    ULIEs['PDUSessID'] = 1
    ULIEs['RequestType'] = { 'Value': 1 }
    session = ue.sessions[0] if getattr(ue, 'sessions', None) else {}
    s_slice = session.get('slice')
    ULIEs['SNSSAI'] = ({'SST': int(s_slice['sst']), 'SD': int(s_slice['sd'])} if 'sd' in s_slice
                       else {'SST': int(s_slice['sst'])}) if s_slice else ue.nssai[0]
    if session.get('apn'):
        ULIEs['DNN'] = session['apn']
    ULMsg = FGMMULNASTransport(val=ULIEs)
    ULMsg['PayloadContainer']['V'].set_val(Msg.to_bytes())
    SecMsg = security_prot_encrypt_ciphered(ue, ULMsg)
    ue.set_state(FGMMState.PDU_SESSION_REQUESTED)
    return SecMsg, '5GSMPDUSessionEstabRequest'


def ref_pdu_session_establishment_complete(ue, IEs, Msg=None):
    ue.IpAddress = Msg['PDUAddress']['PDUAddress'].get_val_d()
    ue.set_state(FGMMState.PDU_SESSION_ESTABLISHED)
    return None, '5GSMPDUSessionEstabComplete'


REF_RESPONSE = {
    '5GMMAuthenticationRequest': ref_authentication_response,
    '5GMMSecurityModeCommand': ref_security_mode_complete,
    '5GMMRegistrationAccept': ref_registration_complete,
    '5GSMPDUSessionEstabAccept': ref_pdu_session_establishment_complete,
    '5GMMMODeregistrationAccept': ref_deregistration_complete,
}
REF_REQUEST = {
    '5GMMRegistrationRequest': ref_registration_request,
    '5GSMPDUSessionEstabRequest': ref_pdu_session_establishment_request,
    '5GMMMODeregistrationRequest': ref_mo_deregistration_request,
}


def ref_downlink(ue, data):
    """ The UE simulator's downlink handling before src/nascache.py: pycrate's parse_NAS5G """
    Msg, err = pycrate_parse_NAS5G(data)
    assert not err
    if Msg._name == '5GMMSecProtNASMessage':
        if Msg['5GMMHeaderSec']['SecHdr'].get_val() == 2:
            Msg.decrypt(ue.k_nas_enc, dir=1, fgea=ue.CiphAlgo, seqnoff=0, bearer=1)
            Msg, err = pycrate_parse_NAS5G(nas_plaintext(Msg))
            assert not err
        else:
            Msg = Msg['5GMMSecurityModeCommand']
    if Msg._name == '5GMMDLNASTransport':
        Msg = Msg['PayloadContainer'][1]
    if Msg._name == '5GMMConfigurationUpdateCommand':
        return None
    SecMsg, _ = REF_RESPONSE[Msg._name](ue, {}, Msg)
    return SecMsg.to_bytes() if SecMsg is not None else None


# --------------------------------------------------------------------------------------------------
# UEs and the AMF's downlink messages
# --------------------------------------------------------------------------------------------------

PLMNS = [('208', '95'), ('001', '01'), ('310', '410'), ('999', '070')]
PROCEDURES = ['5GMMRegistrationRequest', '5GSMPDUSessionEstabRequest', '5GMMMODeregistrationRequest']


def ue_config(rng, i):
    mcc, mnc = PLMNS[i % len(PLMNS)]
    return {'supi': f'{mcc}{mnc}{rng.randrange(10 ** 10):010d}', 'mcc': mcc, 'mnc': mnc,
            'key': rng.randbytes(16).hex(), 'op': rng.randbytes(16).hex(), 'opType': rng.choice(['OP', 'OPC']),
            'amf': '8000', 'imei': '356938035643803', 'imeiSv': ''.join(rng.choice('0123456789') for _ in range(16)),
            'procedures': PROCEDURES,
            'defaultNssai': rng.choice([[{'sst': 1}], [{'sst': 222, 'sd': 123}], [{'sst': 1, 'sd': 66051}, {'sst': 2}]]),
            'sessions': rng.choice([[], [{'type': 'IPv4', 'apn': 'default', 'slice': {'sst': 222, 'sd': 123}}],
                                    [{'type': 'IPv4', 'apn': 'internet', 'slice': {'sst': 1}}],
                                    [{'type': 'IPv4', 'slice': {'sst': 3, 'sd': 1}}], [{'type': 'IPv4', 'apn': 'ims'}]])}


def protect(plain, shdr, ue=None, seqn=0):
    sec = FGMMSecProtNASMessage(val={'5GMMHeaderSec': {'EPD': 126, 'spare': 0, 'SecHdr': shdr}, 'Seqn': seqn})
    sec['NASMessage'].set_val(plain)
    if ue is not None and shdr == 2 and ue.CiphAlgo:
        sec.encrypt(key=ue.k_nas_enc, dir=1, fgea=ue.CiphAlgo, seqnoff=0, bearer=1)
    sec['MAC'].set_val(bytes([seqn, 1, 2, 3]))
    return sec.to_bytes()


def auth_request(rng):
    val = {'NAS_KSI': rng.randrange(7), 'ABBA': b'\x00\x00', 'RAND': rng.randbytes(16), 'AUTN': rng.randbytes(16)}
    return FGMMAuthenticationRequest(val=val).to_bytes()


def security_mode_command(rng, ciph, integ):
    val = {'NASSecAlgo': bytes([ciph << 4 | integ]), 'NAS_KSI': rng.randrange(7),
           # 2 octets (5G algorithms only) or 4 (EPS ones too): pycrate's UESecCap keeps the shorter
           # form in an object that decoded it
           'UESecCap': rng.choice([b'\xf0\xf0', b'\xe0\xe0\xf0\xf0', b'\xf0\x70\x80\x80'])}
    if rng.random() < 0.5:
        val['IMEISVReq'] = 1
    if rng.random() < 0.3:
        val['Add5GSecInfo'] = rng.choice([b'\x00', b'\x02'])
    if rng.random() < 0.3:
        val['ABBA'] = b'\x00\x00'
    plain = FGMMSecurityModeCommand(val=val).to_bytes()
    return protect(plain, 3, seqn=0) if rng.random() < 0.8 else plain


def registration_accept(rng, plmn=b'\x02\xf8\x59'):
    val = {'5GSRegResult': bytes([rng.choice([1, 9, 0x11])])}
    if rng.random() < 0.8:
        val['GUTI'] = b'\xf2' + plmn + b'\x01\x00\x40' + rng.randbytes(4)
    tacs = rng.randrange(1, 4)
    val['5GSTAIList'] = bytes([tacs - 1]) + plmn + b''.join(rng.randrange(1, 1 << 24).to_bytes(3, 'big') for _ in range(tacs))
    if rng.random() < 0.8:
        val['AllowedNSSAI'] = b''.join(rng.sample([b'\x04\xde\x00\x00\x7b', b'\x01\x01', b'\x04\x01\x01\x02\x03'], rng.randrange(1, 4)))
    if rng.random() < 0.5:
        val['5GSNetFeat'] = rng.choice([b'\x01', b'\x01\x00', b'\x03\x00\x01'])
    if rng.random() < 0.5:
        val['T3512'] = bytes([rng.randrange(256)])
    if rng.random() < 0.3:
        val['NetSlicingInd'] = 1
    buf = FGMMRegistrationAccept(val=val).to_bytes()
    if rng.random() < 0.15:
        buf += b'\x7f\x00\x02\xaa\xbb'     # an IE pycrate does not know: appended to the message
    return buf


def configuration_update_command(rng):
    val = {'NetFullName': rng.choice([b'\x81\xcf\x30\x09', b'\x80\x41']), 'NetShortName': b'\x81\xcf\x30\x09'}
    if rng.random() < 0.5:
        val['LocalTimeZone'] = b'\x40'
        val['UnivTimeAndTimeZone'] = rng.randbytes(6) + b'\x40'
    if rng.random() < 0.3:
        val['ConfigUpdateInd'] = 1
    return FGMMConfigurationUpdateCommand(val=val).to_bytes()


def pdu_session_accept(rng):
    sm = FGSMPDUSessionEstabAccept(val={
        '5GSMHeader': {'EPD': 46, 'PDUSessID': 1, 'PTI': 1, 'Type': 194}, 'SSCMode': 1, 'PDUSessType': 1,
        'QoSRules': b'\x01\x00\x06\x31\x31\x01\x01\xff\x09', 'SessAMBR': b'\x06\x00\x64\x06\x00\x64',
        'PDUAddress': b'\x01' + rng.randbytes(4)}).to_bytes()
    return FGMMDLNASTransport(val={'PayloadContainerType': 1, 'PayloadContainer': sm, 'PDUSessID': b'\x01'}).to_bytes()


def registration_reject(rng):
    val = {'5GMMCause': bytes([rng.choice([3, 7, 22])])}
    if rng.random() < 0.5:
        val['T3346'] = b'\x21'
    return FGMMRegistrationReject(val=val).to_bytes()


# --------------------------------------------------------------------------------------------------
# A registration, PDU session and deregistration of many UEs, interleaved
# --------------------------------------------------------------------------------------------------

def ue_state(ue):
    return (ue.MsgInBytes, ue.ul_nas_count, ue.k_amf, ue.k_nas_enc, ue.k_nas_int, ue.CiphAlgo, ue.IntegAlgo,
            ue.state, ue.IpAddress)


def make_sim(ues):
    sim = UESim.__new__(UESim)               # only what dispatcher() uses
    sim.ue_list = dict(ues)
    sim.procedures_count = {}
    sim.ue_fg_msg_states = Array('i', 300)
    sim.inflight = None
    return sim


def steps(rng, ciph, integ):
    """ One UE's messages: None for an uplink message the UE starts, or a function of the UE giving a
    downlink message """
    s = [None, lambda ue: auth_request(rng), lambda ue: security_mode_command(rng, ciph, integ),
         lambda ue: protect(registration_accept(rng), 2, ue, seqn=1)]
    if rng.random() < 0.5:
        s.append(lambda ue: protect(configuration_update_command(rng), 2, ue, seqn=2))
    s += [None, lambda ue: protect(pdu_session_accept(rng), 2, ue, seqn=3), None,
          lambda ue: protect(FGMMMODeregistrationAccept().to_bytes(), 2, ue, seqn=4)]
    return s


def run_ues(sim, ids, seed):
    """ Runs the UEs ids of sim (and a twin of each, through the old builders) in a random order;
    returns how many messages were compared """
    rng = random.Random(seed)
    twins = {i: UE(sim.ue_config[i]) for i in ids}
    pending = {i: steps(rng, *rng.choice([(0, 2), (0, 1), (1, 1), (2, 2), (2, 1), (1, 2)])) for i in ids}
    compared = 0
    while pending:
        i = rng.choice(sorted(pending))
        step = pending[i].pop(0)
        if not pending[i]:
            del pending[i]
        ue, twin = sim.ue_list[i], twins[i]
        if step is None:                     # the UE's next procedure
            sent, _, sent_type = sim.dispatcher(None, i)
            twin.procedure = sent_type
            ref_msg, _ = REF_REQUEST[sent_type](twin, {}, None)
            ref = ref_msg.to_bytes()
        else:
            data = step(twin)
            sent = sim.dispatcher(data, i)[0]
            ref = ref_downlink(twin, data)
        assert sent == ref, f'UE {i}: {sent!r} != {ref!r}'
        assert ue_state(ue) == ue_state(twin), f'UE {i}'
        compared += 1
    return compared


@pytest.fixture
def quiet(monkeypatch):
    monkeypatch.setattr(src.UESim, 'g_verbose', 1, raising=False)


def make_ues(seed, n):
    rng = random.Random(seed)
    configs = {i: ue_config(rng, i) for i in range(n)}
    sim = make_sim({i: UE(c) for i, c in configs.items()})
    sim.ue_config = configs
    return sim


def test_ues_send_what_fresh_objects_send(quiet):
    sim = make_ues(1, 60)
    assert run_ues(sim, list(sim.ue_list), seed=2) >= 60 * 8


def test_ues_on_several_threads_send_what_fresh_objects_send(quiet):
    """ The UE simulator builds and decodes in its init() thread and in two workers at once """
    sim = make_ues(3, 90)
    errors, counts = [], []

    def worker(ids, seed):
        try:
            counts.append(run_ues(sim, ids, seed))
        except Exception as e:               # pragma: no cover - reported below
            errors.append(e)
    threads = [threading.Thread(target=worker, args=(list(range(k, 90, 3)), 10 + k)) for k in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert sum(counts) >= 90 * 8


# --------------------------------------------------------------------------------------------------
# Decoding: nascache.parse_NAS5G against pycrate's
# --------------------------------------------------------------------------------------------------

def view(msg):
    """ What the UE simulator can see of a decoded message. (repr() also shows the fields of optional
    IEs a message does not carry: a reused object's keep an earlier message's values.) """
    if msg is None:
        return None
    return (msg._name, msg.to_bytes(), msg.get_val(), msg.get_val_d(), msg.show(),
            [(e._name, e.get_trans()) for e in msg._content], msg.get_hier_abs())


def downlink_messages(rng, n):
    keys = type('K', (), {'k_nas_enc': rng.randbytes(16), 'CiphAlgo': 0})()
    makers = [lambda: auth_request(rng), lambda: security_mode_command(rng, rng.randrange(3), rng.randrange(1, 3)),
              lambda: registration_accept(rng), lambda: configuration_update_command(rng),
              lambda: pdu_session_accept(rng), lambda: registration_reject(rng),
              lambda: FGMMMODeregistrationAccept().to_bytes(),
              lambda: protect(registration_accept(rng), 2, keys, seqn=rng.randrange(256)),
              lambda: protect(configuration_update_command(rng), rng.choice([1, 2, 3, 4]))]
    msgs = [rng.choice(makers)() for _ in range(n)]
    # and some that do not decode: truncated, or an unknown message type
    msgs += [m[:rng.randrange(1, len(m))] for m in rng.sample(msgs, n // 10)]
    msgs += [b'\x7e\x00\x99', b'\x2e\x01\x01', b'\x00\x00\x00']
    rng.shuffle(msgs)
    return msgs


def test_decoding_gives_what_fresh_objects_give():
    rng = random.Random(4)
    msgs = downlink_messages(rng, 600)
    for buf in msgs + msgs[::-1]:
        ours, err = nascache.parse_NAS5G(buf)
        ref, ref_err = pycrate_parse_NAS5G(buf)
        assert err == ref_err, buf.hex()
        assert view(ours) == view(ref), buf.hex()


def test_decrypted_messages_decode_as_before():
    """ security_prot_decrypt(): the plain message in a 5G-EA1/EA2 ciphered or a 5G-EA0 message """
    rng = random.Random(5)
    for _ in range(300):
        ue = type('UE', (), {'k_nas_enc': rng.randbytes(16), 'CiphAlgo': rng.choice([0, 1, 2])})()
        plain = rng.choice([registration_accept, configuration_update_command, pdu_session_accept])(rng)
        buf = protect(plain, 2, ue, seqn=rng.randrange(256))
        ours = security_prot_decrypt(nascache.parse_NAS5G(buf)[0], ue)
        ref = pycrate_parse_NAS5G(buf)[0]
        ref.decrypt(ue.k_nas_enc, dir=1, fgea=ue.CiphAlgo, seqnoff=0, bearer=1)
        ref = pycrate_parse_NAS5G(nas_plaintext(ref))[0]
        assert view(ours) == view(ref)
        if not plain.endswith(b'\x7f\x00\x02\xaa\xbb'):   # pycrate encodes an unknown IE otherwise
            assert ours.to_bytes() == plain


def test_a_message_with_an_unknown_ie_is_not_reused():
    rng = random.Random(6)
    odd = registration_accept(rng) + b'\x7f\x00\x02\xaa\xbb'
    msg, _ = nascache.parse_NAS5G(odd)
    assert msg[-1]._name.startswith('_T_')
    plain = FGMMRegistrationAccept(val={'5GSRegResult': b'\x01', '5GSTAIList': b'\x00\x02\xf8\x59\x00\x00\x01'}).to_bytes()
    msg2, _ = nascache.parse_NAS5G(plain)
    assert msg2 is not msg and view(msg2) == view(pycrate_parse_NAS5G(plain)[0])


def test_each_thread_decodes_into_objects_of_its_own():
    buf = FGMMMODeregistrationAccept().to_bytes()
    seen = []
    t = threading.Thread(target=lambda: seen.append(nascache.parse_NAS5G(buf)[0]))
    t.start()
    t.join()
    assert nascache.parse_NAS5G(buf)[0] is not seen[0]


# --------------------------------------------------------------------------------------------------
# MessageTemplate: build() against the class's constructor
# --------------------------------------------------------------------------------------------------

def built_view(msg):
    return (msg.to_bytes(), msg.get_val(), msg.show(), [(e._name, e.get_trans()) for e in msg._content])


def test_build_gives_what_the_constructor_gives():
    """ Optional IEs set in one message and not in the next, values of other forms and lengths """
    rng = random.Random(7)
    ul = MessageTemplate(FGMMULNASTransport, {'PayloadContainerType': {'V': 1}, 'RequestType': {'Value': 1}})
    reg = MessageTemplate(FGMMRegistrationRequest, {'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65},
                                                    '5GSRegType': {'FOR': 1, 'Value': 1}})
    for _ in range(400):
        val = {'PDUSessID': rng.randrange(1, 16),
               'SNSSAI': rng.choice([{'SST': 1}, {'SST': 222, 'SD': 123}, {'SST': 2, 'SD': 1, 'MappedHPLMNSST': 3}])}
        if rng.random() < 0.5:
            val['DNN'] = rng.choice(['default', 'internet', 'ims.mnc095.mcc208.gprs'])
        if rng.random() < 0.3:
            val['RequestType'] = {'Value': rng.randrange(1, 4)}      # a fixed IE, set in this message
        assert built_view(ul.build(dict(val))) == built_view(FGMMULNASTransport(val={**ul.fixed, **val}))

        mcc, mnc = rng.choice(PLMNS)
        val = {'NAS_KSI': {'TSC': rng.randrange(2), 'Value': rng.randrange(8)},
               '5GSID': rng.choice([
                   {'Fmt': 0, 'Type': 1, 'Value': {'PLMN': mcc + mnc, 'RoutingInd': b'\x00\x00', 'ProtSchemeID': 0,
                                                   'HNPKID': 0, 'Output': encode_bcd(f'{rng.randrange(10 ** 10):010d}')}},
                   {'Type': 2, 'PLMN': mcc + mnc, 'AMFRegionID': 1, 'AMFSetID': 1, 'AMFPtr': 0, '5GTMSI': rng.randrange(1 << 32)}])}
        for name, value in [('NSSAI', [{'SNSSAI': s} for s in rng.sample([{'SST': 1}, {'SST': 2, 'SD': 3}, {'SST': 4}], rng.randrange(1, 4))]),
                            ('UESecCap', rng.choice([{'5G-EA0': 1, '5G-IA2_128': 1}, {'5G-EA0': 1, 'EEA0': 1, 'EIA2_128': 1}])),
                            ('UEStatus', {'N1ModeReg': 1, 'S1ModeReg': rng.randrange(2)}),
                            ('NASContainer', rng.randbytes(rng.randrange(2, 9)))]:
            if rng.random() < 0.5:
                val[name] = value
        assert built_view(reg.build(dict(val))) == built_view(FGMMRegistrationRequest(val={**reg.fixed, **val}))


def test_each_thread_builds_on_objects_of_its_own():
    t = MessageTemplate(FGMMRegistrationComplete, {'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 67}})
    seen = []
    th = threading.Thread(target=lambda: seen.append(t.build({})))
    th.start()
    th.join()
    assert t.build({}) is not seen[0] and t.build({}) is t.build({})
