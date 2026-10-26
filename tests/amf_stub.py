""" A scripted AMF for end-to-end tests: NGAP over SCTP on the loopback, with the downlink messages of a
registration, a PDU session and a deregistration as OAI's AMF sends them (5G-EA0, 5G-IA2; the MACs are
not checked by CN-TG's UEs, so they are zero here).

It records every uplink NGAP message per association and RAN UE NGAP ID, with the User Location
Information's time stamp zeroed, so that two runs of CN-TG can be compared byte for byte. Its AMF UE
NGAP IDs follow the RAN UE NGAP IDs, so a UE's messages do not depend on the order UEs arrive in.

    python3 tests/amf_stub.py PORT OUT.json    # until SIGTERM or SIGINT, then the records in OUT.json
"""
import json
import select
import signal
import socket
import sys
import threading

import sctp
from pycrate_asn1dir import NGAP
from pycrate_mobile.TS24501_FGMM import (FGMMAuthenticationRequest, FGMMDLNASTransport, FGMMMODeregistrationAccept,
                                         FGMMRegistrationAccept, FGMMSecProtNASMessage, FGMMSecurityModeCommand)
from pycrate_mobile.TS24501_FGSM import FGSMPDUSessionEstabAccept

PLMN = b'\x02\xf8\x59'          # 208 95
SCTP_NODELAY = getattr(socket, 'SCTP_NODELAY', 3)
RAND = bytes(range(16))
AUTN = bytes(range(16, 32))
AMF_ID_OFFSET = 1000

_pdu_lock = threading.Lock()    # pycrate's NGAP_PDU is one shared object


# Downlink NAS

def _protect(plain, shdr, seqn):
    sec = FGMMSecProtNASMessage(val={'5GMMHeaderSec': {'EPD': 126, 'spare': 0, 'SecHdr': shdr}, 'Seqn': seqn})
    sec['NASMessage'].set_val(plain)
    sec['MAC'].set_val(b'\x00\x00\x00\x00')
    return sec.to_bytes()


def authentication_request():
    return FGMMAuthenticationRequest(val={'NAS_KSI': {'TSC': 0, 'Value': 0}, 'ABBA': b'\x00\x00',
                                          'RAND': RAND, 'AUTN': AUTN}).to_bytes()


def security_mode_command():
    smc = FGMMSecurityModeCommand(val={
        'NASSecAlgo': {'CiphAlgo': 0, 'IntegAlgo': 2}, 'NAS_KSI': {'TSC': 0, 'Value': 0},
        'UESecCap': {'5G-EA0': 1, '5G-EA1_128': 1, '5G-EA2_128': 1, '5G-EA3_128': 1,
                     '5G-IA0': 1, '5G-IA1_128': 1, '5G-IA2_128': 1, '5G-IA3_128': 1},
        'IMEISVReq': {'Value': 1}}).to_bytes()
    return _protect(smc, 3, 0)


def registration_accept(tmsi):
    ra = FGMMRegistrationAccept(val={
        '5GSRegResult': b'\x01', 'GUTI': b'\xf2' + PLMN + b'\x01\x00\x40' + tmsi.to_bytes(4, 'big'),
        '5GSTAIList': b'\x00' + PLMN + b'\x00\xa0\x00', 'AllowedNSSAI': b'\x04\xde\x00\x00\x7b',
        'T3512': b'\x06'}).to_bytes()
    return _protect(ra, 2, 1)


def pdu_session_establishment_accept(address):
    sm = FGSMPDUSessionEstabAccept(val={'5GSMHeader': {'EPD': 46, 'PDUSessID': 1, 'PTI': 1, 'Type': 194},
                                         'PDUSessType': {'Value': 1}, 'SSCMode': {'Value': 1},
                                         'QoSRules': b'\x01\x00\x06\x31\x31\x01\x01\xff\x09',
                                         'SessAMBR': b'\x06\x00\x64\x06\x00\x64',
                                         'PDUAddress': {'Type': 1, 'Addr': address}}).to_bytes()
    dl = FGMMDLNASTransport(val={'PayloadContainerType': {'V': 1}, 'PDUSessID': 1})
    dl['PayloadContainer']['V'].set_val(sm)
    return _protect(dl.to_bytes(), 2, 2)


def deregistration_accept():
    return _protect(FGMMMODeregistrationAccept().to_bytes(), 2, 3)


def nas_type(nas):
    """ The 5GMM message type of an uplink NAS PDU, plain or protected without ciphering (5G-EA0) """
    if len(nas) >= 3 and nas[1] & 0x0F:
        nas = nas[7:]
    return nas[2] if len(nas) >= 3 else None


# NGAP

UPLINK_NAMES = {('initiatingMessage', 15): 'initial-ue', ('successfulOutcome', 14): 'context-setup-response',
                ('successfulOutcome', 29): 'setup-response', ('successfulOutcome', 41): 'release-complete'}


def _what(kind, code, ies):
    """ An uplink message's name in AMFStub.arrivals """
    if kind == 'initiatingMessage' and code == 46:
        return f'nas-0x{nas_type(ies[38]):02x}'
    return UPLINK_NAMES.get((kind, code), f'{kind}-{code}')


def _ies(pdu):
    return {ie['id']: ie['value'][1] for ie in pdu.get_val()[1]['value'][1]['protocolIEs']}


def _encode(val):
    pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    pdu.set_val(val)
    return pdu.to_aper()


def _ue_ids(amf_id, ran_id):
    return [{'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', amf_id)},
            {'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', ran_id)}]


def downlink_nas_transport(amf_id, ran_id, nas):
    return _encode(('initiatingMessage', {'procedureCode': 4, 'criticality': 'ignore', 'value': (
        'DownlinkNASTransport', {'protocolIEs': _ue_ids(amf_id, ran_id) + [
            {'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', nas)}]})}))


def initial_context_setup_request(amf_id, ran_id, nas):
    return _encode(('initiatingMessage', {'procedureCode': 14, 'criticality': 'reject', 'value': (
        'InitialContextSetupRequest', {'protocolIEs': _ue_ids(amf_id, ran_id) + [
            {'id': 38, 'criticality': 'ignore', 'value': ('NAS-PDU', nas)}]})}))


def pdu_session_resource_setup_request(amf_id, ran_id, nas):
    """ With the IEs OAI's AMF and SMF send (experiment 06's captures): the session's and the UE's
    aggregate maximum bit rates, the UPF's tunnel, the PDU session type, one QoS flow (5QI 9) """
    transfer = ('PDUSessionResourceSetupRequestTransfer', {'protocolIEs': [
        {'id': 130, 'criticality': 'reject', 'value': ('PDUSessionAggregateMaximumBitRate', {
            'pDUSessionAggregateMaximumBitRateDL': 1 << 30, 'pDUSessionAggregateMaximumBitRateUL': 1 << 30})},
        {'id': 139, 'criticality': 'reject', 'value': ('UPTransportLayerInformation', ('gTPTunnel', {
            'transportLayerAddress': (0x7F000002, 32), 'gTP-TEID': (0x10000 + ran_id).to_bytes(4, 'big')}))},
        {'id': 134, 'criticality': 'reject', 'value': ('PDUSessionType', 'ipv4')},
        {'id': 136, 'criticality': 'reject', 'value': ('QosFlowSetupRequestList', [{
            'qosFlowIdentifier': 1, 'qosFlowLevelQosParameters': {
                'qosCharacteristics': ('nonDynamic5QI', {'fiveQI': 9, 'priorityLevelQos': 0}),
                'allocationAndRetentionPriority': {'priorityLevelARP': 1,
                                                   'pre-emptionCapability': 'shall-not-trigger-pre-emption',
                                                   'pre-emptionVulnerability': 'not-pre-emptable'}}}])}]})
    item = {'pDUSessionID': 1, 'pDUSessionNAS-PDU': nas, 's-NSSAI': {'sST': b'\xde', 'sD': b'\x00\x00\x7b'},
            'pDUSessionResourceSetupRequestTransfer': transfer}
    return _encode(('initiatingMessage', {'procedureCode': 29, 'criticality': 'reject', 'value': (
        'PDUSessionResourceSetupRequest', {'protocolIEs': _ue_ids(amf_id, ran_id) + [
            {'id': 74, 'criticality': 'reject', 'value': ('PDUSessionResourceSetupListSUReq', [item])},
            {'id': 110, 'criticality': 'ignore', 'value': ('UEAggregateMaximumBitRate', {
                'uEAggregateMaximumBitRateDL': 10**9, 'uEAggregateMaximumBitRateUL': 10**9})}]})}))


def ue_context_release_command(amf_id, ran_id):
    return _encode(('initiatingMessage', {'procedureCode': 41, 'criticality': 'reject', 'value': (
        'UEContextReleaseCommand', {'protocolIEs': [
            {'id': 114, 'criticality': 'reject', 'value': ('UE-NGAP-IDs', ('uE-NGAP-ID-pair', {
                'aMF-UE-NGAP-ID': amf_id, 'rAN-UE-NGAP-ID': ran_id}))},
            {'id': 15, 'criticality': 'ignore', 'value': ('Cause', ('nas', 'deregister'))}]})}))


class AMFStub:
    """ Serves CN-TG's gNBs, one association each, until stop() """

    def __init__(self, host='127.0.0.1', port=0):
        self.server = sctp.sctpsocket_tcp(socket.AF_INET)
        self.server.sock().setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(16)
        self.port = self.server.sock().getsockname()[1]
        self.lock = threading.Lock()
        self.uplink = {}        # (association, RAN UE NGAP ID) -> [uplink NGAP, hex, time stamp zeroed]
        self.setups = {}        # association -> its NG Setup Request
        self.released = set()   # (association, RAN UE NGAP ID) that completed the UE context release
        # (association, RAN UE NGAP ID, what) per uplink message, in arrival order: what is the NGAP
        # message (initial-ue, setup-response for the PDU Session Resource Setup Response, ...), or
        # nas-0x<type> for an Uplink NAS Transport (nas-0x43: the Registration Complete)
        self.arrivals = []
        self.errors = []
        self._stop = threading.Event()
        self._threads = []

    def start(self):
        t = threading.Thread(target=self._accept, daemon=True)
        t.start()
        self._threads.append(t)
        return self

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(2)
        self.server.close()

    def records(self):
        """ The uplink messages, keyed 'association/RAN UE NGAP ID' """
        with self.lock:
            out = {f'{a}/{r}': list(msgs) for (a, r), msgs in sorted(self.uplink.items())}
            out.update({f'{a}/setup': [m] for a, m in sorted(self.setups.items())})
            return out

    def _accept(self):
        n = 0
        while not self._stop.is_set():
            r, _, _ = select.select([self.server.sock()], [], [], 0.2)
            if not r:
                continue
            conn, _ = self.server.accept()
            # Each answer at once: with Nagle's algorithm, the second of two answers (a Deregistration
            # Accept, then the UE Context Release Command) waits for the gNB's delayed SACK, 200 ms
            conn.sock().setsockopt(socket.IPPROTO_SCTP, SCTP_NODELAY, 1)
            t = threading.Thread(target=self._serve, args=(conn, n), daemon=True)
            t.start()
            self._threads.append(t)
            n += 1

    def _serve(self, conn, assoc):
        sock = conn.sock()
        while not self._stop.is_set():
            r, _, _ = select.select([sock], [], [], 0.2)
            if not r:
                continue
            try:
                data = conn.recv(65536)
            except OSError:
                return
            if not data:
                return
            try:
                for answer in self._handle(assoc, data):
                    conn.sctp_send(answer, ppid=socket.htonl(60))
            except Exception as e:      # recorded: a test fails on it
                self.errors.append(f'{type(e).__name__}: {e}')

    def _handle(self, assoc, data):
        with _pdu_lock:
            pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
            pdu.from_aper(data)
            kind, val = pdu.get_val()
            code = val['procedureCode']
            ies = _ies(pdu)
            masked = data
            uli = ies.get(121)
            if uli is not None:
                stamp = uli[1].get('timeStamp')
                if stamp:
                    masked = data.replace(stamp, b'\x00' * len(stamp), 1)
            if code == 21:
                with self.lock:
                    self.setups[assoc] = masked.hex()
                return []
            ran_id = ies.get(85)
            if ran_id is None and 114 in ies:
                ran_id = ies[114][1]['rAN-UE-NGAP-ID']
            with self.lock:
                self.uplink.setdefault((assoc, ran_id), []).append(masked.hex())
                self.arrivals.append((assoc, ran_id, _what(kind, code, ies)))
            amf_id = ran_id + AMF_ID_OFFSET
            if kind == 'initiatingMessage' and code == 15:          # Initial UE Message
                return [downlink_nas_transport(amf_id, ran_id, authentication_request())]
            if kind == 'initiatingMessage' and code == 46:          # Uplink NAS Transport
                t = nas_type(ies[38])
                if t == 0x57:       # Authentication Response
                    return [downlink_nas_transport(amf_id, ran_id, security_mode_command())]
                if t == 0x5E:       # Security Mode Complete
                    return [initial_context_setup_request(amf_id, ran_id, registration_accept(ran_id))]
                if t == 0x67:       # UL NAS Transport: PDU Session Establishment Request
                    address = bytes((12, 1, (ran_id >> 8) & 0xFF, ran_id & 0xFF))
                    return [pdu_session_resource_setup_request(amf_id, ran_id, pdu_session_establishment_accept(address))]
                if t == 0x45:       # Deregistration Request (UE originating)
                    return [downlink_nas_transport(amf_id, ran_id, deregistration_accept()),
                            ue_context_release_command(amf_id, ran_id)]
                return []           # Registration Complete
            if kind == 'successfulOutcome' and code == 41:          # UE Context Release Complete
                with self.lock:
                    self.released.add((assoc, ran_id))
            return []


def main():
    port, out = int(sys.argv[1]), sys.argv[2]
    amf = AMFStub(port=port).start()
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    signal.signal(signal.SIGINT, lambda *_: done.set())
    while not done.wait(0.2):
        pass
    amf.stop()
    with open(out, 'w') as f:
        json.dump({'uplink': amf.records(), 'released': sorted(f'{a}/{r}' for a, r in amf.released),
                   'errors': amf.errors}, f, indent=1)


if __name__ == '__main__':
    main()
