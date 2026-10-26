""" The gNB's NGAP messages without pycrate objects: byte templates for the uplink messages of a
registration, a PDU session's setup and a UE context release, and a light parser for the downlink
messages the gNB answers.

Step 0's profile of the gNB processes put pycrate's APER codec at about a third of their CPU (encode
22%, decode 13%), and G14 left the gNB processes with most of CN-TG's CPU. Here, as G14's
src/nasfast.py does for NAS:

- Uplink: Uplink(plmn, nci, tac) holds a gNB's constant parts (the User Location Information, whose
  NR-CGI and TAI are the gNB's). Its initial_ue_message() and uplink_nas_transport(), and the module's
  initial_context_setup_response(), pdu_session_resource_setup_response() and
  ue_context_release_complete(), give the bytes pycrate gives for the PDUs src/NGAPSim.py builds,
  with the same IEs in the same order: the UE NGAP IDs, the NAS PDU, the time stamp, the
  establishment cause, the 5G-S-TMSI, the PDU session ID, the gNB's DL NG-U tunnel and the QoS flows
  spliced in with their APER encodings (X.691):
    - AMF-UE-NGAP-ID, INTEGER (0..2^40-1): the number of octets less one in 3 bits, then the
      value in that many octets (at least one); RAN-UE-NGAP-ID, INTEGER (0..2^32-1): the same
      with 2 bits;
    - the NAS-PDU (OCTET STRING), each IE's value (an open type), the message's value (an open
      type holding the IE container) and the PDUSessionResourceSetupResponseTransfer (an OCTET
      STRING holding its encoding): a length determinant, one octet below 128, two below 16384,
      and from 16384 fragments of 64K, 48K, 32K and 16K octets as pycrate cuts them, each after its
      own octet (0xC4 .. 0xC1), then the rest's length (perhaps 0);
    - the 5G-S-TMSI: the AMF Set ID's 10 bits and the AMF Pointer's 6 bits after the SEQUENCE's
      extension and option bits, padding, then the 5G-TMSI's four octets;
    - the PDU session ID, INTEGER (0..255): an octet; the transport layer address, BIT STRING
      (SIZE(1..160, ...)): its extension bit, its size less one in 8 bits, padding, the address's
      octets; the GTP-TEID: its four octets; the QFIs, INTEGER (0..63, ...), in their list's bit
      fields (see pdu_session_resource_setup_response()).
  They give None for what they do not cover (an id out of its range or not an int, an unknown
  cause, a 5G-S-TMSI not of 6 octets, a cell identity, PLMN or TAC of another size, a QFI outside
  0..63, an address not of 4, 16 or 20 octets, any exception), and the caller builds the message
  with pycrate as before, which meets the same problem or encodes what the template does not.
- Downlink: downlink() parses a DownlinkNASTransport, an InitialContextSetupRequest, a
  PDUSessionResourceSetupRequest and a UEContextReleaseCommand into what the gNB reads from them: the
  procedure code, the AMF and RAN UE NGAP IDs (in the UEContextReleaseCommand, its UE-NGAP-IDs'
  pair), the NAS-PDU and, for the PDU Session Resource Setup Request, its PDU session (one, with its
  own NAS-PDU): the PDU session ID and from its PDUSessionResourceSetupRequestTransfer the UL NG-U
  tunnel (the UPF's transport layer address and TEID), the first QoS flow's QFI and the PDU session
  type. Each IE, in a message or in the transfer, must be one of its IE set's (pycrate's), with that
  set's criticality and in that set's order (each at most once, as OAI's AMF and SMF send them);
  every length must be in its canonical form below 16384 and must end where its value ends; every
  extension bit and padding bit must be 0. The IEs the gNB does not read are not decoded: one whose
  type is a fixed-size BIT or OCTET STRING of whole octets (SecurityKey, MaskedIMEISV) must have
  that size, and any other must be, byte for byte, one pycrate decoded before in a message of the
  same procedure (or a transfer): learn() records them after pycrate's path has decoded a message,
  each once pycrate's object for that IE's value has decoded all of it and encoded it back the same
  (at most MAX_LEARNT). The QoS flow setup list is one of these (its QoS parameters are the SMF's,
  the same for each session), and the parser reads its first QFI from the bytes pycrate decoded.
  Anything else gives None and the caller decodes the message with pycrate as before: other
  procedures and PDU types, fragmented lengths, an IE the parser has not seen, a UE-NGAP-IDs that is
  not a pair, ids in a form pycrate decodes but does not encode (more octets than the value needs),
  a PDU session list of more than one item or without the item's NAS-PDU, a tunnel with an address
  of other than 32, 128 or 160 bits, IE extensions, and any exception.

The NGSetupRequest stays with pycrate (once per gNB). The gNB uses pycrate's path for every message
when messages are logged (debug), which needs pycrate objects, and with run.py --no-ngap-fastpath.
"""
import struct
import time
from collections import namedtuple

from pycrate_asn1dir import NGAP

_NTP_OFFSET = 2208988800            # the User Location Information's time stamp counts from 1900


# --------------------------------------------------------------------------------------------------
# APER
# --------------------------------------------------------------------------------------------------

_FRAGMENTS = (65536, 49152, 32768, 16384)


def wrap(value):
    """ value after its unconstrained length determinant (X.691 §11.9.3.8): an octet string, or an
    open type's encoding, as pycrate encodes them (fragments as pycrate's factor_perfrag cuts them) """
    n = len(value)
    if n < 128:
        return bytes((n,)) + value
    if n < 16384:
        return bytes((0x80 | n >> 8, n & 0xFF)) + value
    out, off = [], 0
    for size in _FRAGMENTS:
        for _ in range((n - off) // size):
            out.append(bytes((0xC0 | size >> 14,)))
            out.append(value[off:off + size])
            off += size
    rest = n - off
    out.append(bytes((rest,)) if rest < 128 else bytes((0x80 | rest >> 8, rest & 0xFF)))
    out.append(value[off:])
    return b''.join(out)


def _uint(v, ubits, lbits):
    """ An INTEGER (0..2^ubits-1) whose range exceeds 64K: (octets - 1) in lbits bits, padding, the
    value in the fewest octets (one for 0); None out of range """
    if type(v) is not int or v < 0 or v >> ubits:
        return None
    n = (v.bit_length() + 7) >> 3 or 1
    return bytes(((n - 1) << (8 - lbits),)) + v.to_bytes(n, 'big')


def amf_ue_ngap_id(v):
    """ AMF-UE-NGAP-ID ::= INTEGER (0..1099511627775), APER """
    return _uint(v, 40, 3)


def ran_ue_ngap_id(v):
    """ RAN-UE-NGAP-ID ::= INTEGER (0..4294967295), APER """
    return _uint(v, 32, 2)


# Criticality ::= ENUMERATED {reject, ignore, notify}: 2 bits, then the open type's padding
REJECT, IGNORE = b'\x00', b'\x40'


def _ie(ie_id, crit, value):
    """ A ProtocolIE-Field: the id (2 octets), the criticality and the value as an open type """
    return ie_id.to_bytes(2, 'big') + crit + wrap(value)


def _message(head, ies):
    """ An NGAP-PDU: its choice and procedure code (one octet each), its criticality, then the
    message (a SEQUENCE with its extension bit 0 and the IE container's count) as an open type """
    return head + wrap(b'\x00' + len(ies).to_bytes(2, 'big') + b''.join(ies))


# --------------------------------------------------------------------------------------------------
# Uplink
# --------------------------------------------------------------------------------------------------

# NGAP-PDU's choice (initiatingMessage 0x00, successfulOutcome 0x20), the procedure code and its
# criticality
_INITIAL_UE_MESSAGE = b'\x00\x0f' + IGNORE
_UPLINK_NAS_TRANSPORT = b'\x00\x2e' + IGNORE
_INITIAL_CONTEXT_SETUP_RESPONSE = b'\x20\x0e' + REJECT
_PDU_SESSION_RESOURCE_SETUP_RESPONSE = b'\x20\x1d' + REJECT
_UE_CONTEXT_RELEASE_COMPLETE = b'\x20\x29' + REJECT

# RRCEstablishmentCause ::= ENUMERATED {10 values, ...}: the extension bit 0, the index in 4 bits;
# UEContextRequest ::= ENUMERATED {requested, ...}: the extension bit only
_CAUSES = tuple(_ie(90, IGNORE, bytes((i << 3,))) for i in range(10))
_UE_CONTEXT_REQUESTED = _ie(112, IGNORE, b'\x00')


def _nas_pdu(nas):
    if type(nas) is not bytes:
        return None
    return _ie(38, REJECT, wrap(nas))


def _ids(crit_amf, crit_ran, amf_id, ran_id):
    a, r = amf_ue_ngap_id(amf_id), ran_ue_ngap_id(ran_id)
    if a is None or r is None:
        return None
    return _ie(10, crit_amf, a), _ie(85, crit_ran, r)


def _stamp(now):
    """ The time stamp src/NGAPSim.py puts in the User Location Information """
    return struct.pack('!I', int(time.time() if now is None else now) + _NTP_OFFSET)


class Uplink:
    """ A gNB's uplink messages: its PLMN identity (3 octets), NR cell identity (36 bits) and TAC
    (3 octets) are those of its User Location Information """

    def __init__(self, plmn_identity, nr_cell_identity, tac):
        plmn, tac = bytes(plmn_identity), bytes(tac)
        if len(plmn) != 3 or len(tac) != 3 or type(nr_cell_identity) is not int or not 0 <= nr_cell_identity < 1 << 36:
            raise ValueError('a PLMN identity, NR cell identity or TAC of another size')
        # UserLocationInformation ::= CHOICE (no extension marker): userLocationInformationNR (index 1,
        # 2 bits); its SEQUENCE's extension bit 0, timeStamp present, no iE-Extensions; the NR-CGI's
        # extension and option bits 0; then the PLMN, the cell identity's 36 bits followed by the
        # TAI's extension and option bits (0) and padding, the TAI's PLMN and TAC, and the time stamp
        value = b'\x50' + plmn + (nr_cell_identity << 4).to_bytes(5, 'big') + plmn + tac
        self._uli = {crit: b'\x00\x79' + crit + bytes((len(value) + 4,)) + value for crit in (REJECT, IGNORE)}

    def initial_ue_message(self, ran_id, nas, cause=3, s_tmsi=None, now=None):
        """ src/NGAPSim.py's InitialUEMessage: NAS-PDU, User Location Information, RAN-UE-NGAP-ID,
        RRC establishment cause (an index into its enumeration), the 5G-S-TMSI (6 octets: AMF Set ID
        and Pointer in 2, the 5G-TMSI in 4) if any, UE context requested """
        try:
            r = ran_ue_ngap_id(ran_id)
            nas_ie = _nas_pdu(nas)
            if r is None or nas_ie is None or type(cause) is not int or not 0 <= cause < len(_CAUSES):
                return None
            ies = [nas_ie, self._uli[REJECT] + _stamp(now), _ie(85, REJECT, r), _CAUSES[cause]]
            if s_tmsi:
                s_tmsi = bytes(s_tmsi)
                if len(s_tmsi) != 6:
                    return None
                # FiveG-S-TMSI ::= SEQUENCE {aMFSetID (10 bits), aMFPointer (6 bits), fiveG-TMSI (4
                # octets), iE-Extensions OPTIONAL, ...}: extension and option bits, the 16 bits,
                # padding, the octets
                ies.append(_ie(26, REJECT, (int.from_bytes(s_tmsi[:2], 'big') << 6).to_bytes(3, 'big') + s_tmsi[2:]))
            ies.append(_UE_CONTEXT_REQUESTED)
            return _message(_INITIAL_UE_MESSAGE, ies)
        except Exception:
            return None

    def uplink_nas_transport(self, amf_id, ran_id, nas, now=None):
        """ src/NGAPSim.py's UplinkNASTransport: NAS-PDU, User Location Information, the UE NGAP IDs """
        try:
            ids = _ids(REJECT, REJECT, amf_id, ran_id)
            nas_ie = _nas_pdu(nas)
            if ids is None or nas_ie is None:
                return None
            return _message(_UPLINK_NAS_TRANSPORT, [nas_ie, self._uli[IGNORE] + _stamp(now), *ids])
        except Exception:
            return None


def initial_context_setup_response(amf_id, ran_id):
    """ src/NGAPSim.py's InitialContextSetupResponse: the UE NGAP IDs """
    ids = _ids(IGNORE, IGNORE, amf_id, ran_id)
    return _message(_INITIAL_CONTEXT_SETUP_RESPONSE, ids) if ids is not None else None


def ue_context_release_complete(amf_id, ran_id):
    """ src/NGAPSim.py's UEContextReleaseComplete: the UE NGAP IDs """
    ids = _ids(IGNORE, IGNORE, amf_id, ran_id)
    return _message(_UE_CONTEXT_RELEASE_COMPLETE, ids) if ids is not None else None


def _qos_flows(qfis):
    """ AssociatedQosFlowList ::= SEQUENCE (SIZE(1..64)) OF AssociatedQosFlowItem, an item a SEQUENCE
    {qosFlowIdentifier INTEGER (0..63, ...), qosFlowMappingIndication OPTIONAL, iE-Extensions
    OPTIONAL, ...}: the count less one in 6 bits, then per flow its extension and option bits (0, 0, 0)
    and the QFI's extension bit (0) and 6 bits, then padding to the octet; None for no flow, more
    than 64, or a QFI that is not an int of 0..63 """
    if type(qfis) not in (list, tuple) or not 0 < len(qfis) <= 64:
        return None
    bits = len(qfis) - 1
    for qfi in qfis:
        if type(qfi) is not int or not 0 <= qfi < 64:
            return None
        bits = bits << 10 | qfi
    n = 6 + 10 * len(qfis)
    pad = -n % 8
    return (bits << pad).to_bytes((n + pad) >> 3, 'big')


def pdu_session_resource_setup_response(amf_id, ran_id, pdu_session_id, address, teid, qfis):
    """ src/NGAPSim.py's PDUSessionResourceSetupResponse: the UE NGAP IDs and one PDU session set up
    (its ID, 0..255), whose PDUSessionResourceSetupResponseTransfer gives the gNB's DL NG-U tunnel
    (address: its transport layer address, 4, 16 or 20 octets for IPv4, IPv6 or both; teid: its GTP
    TEID, 4 octets) and the QFIs of the QoS flows on it """
    try:
        ids = _ids(IGNORE, IGNORE, amf_id, ran_id)
        flows = _qos_flows(qfis)
        if (ids is None or flows is None or type(pdu_session_id) is not int or not 0 <= pdu_session_id < 256
                or type(address) is not bytes or len(address) not in (4, 16, 20)
                or type(teid) is not bytes or len(teid) != 4):
            return None
        # PDUSessionResourceSetupResponseTransfer ::= SEQUENCE {dLQosFlowPerTNLInformation, three
        # OPTIONAL, iE-Extensions OPTIONAL, ...}: its extension and option bits; the
        # QosFlowPerTNLInformation's extension and option bits; the UPTransportLayerInformation's
        # choice (gTPTunnel, 1 bit); the GTPTunnel's extension and option bits; the
        # TransportLayerAddress's extension bit: 11 bits, all 0. Then the address's size less one in 8
        # bits, padding, the address, the TEID and the QoS flows.
        transfer = ((len(address) * 8 - 1) << 5).to_bytes(3, 'big') + address + teid + flows
        # PDUSessionResourceSetupListSURes ::= SEQUENCE (SIZE(1..256)) OF ...: the count less one (an
        # octet); the item's extension and option bits and padding, its PDU session ID (an octet) and
        # the transfer (an OCTET STRING holding its encoding)
        sessions = b'\x00\x00' + bytes((pdu_session_id,)) + wrap(transfer)
        return _message(_PDU_SESSION_RESOURCE_SETUP_RESPONSE, [*ids, _ie(75, IGNORE, sessions)])
    except Exception:
        return None


# --------------------------------------------------------------------------------------------------
# Downlink
# --------------------------------------------------------------------------------------------------

DOWNLINK_NAS_TRANSPORT = 4
INITIAL_CONTEXT_SETUP = 14
PDU_SESSION_RESOURCE_SETUP = 29
UE_CONTEXT_RELEASE = 41

# How an IE is read: an id or the NAS-PDU kept, the UE-NGAP-IDs' pair, a fixed size checked, bytes
# pycrate decoded before; the PDU Session Resource Setup Request's PDU sessions, and in their
# transfer the UL NG-U tunnel, the PDU session type and the QoS flows (bytes pycrate decoded before,
# whose first QFI is kept)
_AMF, _RAN, _NAS, _PAIR, _FIXED, _LEARNT, _SESSIONS, _TUNNEL, _TYPE, _FLOWS = range(10)
_KINDS = {10: _AMF, 85: _RAN, 38: _NAS, 114: _PAIR}
_CRITICALITY = {'reject': 0x00, 'ignore': 0x40, 'notify': 0x80}

MAX_LEARNT = 4096
_learnt = set()          # (procedure code or TRANSFER, IE id, value bytes)

# What the gNB reads of the PDU session in a PDU Session Resource Setup Request: its ID, the UL NG-U
# tunnel as pycrate gives it, ('gTPTunnel', {'transportLayerAddress': (address, bits), 'gTP-TEID':
# 4 octets}), the first QoS flow's QFI and the PDU session type (its name), or None if absent
PDUSession = namedtuple('PDUSession', 'pdu_session_id ul_tunnel qfi pdu_session_type')


def _fixed_octets(value_type):
    """ The size in octets of a BIT or OCTET STRING of one fixed size (whole octets), else None """
    if type(value_type).__name__ not in ('BIT_STR', 'OCT_STR') or getattr(value_type, '_const_cont', None) is not None:
        return None
    sz = getattr(value_type, '_const_sz', None)
    if sz is None or sz.ext is not None or len(sz.root) != 1 or type(sz.root[0]) is not int:
        return None
    n = sz.root[0]
    if type(value_type).__name__ == 'BIT_STR':
        return n >> 3 if n % 8 == 0 else None
    return n


class _IESet:
    """ An IE set's layout from pycrate's tables: per IE id its place in the set, its criticality and
    how it is read (kinds: the IEs read, by id; any other is checked by size or learnt) """

    def __init__(self, ie_set, kinds):
        self.ies = {}
        self.values = {}            # pycrate's object for each IE's value, to check what is learnt
        for place, ie in enumerate(ie_set._val.root):
            self.values[ie['id']] = ie['Value']
            kind, size = kinds.get(ie['id'], _LEARNT), None
            if kind == _LEARNT:
                size = _fixed_octets(ie['Value'])
                if size is not None:
                    kind = _FIXED
            self.ies[ie['id']] = (place, _CRITICALITY[ie['criticality']], kind, size)


class _Message(_IESet):
    """ A downlink message's layout: its IE set's, and its procedure's criticality """

    def __init__(self, procedure, ie_set, kinds=_KINDS):
        super().__init__(ie_set, kinds)
        self.criticality = _CRITICALITY[procedure._val['criticality']]


_D, _C = NGAP.NGAP_PDU_Descriptions, NGAP.NGAP_PDU_Contents
_DOWNLINK = {
    DOWNLINK_NAS_TRANSPORT: _Message(_D.downlinkNASTransport, _C.DownlinkNASTransport_IEs),
    INITIAL_CONTEXT_SETUP: _Message(_D.initialContextSetup, _C.InitialContextSetupRequestIEs),
    # its message-level NAS-PDU, which src/NGAPSim.py does not read (it reads the PDU session's), is learnt
    PDU_SESSION_RESOURCE_SETUP: _Message(_D.pDUSessionResourceSetup, _C.PDUSessionResourceSetupRequestIEs,
                                         {10: _AMF, 85: _RAN, 74: _SESSIONS}),
    UE_CONTEXT_RELEASE: _Message(_D.uEContextRelease, _C.UEContextReleaseCommand_IEs),
}
# The PDUSessionResourceSetupRequestTransfer's IE set, and its key among the learnt IEs
TRANSFER = 'PDUSessionResourceSetupRequestTransfer'
_LAYOUTS = dict(_DOWNLINK)
_LAYOUTS[TRANSFER] = _IESet(NGAP.NGAP_IEs.PDUSessionResourceSetupRequestTransferIEs,
                            {139: _TUNNEL, 134: _TYPE, 136: _FLOWS})
_SESSION_TYPES = tuple(NGAP.NGAP_IEs.PDUSessionType._root)
_TUNNEL_BITS = (32, 128, 160)       # an IPv4 address, an IPv6 one, both (TS 38.414 §5.1)


def _length(buf, o, end):
    """ (offset of the value, its length) for a length determinant at o in its canonical form below
    16384, or None (a fragmented, long-form-for-short or truncated one) """
    if o >= end:
        return None
    b = buf[o]
    if b < 0x80:
        return o + 1, b
    if b & 0xC0 != 0x80 or o + 1 >= end:
        return None
    n = (b & 0x3F) << 8 | buf[o + 1]
    if n < 128:
        return None
    return o + 2, n


def _id(value, lbits, max_octets):
    """ A UE NGAP ID's value from its APER encoding (the whole of value), or None """
    if len(value) < 2:
        return None
    b = value[0]
    n = (b >> (8 - lbits)) + 1
    if b & (0xFF >> lbits) or n > max_octets or len(value) != 1 + n or (n > 1 and value[1] == 0):
        return None
    return int.from_bytes(value[1:], 'big')


def _octets(value):
    """ An OCTET STRING's octets (the NAS-PDU) from its encoding (the whole of value), or None """
    w = _length(value, 0, len(value))
    if w is None or w[0] + w[1] != len(value):
        return None
    return value[w[0]:]


def _pair(value):
    """ UE-NGAP-IDs ::= CHOICE {uE-NGAP-ID-pair, aMF-UE-NGAP-ID, choice-Extensions} (no extension
    marker): only a pair, without iE-Extensions or extension: (AMF, RAN) UE NGAP IDs, or None """
    if len(value) < 4 or value[0] & 0xF1:
        return None
    n = (value[0] >> 1) + 1                 # the AMF id's octets, after the choice, extension and option bits
    if n > 5 or len(value) < n + 3 or (n > 1 and value[1] == 0):
        return None
    amf = int.from_bytes(value[1:1 + n], 'big')
    ran = _id(value[1 + n:], 2, 4)
    if ran is None:
        return None
    return amf, ran


def _sessions(value, learning):
    """ PDUSessionResourceSetupListSUReq ::= SEQUENCE (SIZE(1..256)) OF PDUSessionResourceSetupItemSUReq,
    of one item here (src/NGAPSim.py reads the first): SEQUENCE {pDUSessionID INTEGER (0..255),
    pDUSessionNAS-PDU OPTIONAL (present here: src/NGAPSim.py reads it), s-NSSAI,
    pDUSessionResourceSetupRequestTransfer (an OCTET STRING holding its encoding), iE-Extensions
    OPTIONAL (absent), ...}: (the NAS-PDU, PDUSession), or None """
    end = len(value)
    # The count less one (an octet); the item's extension and option bits (0, 1, 0) and padding; the
    # PDU session ID (an octet); the NAS-PDU
    if end < 4 or value[0] != 0 or value[1] != 0x40:
        return None
    pdu_session_id = value[2]
    v = _length(value, 3, end)
    if v is None:
        return None
    o = v[0] + v[1]
    if o + 2 > end:
        return None
    nas = value[v[0]:o]
    # S-NSSAI ::= SEQUENCE {sST OCTET STRING (SIZE(1)), sD OCTET STRING (SIZE(3)) OPTIONAL, iE-Extensions
    # OPTIONAL, ...}: the extension and option bits, the SST's 8 bits, padding; the SD's octets if any
    if value[o] & 0xA0 or value[o + 1] & 0x1F:
        return None
    o += 5 if value[o] & 0x40 else 2
    # PDUSessionResourceSetupRequestTransfer ::= SEQUENCE {protocolIEs, ...}: the extension bit and
    # padding, then its IEs, which end where the OCTET STRING ends
    v = _length(value, o, end)
    if v is None or v[0] + v[1] != end or v[0] >= end or value[v[0]] != 0:
        return None
    got = {}
    if not _container(value, v[0] + 1, end, _LAYOUTS[TRANSFER], TRANSFER, learning, got):
        return None
    tunnel, qfi = got.get(_TUNNEL), got.get(_FLOWS)
    if tunnel is None or qfi is None:
        return None
    return nas, PDUSession(pdu_session_id, tunnel, qfi, got.get(_TYPE))


def _tunnel(value):
    """ UPTransportLayerInformation ::= CHOICE {gTPTunnel, choice-Extensions} (no extension marker):
    a GTPTunnel ::= SEQUENCE {transportLayerAddress BIT STRING (SIZE(1..160, ...)), gTP-TEID OCTET
    STRING (SIZE(4)), iE-Extensions OPTIONAL, ...} without iE-Extensions or extension, whose address
    has 32, 128 or 160 bits: the choice, extension and option bits, the size less one in 8 bits,
    padding, the address, the TEID. pycrate's value of it, or None. """
    if len(value) < 2 or value[0] & 0xF0 or value[1] & 0x0F:
        return None
    bits = ((value[0] & 0x0F) << 4 | value[1] >> 4) + 1
    n = bits >> 3
    if bits not in _TUNNEL_BITS or len(value) != 2 + n + 4:
        return None
    return 'gTPTunnel', {'transportLayerAddress': (int.from_bytes(value[2:2 + n], 'big'), bits),
                         'gTP-TEID': value[2 + n:]}


def _session_type(value):
    """ PDUSessionType ::= ENUMERATED {ipv4, ipv6, ipv4v6, ethernet, unstructured, ...}: the extension
    bit, the index in 3 bits, padding. Its name, or None. """
    if len(value) != 1 or value[0] & 0x8F or value[0] >> 4 >= len(_SESSION_TYPES):
        return None
    return _SESSION_TYPES[value[0] >> 4]


def _first_qfi(value):
    """ The first QoS flow's QFI in a QosFlowSetupRequestList ::= SEQUENCE (SIZE(1..64)) OF
    QosFlowSetupRequestItem, an item a SEQUENCE {qosFlowIdentifier INTEGER (0..63, ...), ...,
    e-RAB-ID OPTIONAL, iE-Extensions OPTIONAL, ...}: after the count (6 bits) and the item's extension
    and option bits, the QFI's extension bit (0 here) and 6 bits. The list's bytes are ones pycrate
    decoded before (learnt). """
    if len(value) < 2 or value[1] & 0x40:
        return None
    return value[1] & 0x3F


def _container(data, o, end, layout, key, learning, got):
    """ A ProtocolIE-Container at o (the count in two octets, then the fields), which must end at end:
    what the gNB reads from its IEs into got (by kind). False if the parser does not take it. With
    learning (a list), the IEs not known yet are appended to it instead of refusing them. """
    if o + 2 > end:
        return False
    count = data[o] << 8 | data[o + 1]
    o += 2
    place = -1
    ies = layout.ies
    for _ in range(count):
        if o + 3 > end:
            return False
        ie_id = data[o] << 8 | data[o + 1]
        entry = ies.get(ie_id)
        if entry is None or entry[0] <= place or data[o + 2] != entry[1]:
            return False
        place, _, kind, size = entry
        v = _length(data, o + 3, end)
        if v is None:
            return False
        start, o = v[0], v[0] + v[1]
        if o > end:
            return False
        value = data[start:o]
        if kind == _FIXED:
            if len(value) != size:
                return False
            continue
        if kind == _LEARNT or kind == _FLOWS:
            if (key, ie_id, value) not in _learnt:
                if learning is None:
                    return False
                learning.append((key, ie_id, value))
            if kind == _LEARNT:
                continue
        if kind == _AMF:
            read = _id(value, 3, 5)
        elif kind == _RAN:
            read = _id(value, 2, 4)
        elif kind == _NAS:
            read = _octets(value)
        elif kind == _PAIR:
            read = _pair(value)
        elif kind == _SESSIONS:
            read = _sessions(value, learning)
        elif kind == _TUNNEL:
            read = _tunnel(value)
        elif kind == _TYPE:
            read = _session_type(value)
        else:
            read = _first_qfi(value)
        if read is None:
            return False
        got[kind] = read
    return o == end


def _walk(data, learning=None):
    """ (procedure code, AMF UE NGAP ID, RAN UE NGAP ID, NAS-PDU or None, PDUSession or None), or None.
    With learning (a list), the IEs not known yet are appended to it instead of refusing the message. """
    if type(data) is not bytes or len(data) < 7 or data[0] != 0:      # initiatingMessage, no extension
        return None
    code = data[1]
    msg = _DOWNLINK.get(code)
    if msg is None or data[2] != msg.criticality:
        return None
    end = len(data)
    v = _length(data, 3, end)
    if v is None or v[0] + v[1] != end:
        return None
    o = v[0]
    if o + 3 > end or data[o] != 0:          # the message's extension bit, padding
        return None
    got = {}
    if not _container(data, o + 1, end, msg, code, learning, got):
        return None
    if _PAIR in got:
        amf, ran = got[_PAIR]
    else:
        amf, ran = got.get(_AMF), got.get(_RAN)
    if amf is None or ran is None:
        return None
    if code == PDU_SESSION_RESOURCE_SETUP:
        if _SESSIONS not in got:
            return None
        nas, session = got[_SESSIONS]
        return code, amf, ran, nas, session
    return code, amf, ran, got.get(_NAS), None


def downlink(data):
    """ What the gNB reads from a downlink NGAP message, as src/NGAPSim.py gets it from pycrate:
    (procedure code, AMF UE NGAP ID, RAN UE NGAP ID, NAS-PDU or None if absent, and for a PDU Session
    Resource Setup Request its PDUSession (the NAS-PDU then the PDU session's), else None), or None
    for a message to decode with pycrate as before """
    try:
        return _walk(data)
    except Exception:
        return None


def _canonical(key, ie_id, value):
    """ Whether pycrate decodes value as the IE's value, all of it, and encodes it back the same: within
    a message, pycrate goes on after the end of what it decoded, not after the open type's length """
    obj = _LAYOUTS[key].values[ie_id]
    try:
        obj.from_aper(value)
        return obj.to_aper() == value
    except Exception:
        return False


def learn(data):
    """ After pycrate decoded data: its IEs the parser does not read become known (byte for byte), so
    that the next message with the same ones need not go to pycrate. It uses pycrate's objects:
    src/NGAPSim.py calls it under ngap_pdu_lock. """
    if len(_learnt) >= MAX_LEARNT:
        return
    new = []
    try:
        if _walk(data, new) is None:
            return
    except Exception:
        return
    for ie in new:
        if len(_learnt) >= MAX_LEARNT:
            break
        if _canonical(*ie):
            _learnt.add(ie)
