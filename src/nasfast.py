""" The UE simulator's NAS messages without pycrate objects: a light parser for the downlink messages
of a registration, PDU session and deregistration, and byte templates for the uplink ones.

After src/nascache.py (G10) the UE simulators still spent most of their CPU in pycrate: decoding a
message clones the templates of its IEs, and building one sets and encodes every IE. Here:

- downlink() walks a message as pycrate's Layer3 decoding does: the mandatory IEs in order, then
  the optional IEs, each matched by its tag in the order of the message's class (an IE seen twice
  matches the next IE with that tag, as in pycrate). The layout is read from pycrate's own class.
  It keeps the fields the UE's handlers read (src/UEMessages.py), in an object they read as they
  read pycrate's (Msg['AUTN']['AUTN'].get_val(), ...), and deciphers a security protected message
  as security_prot_decrypt() does (the MAC is not checked, as there). Anything else gives None and
  the caller decodes the message with pycrate as before: another message or security header, an
  IE the class does not have or one seen more often than the class has it (pycrate appends an
  unknown IE), a message too short for its IEs (pycrate fails), an IE the handler reads that
  pycrate would not decode (an AUTN of another length, no PDU address), a payload container that
  is not a PDU Session Establishment Accept.
- The uplink builders give a message's bytes from its fixed parts and the UE's fields (SUCI, RES*,
  IMEISV, NSSAI, S-NSSAI and DNN), as pycrate encodes them with the IEs of src/UEMessages.py, and
  protect() protects them as security_prot_encrypt_ciphered() does: the same header and NAS
  COUNT, ciphering and MAC with the functions pycrate calls (CryptoMobile). They give None for
  what they do not cover (another algorithm, an identity, slice or DNN of another form) and the
  callers then build the message with pycrate (src/nascache.py) as before.

The pycrate path stays in use when messages are logged (debug), validated or used by the compliance
tests, which need pycrate objects, and can be forced with CNTG_NAS_FASTPATH=0.
"""
import logging
import os
from binascii import unhexlify
from struct import pack

from pycrate_core.base import Buf, Uint
from pycrate_core.charpy import Charpy
from pycrate_core.elt import Envelope
from pycrate_mobile import TS24501_FGMM
from pycrate_mobile.TS24007 import IE, Type1V, Type1TV, Type2, Type3V, Type3TV, Type4LV, Type4TLV, Type6LVE, Type6TLVE
from pycrate_mobile.TS24008_IE import encode_bcd
from pycrate_mobile.TS24501_FGMM import FGMMTypeClasses
from pycrate_mobile.TS24501_FGSM import FGSMTypeClasses

_logger = logging.getLogger('__UESim__')

ENABLED = os.environ.get('CNTG_NAS_FASTPATH', '1') != '0'


def enabled():
    """ Whether to use the fast path: not when messages are logged, which needs pycrate objects """
    return ENABLED and not _logger.isEnabledFor(logging.DEBUG)


# The 5G NAS ciphering and integrity algorithms of pycrate's FGMMSecProtNASMessage (CryptoMobile)
_FGEA = getattr(TS24501_FGMM, '_FGEA', {})
_FGIA = getattr(TS24501_FGMM, '_FGIA', {})


# --------------------------------------------------------------------------------------------------
# Downlink
# --------------------------------------------------------------------------------------------------

class Field:
    """ An IE or a field of one, as a handler reads it: get_val(), get_val_d(), or a field in it """
    __slots__ = ('_val', '_sub')

    def __init__(self, val=None, sub=None):
        self._val = val
        self._sub = sub

    def get_val(self):
        return self._val

    get_val_d = get_val

    def __getitem__(self, name):
        return self._sub[name]


class Message:
    """ A downlink message: pycrate's name for it and the IEs the UE's handlers read """
    __slots__ = ('_name', '_ies')

    def __init__(self, name, ies=None):
        self._name = name
        self._ies = ies or {}

    def __getitem__(self, name):
        return self._ies[name]

    def __repr__(self):
        return f'<nasfast.Message {self._name}>'


# The parts of a message as pycrate decodes them: mandatory ones (in order) and optional IEs
_FIXED, _NIBBLE, _V, _LV, _LVE = range(5)
_TV1, _T2, _TV, _TLV, _TLVE = range(5)


def _fixed_bl(elt):
    """ The bit length of an element whose decoding takes a fixed number of bits, else None """
    if isinstance(elt, Envelope):
        if type(elt)._from_char is not Envelope._from_char or elt._blauto is not None or elt._transauto is not None:
            return None
        bl = 0
        for e in elt._content:
            if e._trans or e._transauto is not None:
                return None
            e_bl = _fixed_bl(e)
            if e_bl is None:
                return None
            bl += e_bl
        return bl
    for base in (Uint, Buf):
        if isinstance(elt, base) and type(elt)._from_char is base._from_char:
            if elt._bl is None or elt._blauto is not None or elt._transauto is not None:
                return None
            return elt._bl
    return None


class Layout:
    """ How pycrate's Layer3._from_char decodes a message of class cls (pycrate_mobile/TS24007.py)

    name: pycrate's name for the message; mand: the mandatory part, (name, kind, bits); opts: the
    optional IEs, (name, kind, octets of a fixed value); match[b]: the optional IEs, in the class's
    order, whose tag an IE starting with octet b matches (a 4-bit tag in its upper half, or any tag
    equal to b, as pycrate compares).
    """

    def __init__(self, cls):
        self.name = cls._name
        msg = cls()
        if msg._rest is not None:
            raise ValueError(f'{cls.__name__}: rest octets')
        optional = {id(o[2]) for o in msg._opts}
        self.mand = []
        for e in msg._content:
            if id(e) in optional:
                continue
            if isinstance(e, Type1V):
                self.mand.append((e._name, _NIBBLE, 4))
            elif isinstance(e, Type3V):
                bl = _fixed_bl(e[-1])
                if bl is None or bl % 8:
                    raise ValueError(f'{cls.__name__}: {e._name}')
                self.mand.append((e._name, _V, bl))
            elif isinstance(e, Type4LV):
                self.mand.append((e._name, _LV, 0))
            elif isinstance(e, Type6LVE):
                self.mand.append((e._name, _LVE, 0))
            elif isinstance(e, IE):
                raise ValueError(f'{cls.__name__}: {e._name}')
            else:
                bl = _fixed_bl(e)
                if bl is None:
                    raise ValueError(f'{cls.__name__}: {e._name}')
                self.mand.append((e._name, _FIXED, bl))
        self.opts = []
        match = [[] for _ in range(256)]
        for i, (tag_bl, tag, ie) in enumerate(msg._opts):
            size = 0
            if isinstance(ie, Type1TV):
                kind = _TV1
            elif isinstance(ie, Type2):
                kind = _T2
            elif isinstance(ie, Type3TV):
                kind, size = _TV, _fixed_bl(ie[-1])
                if size is None or size % 8:
                    raise ValueError(f'{cls.__name__}: {ie._name}')
                size //= 8
            elif isinstance(ie, Type4TLV):
                kind = _TLV
            elif isinstance(ie, Type6TLVE):
                kind = _TLVE
            else:
                raise ValueError(f'{cls.__name__}: {ie._name}')
            self.opts.append((ie._name, kind, size))
            for b in range(256):
                if (tag_bl == 4 and tag == b >> 4) or tag == b:
                    match[b].append(i)
        self.match = tuple(tuple(m) for m in match)

    def walk(self, buf):
        """ The values of buf's IEs: a nibble for Type1 IEs, True for Type2 ones, (start, end) of the
        value for the others. None if pycrate's decoding would fail, or meet an IE the class does not
        have or one more time than the class has it. """
        n = len(buf)
        vals = {}
        bit = 0
        for name, kind, size in self.mand:
            if kind == _FIXED:
                bit += size
                continue
            if kind == _NIBBLE:
                o = bit >> 3
                if o >= n:
                    return None
                vals[name] = buf[o] & 0xF if bit & 7 else buf[o] >> 4
                bit += 4
                continue
            if bit & 7:
                return None
            o = bit >> 3
            if kind == _V:
                start, end = o, o + (size >> 3)
            elif kind == _LV:
                if o >= n:
                    return None
                start = o + 1
                end = start + buf[o]
            else:
                if o + 1 >= n:
                    return None
                start = o + 2
                end = start + (buf[o] << 8 | buf[o + 1])
            if end > n:
                return None
            vals[name] = (start, end)
            bit = end << 3
        if bit & 7 or bit > n << 3:
            return None
        o, used = bit >> 3, 0
        opts, match = self.opts, self.match
        while o < n:
            b = buf[o]
            for i in match[b]:
                if not used >> i & 1:
                    break
            else:
                return None
            used |= 1 << i
            name, kind, size = opts[i]
            if kind == _TV1:
                vals[name] = b & 0xF
                o += 1
                continue
            if kind == _T2:
                vals[name] = True
                o += 1
                continue
            if kind == _TV:
                start = o + 1
            elif kind == _TLV:
                if o + 1 >= n:
                    return None
                start, size = o + 2, buf[o + 1]
            else:
                if o + 2 >= n:
                    return None
                start, size = o + 3, buf[o + 1] << 8 | buf[o + 2]
            o = start + size
            if o > n:
                return None
            vals[name] = (start, o)
        return vals


_LAYOUTS = {}      # the 5GMM messages parsed here, by message type
for _typ in (86, 93, 66, 84, 104, 70):
    _LAYOUTS[_typ] = Layout(FGMMTypeClasses[_typ])
_PDU_SESSION_ESTABLISHMENT_ACCEPT = Layout(FGSMTypeClasses[194])
# The PDU address IE as pycrate decodes it in a PDU Session Establishment Accept
_PDU_ADDRESS = FGSMTypeClasses[194]()['PDUAddress']._IE_stat


def _authentication_request(buf):
    layout = _LAYOUTS[86]
    v = layout.walk(buf)
    if v is None or 'RAND' not in v or 'AUTN' not in v:
        return None
    a0, a1 = v['AUTN']
    if a1 - a0 != 16:                 # pycrate does not decode another length into SQNxAK, AMF, MAC
        return None
    r0, r1 = v['RAND']
    b0, b1 = v['ABBA']
    return Message(layout.name, {
        'RAND': Field([0x21, buf[r0:r1]]),
        'AUTN': Field(sub={'AUTN': Field([buf[a0:a0 + 6], buf[a0 + 6:a0 + 8], buf[a0 + 8:a1]])}),
        'ABBA': Field(sub={'V': Field(buf[b0:b1])})})


def _security_mode_command(buf):
    layout = _LAYOUTS[93]
    v = layout.walk(buf)
    if v is None:
        return None
    algs = buf[v['NASSecAlgo'][0]]
    return Message(layout.name, {
        'NASSecAlgo': Field(sub={'NASSecAlgo': Field({'CiphAlgo': algs >> 4, 'IntegAlgo': algs & 0xF})})})


def _no_fields(typ):
    """ A message whose fields the UE does not read: its structure only """
    layout = _LAYOUTS[typ]

    def parse(buf):
        return Message(layout.name) if layout.walk(buf) is not None else None
    return parse


def _pdu_address(value):
    """ The PDU address IE's value as pycrate decodes it (the forms differ between its versions) """
    ie = _PDU_ADDRESS.clone()
    char = Charpy(value)
    try:
        ie._from_char(char)
    except Exception:
        return None
    if char.len_bit() > 7:
        return None
    return ie.get_val_d()


def _dl_nas_transport(buf):
    """ A DL NAS Transport with a PDU Session Establishment Accept: as dispatcher() gets it from
    dl_nas_transport_extract(), the 5GSM message pycrate decodes in the payload container """
    v = _LAYOUTS[104].walk(buf)
    if v is None or v['PayloadContainerType'] != 1:     # N1 SM information
        return None
    s0, s1 = v['PayloadContainer']
    sm = buf[s0:s1]
    if len(sm) < 4 or sm[0] != 46 or sm[3] != 194:
        return None
    w = _PDU_SESSION_ESTABLISHMENT_ACCEPT.walk(sm)
    if w is None or 'PDUAddress' not in w:
        return None
    a0, a1 = w['PDUAddress']
    address = _pdu_address(sm[a0:a1])
    if address is None:
        return None
    return Message(_PDU_SESSION_ESTABLISHMENT_ACCEPT.name, {'PDUAddress': Field(sub={'PDUAddress': Field(address)})})


_PLAIN = {
    86: _authentication_request,
    93: _security_mode_command,
    66: _no_fields(66),           # Registration Accept
    84: _no_fields(84),           # Configuration Update Command
    70: _no_fields(70),           # Deregistration Accept (UE originating)
    104: _dl_nas_transport,
}


def _plain(buf):
    if len(buf) < 3 or buf[0] != 126 or buf[1] != 0:
        return None
    parse = _PLAIN.get(buf[2])
    return parse(buf) if parse is not None else None


def _downlink(data, ue):
    if type(data) is not bytes or len(data) < 3 or data[0] != 126:
        return None
    shdr = data[1]
    if shdr == 0:
        return _plain(data)
    if len(data) < 10:
        return None
    if shdr == 2:
        # integrity protected and ciphered: deciphered with the downlink COUNT of the header's
        # sequence number, as security_prot_decrypt() asks pycrate's decrypt() to
        plain = data[7:]
        ciph = ue.CiphAlgo
        if ciph != 0:
            fgea = _FGEA.get(ciph)
            if fgea is None:
                return None
            plain = fgea(ue.k_nas_enc, data[6], 1, 1, plain)
        return _plain(plain)
    if shdr in (1, 3):
        # integrity protected (with a new security context): dispatcher() takes a Security Mode
        # Command out of it, and nothing else
        msg = _plain(data[7:])
        if msg is not None and msg._name == _LAYOUTS[93].name:
            return msg
    return None


def downlink(data, ue):
    """ The downlink NAS message data of ue as dispatcher() gets it from pycrate, after deciphering
    and taking the message out of a security protected message or a DL NAS Transport:
    (message, its name), or None for a message to decode with pycrate as before """
    try:
        msg = _downlink(data, ue)
    except Exception:
        return None                    # pycrate meets the same problem, and handles it as before
    return (msg, msg._name) if msg is not None else None


# --------------------------------------------------------------------------------------------------
# Uplink
# --------------------------------------------------------------------------------------------------

class NASBytes(bytes):
    """ An uplink message from the templates: its bytes, with to_bytes() as pycrate's messages have """
    __slots__ = ()

    def to_bytes(self):
        return bytes(self)


def protect(ue, plain, count=None):
    """ The plain message (bytes) security protected as security_prot_encrypt_ciphered() does it,
    with the uplink NAS COUNT count (ue.ul_nas_count by default), which becomes count + 1; None
    (and nothing changed) for algorithms pycrate has not, or when ciphering or the MAC fails.

    Security header type 2 with any algorithm (5G-EA0 ciphers as the identity), 0 without; the
    sequence number is the COUNT's lower octet; ciphering first, then the MAC over the sequence
    number and the ciphered message (TS 24.501 §4.4.3).
    """
    ciph, integ = ue.CiphAlgo, ue.IntegAlgo
    if (ciph != 0 and ciph not in _FGEA) or (integ != 0 and integ not in _FGIA):
        return None
    if count is None:
        count = getattr(ue, 'ul_nas_count', 0)
    seqn = count & 0xFF
    try:
        if ciph != 0:
            plain = _FGEA[ciph](ue.k_nas_enc, count, 1, 0, plain)
        mac = _FGIA[integ](ue.k_nas_int, count, 1, 0, bytes((seqn,)) + plain) if integ != 0 else b'\0\0\0\0'
    except Exception:
        return None
    if len(mac) != 4:
        return None
    ue.ul_nas_count = count + 1
    return NASBytes(bytes((126, 2 if ciph != 0 or integ != 0 else 0)) + mac + bytes((seqn,)) + plain)


_DIGITS = frozenset('0123456789')


def _digits(s, n=None):
    return type(s) is str and (n is None or len(s) in n) and set(s) <= _DIGITS


def _suci(ue):
    """ The UE's SUCI (suci(): null protection scheme, routing indicator 0) as a 5GS mobile identity
    LV-E: type 1, the PLMN as pycrate's PLMN encodes MCC + MNC, the MSIN in BCD """
    plmn, msin = ue.mcc + ue.mnc, ue.msin
    if not (_digits(plmn, (5, 6)) and _digits(msin)):
        return None
    if len(plmn) == 5:
        plmn += 'F'
    value = (b'\x01' + unhexlify(plmn[1] + plmn[0] + plmn[5] + plmn[2] + plmn[4] + plmn[3]) + b'\x00\x00\x00\x00'
             + encode_bcd(msin))
    return pack('>H', len(value)) + value


def _snssai(s):
    """ An S-NSSAI {'SST': .., 'SD': ..} (SD optional) as pycrate encodes it, else None """
    if type(s) is not dict:
        return None
    sst, sd = s.get('SST'), s.get('SD')
    if type(sst) is not int or not 0 <= sst <= 0xFF:
        return None
    if len(s) == 1:
        return bytes((sst,))
    if len(s) == 2 and type(sd) is int and 0 <= sd <= 0xFFFFFF:
        return bytes((sst,)) + sd.to_bytes(3, 'big')
    return None


def _dnn(dnn):
    """ A DNN as pycrate's APN encodes it, its labels each after its length, else None """
    if type(dnn) is not str:
        return None
    labels = [label.encode() for label in dnn.split('.')]
    if any(len(label) > 0xFF for label in labels):
        return None
    value = b''.join(bytes((len(label),)) + label for label in labels)
    return value if len(value) <= 0xFF else None


# The messages as pycrate encodes them with src/UEMessages.py's IEs: EPD, security header type 0 and
# message type, then:
_NGKSI_REG_TYPE = b'\x79'                     # ngKSI 7 (no key), 5GS registration type: initial, follow-on
_UE_SEC_CAP = b'\x2e\x04\xf0\xf0\xf0\xf0'     # 5G-EA0-3, 5G-IA0-3, EEA0-3, EIA0-3
_5GMM_CAP = b'\x10\x05\x00\x00\x00\x00\x00'
_5GS_UPDATE_TYPE = b'\x53\x01\x00'
REGISTRATION_COMPLETE = b'\x7e\x00\x43'
CONFIGURATION_UPDATE_COMPLETE = b'\x7e\x00\x55'
# PDU session ID 1, PTI 1, integrity protection maximum data rate 0, PDU session type IPv4, SSC mode 1
PDU_SESSION_ESTABLISHMENT_REQUEST = b'\x2e\x01\x01\xc1\x00\x00\x91\xa1'


def registration_request(ue):
    suci = _suci(ue)
    if suci is None:
        return None
    return NASBytes(b'\x7e\x00\x41' + _NGKSI_REG_TYPE + suci + _UE_SEC_CAP)


def authentication_response(res):
    if type(res) is not bytes or len(res) > 0xFF:
        return None
    return NASBytes(b'\x7e\x00\x57\x2d' + bytes((len(res),)) + res)


def security_mode_complete(ue):
    """ The plain Security Mode Complete: the IMEISV and, in the NAS message container, the
    Registration Request with the UE's NSSAI """
    suci = _suci(ue)
    imeisv = ue.imeiSv
    if suci is None or not _digits(imeisv, (16,)) or type(ue.nssai) is not list or not ue.nssai:
        return None
    nssai = b''
    for s in ue.nssai:
        v = _snssai(s)
        if v is None:
            return None
        nssai += bytes((len(v),)) + v
    if len(nssai) > 0xFF:
        return None
    reg = (b'\x7e\x00\x41' + _NGKSI_REG_TYPE + suci + _5GMM_CAP + _UE_SEC_CAP + b'\x2f' + bytes((len(nssai),)) + nssai
           + _5GS_UPDATE_TYPE)
    # IMEISV: first digit, odd/even indication 0 (pycrate's default), type 5; the other 15 digits in BCD
    return (b'\x7e\x00\x5e\x77\x00\x09' + bytes((int(imeisv[0]) << 4 | 5,)) + encode_bcd(imeisv[1:])
            + b'\x71' + pack('>H', len(reg)) + reg)


def ul_nas_transport_pdu_session_establishment_request(ue):
    """ The plain UL NAS Transport of PDU_SESSION_ESTABLISHMENT_REQUEST, with the S-NSSAI and DNN of
    the UE's first session as pdu_session_establishment_request() picks them """
    session = ue.sessions[0] if getattr(ue, 'sessions', None) else {}
    s_slice = session.get('slice')
    snssai = _snssai(({'SST': int(s_slice['sst']), 'SD': int(s_slice['sd'])} if 'sd' in s_slice
                      else {'SST': int(s_slice['sst'])}) if s_slice else ue.nssai[0])
    if snssai is None:
        return None
    msg = (b'\x7e\x00\x67\x01' + pack('>H', len(PDU_SESSION_ESTABLISHMENT_REQUEST)) + PDU_SESSION_ESTABLISHMENT_REQUEST
           + b'\x12\x01\x81\x22' + bytes((len(snssai),)) + snssai)       # PDU session ID 1, initial request
    if session.get('apn'):
        dnn = _dnn(session['apn'])
        if dnn is None:
            return None
        msg += b'\x25' + bytes((len(dnn),)) + dnn
    return msg


def mo_deregistration_request(ue):
    suci = _suci(ue)
    if suci is None:
        return None
    # ngKSI 7, de-registration type: normal, 3GPP access
    return b'\x7e\x00\x45\x71' + suci


def build(builder, ue):
    """ builder(ue), or None when it fails: the caller's pycrate path then meets the same problem """
    try:
        return builder(ue)
    except Exception:
        return None
