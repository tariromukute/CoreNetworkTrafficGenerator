""" NAS message objects that each thread reuses, instead of a fresh pycrate object per message.

pycrate builds every message object by cloning its class's template, every IE of it, the optional
IEs the message does not carry included: about 0.4-0.5 ms for a Registration Request or Accept,
most of the UE simulator's CPU per registration. Here each thread keeps one object per message
class (and set of IEs) and sets or decodes the values of the next message into it.

A reused object must give exactly what a fresh one gives. MessageTemplate.build() sets the IEs as
Layer3.__init__(val=...) does, and only those IEs: one object per set of IE names, so the IEs a
message does not set stay as the template has them. parse_NAS5G() resets the presence of the
optional IEs and the IEs' inner structures before decoding, and drops an object that decoding grew
(an unknown IE) or left half done (an error). Only repr() tells a decoded message from a fresh one:
it also shows the fields of the optional IEs the message does not carry, which keep an earlier
message's values. A message is valid until its thread builds or decodes another of the same kind.
"""
import copy
import threading
from struct import unpack

from pycrate_mobile.TS24007 import (IE, Type1V, Type3V, Type4LV, Type6LVE, Type1TV, Type3TV, Type4TLV,
                                    Type6TLVE, Type2, RestOctets)
from pycrate_mobile.TS24501_FGMM import FGMMTypeClasses, FGMMSecProtNASMessage
from pycrate_mobile.TS24501_FGSM import FGSMTypeClasses
from pycrate_mobile.NAS5G import parse_NAS5G as pycrate_parse_NAS5G

_MANDATORY = (Type1V, Type3V, Type4LV, Type6LVE)
_OPTIONAL = (Type1TV, Type3TV, Type4TLV, Type6TLVE)


def _fresh_ie(ie):
    """ Put back the IE's value buffer and drop its inner IE, as in a newly cloned IE: pycrate then
    clones the inner IE from the class's template again when it sets or decodes one. """
    if ie._IE is not None:
        ie.unset_IE()
        ie._IE = None


def _set_ies(msg, val):
    """ Set the IEs named in val as Layer3.__init__(val=val) sets them (pycrate_mobile/TS24007.py) """
    for ie in msg._content:
        name = ie._name
        if name not in val:
            continue
        if isinstance(ie, _MANDATORY):
            _fresh_ie(ie)
            ie.set_val({'V': val[name]})
        elif isinstance(ie, _OPTIONAL):
            ie._trans = False
            _fresh_ie(ie)
            ie.set_val({'V': val[name]})
        elif isinstance(ie, Type2):
            ie._trans = False
        elif isinstance(ie, RestOctets):
            pass
        else:
            ie.set_val(val[name])


class MessageTemplate:
    """ Messages of one class whose fixed IEs are the same in every message.

    build(val) returns what cls(val={**fixed, **val}) returns, from an object of this thread's:
    created with the fixed IEs (and the first val), then given each later val's IEs.
    """

    def __init__(self, cls, fixed=None):
        self.cls = cls
        self.fixed = dict(fixed or {})
        self._local = threading.local()

    def build(self, val=None):
        val = val or {}
        objs = self._local.__dict__.setdefault('objs', {})
        key = frozenset(val)          # the same IEs set in every message the object carries
        msg = objs.get(key)
        if msg is None:
            # a copy: the template's values are not handed to pycrate, which might keep or change them
            msg = objs[key] = self.cls(val={**copy.deepcopy(self.fixed), **val})
            return msg
        try:
            _set_ies(msg, val)
        except Exception:
            del objs[key]             # half set: not to be reused
            raise
        return msg


# Message types whose decoding parse_NAS5G completes by parsing a container inside them (NAS message
# container, payload container, port management container): left to parse_NAS5G
_FGMM_INNER = {65, 76, 79, 94, 103, 104}
_FGSM_INNER = {193, 201, 203, 204}

_decoders = threading.local()


def _decode(cls, buf):
    objs = _decoders.__dict__.setdefault('objs', {})
    entry = objs.get(cls)
    if entry is None:
        msg = cls()
        entry = (msg, len(msg._content), msg._hier)
        if msg._rest is None:         # (no 5G NAS message has rest octets, whose decoding leaves state)
            objs[cls] = entry
    else:
        msg = entry[0]
        for ie in msg._content:
            if isinstance(ie, IE):
                _fresh_ie(ie)
        msg.reset_opts()              # optional IEs absent until decoded, as in a fresh object
        msg.set_env(None)             # out of the security protected message it was last put in
        msg._hier = entry[2]
    try:
        msg.from_bytes(buf)
    except Exception:
        objs.pop(cls, None)
        return None, 96               # invalid mandatory info, as parse_NAS5G
    if len(msg._content) != entry[1]:
        objs.pop(cls, None)           # an unknown IE was appended: fine for this message, not the next
    return msg, 0


def parse_NAS5G(buf, inner=True, sec_hdr=True):
    """ pycrate's parse_NAS5G, decoding plain messages into objects this thread reuses.

    Security protected messages get a new (small) outer object, as in pycrate; a plain message in
    one (header type 1 or 3) is decoded into a reused object. Messages with a container that
    pycrate parses too, and anything unusual, go to pycrate's parse_NAS5G.
    """
    if not (inner and sec_hdr):
        return pycrate_parse_NAS5G(buf, inner, sec_hdr)
    try:
        pd, shdr, typ = unpack('>BBB', buf[:3])
    except Exception:
        return pycrate_parse_NAS5G(buf, inner, sec_hdr)
    if pd == 126:
        if shdr in (1, 2, 3, 4):
            Msg = FGMMSecProtNASMessage()
            try:
                Msg.from_bytes(buf)
            except Exception:
                return None, 96
            if shdr in (1, 3):
                cont, err = parse_NAS5G(Msg[3].get_val(), inner=inner)
                if cont is not None:
                    Msg.replace(Msg[3], cont)
                return Msg, err
            return Msg, 0
        cls = FGMMTypeClasses.get(typ) if typ not in _FGMM_INNER else None
    elif pd == 46 and len(buf) > 3:
        typ = buf[3]
        cls = FGSMTypeClasses.get(typ) if typ not in _FGSM_INNER else None
    else:
        cls = None
    if cls is None:
        return pycrate_parse_NAS5G(buf, inner, sec_hdr)
    return _decode(cls, buf)
