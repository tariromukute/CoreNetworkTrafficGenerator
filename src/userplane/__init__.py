""" User plane providers: what happens to a UE's PDU session once it is up.

The gNB hands each session to the providers listed in its configuration, as the session comes
up, and tells them when the UE is released, so UEs can be added (and removed) while others are
sending. A provider is a UserPlaneProvider (base.py):

    file   each session as a JSON line, for a generator that reads them (file_provider.py)
    xdp    CN-TG's own XDP generator, the default without a userPlane section (xdp_provider.py)
    trex   one TRex stream per session, through TRex's stateless Python API (trex_provider.py)

Several may run together, e.g. file and trex. A new one (tc-gtpu, a hardware generator ...)
implements UserPlaneProvider; it is named in the configuration as 'package.module:Class', or
added to service.create_provider() under a short name.
"""
from .base import Context, Session, UserPlaneProvider
from .service import UserPlane, create_provider, providers_from_config
