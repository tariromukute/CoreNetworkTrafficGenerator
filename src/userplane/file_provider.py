""" The file provider: each PDU session, as a JSON line, for a generator that reads them. """
import json
import os
from dataclasses import asdict

from .base import Context, Session, UserPlaneProvider


class FileProvider(UserPlaneProvider):
    """ Appends each session that comes up to a JSON-lines file (`path`, default
    <folder>/sessions.jsonl): supi, ue_ip, pdu_session_id, ul_teid, qfi, upf_address, dl_teid,
    gnb_address, ran_ue_ngap_id, amf_ue_ngap_id and t. The file lists the sessions that came up;
    releases are not recorded. It is emptied at start. """

    def __init__(self, config: dict, context: Context):
        super().__init__(config, context)
        self.path = config.get('path') or os.path.join(context.folder, 'sessions.jsonl')

    def start(self) -> None:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        open(self.path, 'w').close()

    def add_session(self, session: Session) -> None:
        # one write() per line on an O_APPEND file: a reader never sees half a line
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, (json.dumps(asdict(session)) + "\n").encode())
        finally:
            os.close(fd)
