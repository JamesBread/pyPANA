from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest, AccessAccept, AccessReject, AccessChallenge
import os

_DICTIONARY = os.path.join(os.path.dirname(__file__), 'radius.dict')

class RADIUSClient:
    """Simple RADIUS client for EAP proxying."""

    def __init__(self, server, secret, port=1812):
        self.client = Client(server=server, secret=secret.encode(), dict=Dictionary(_DICTIONARY), authport=port)
        self.state = None

    def send_eap(self, eap):
        """Send an EAP packet to the RADIUS server.

        Returns a tuple of (reply_code, eap_reply).
        reply_code is one of pyrad.packet.AccessAccept, AccessReject or AccessChallenge.
        eap_reply may be None if no EAP-Message was present.
        """
        req = self.client.CreateAuthPacket(code=AccessRequest)
        req['EAP-Message'] = eap
        if self.state:
            req['State'] = self.state
        req.add_message_authenticator()
        reply = self.client.SendPacket(req)
        if 'State' in reply:
            self.state = reply['State'][0]
        eap_reply = b''.join(reply.get('EAP-Message', [])) if 'EAP-Message' in reply else None
        return reply.code, eap_reply
