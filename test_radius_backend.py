#!/usr/bin/env python3
"""
Unit test for RADIUS backend forwarding in PANAAuthAgent.
"""

import struct

from pyPANA import (
    PANAAuthAgent, PANAMessage, AVP,
    PANA_AUTH, AVP_EAP_PAYLOAD
)


class FakeRadiusReply(dict):
    """Simple dict-like object representing a RADIUS reply."""
    def __init__(self, code=11, eap=b'reply', state=b'state'):
        super().__init__()
        self.code = code
        if eap is not None:
            self['EAP-Message'] = [eap]
        if state is not None:
            self['State'] = [state]


class FakeRadiusClient:
    """Mock RADIUS client used for testing."""
    def __init__(self):
        self.sent = []

    def CreateAuthPacket(self, code=1):
        pkt = {'code': code}
        return pkt

    def SendPacket(self, pkt):
        self.sent.append(pkt)
        return FakeRadiusReply()


class FakeSocket:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))


def test_radius_forwarding():
    agent = PANAAuthAgent(radius_server='rad', radius_secret='secret')
    agent.socket = FakeSocket()
    agent.radius_client = FakeRadiusClient()

    key = (0x1, '198.51.100.10')
    session = agent.session_mgr.create_session(key, (key[1], 12345))

    msg = PANAMessage()
    msg.flags = 0
    msg.msg_type = PANA_AUTH
    msg.session_id = 0x1
    msg.seq_number = 0
    msg.avps.append(AVP(AVP_EAP_PAYLOAD, 0, b'eap'))

    agent.handle_auth_msg(msg, (key[1], 12345))

    assert len(agent.radius_client.sent) == 1
    assert session.radius_state == b'state'
    assert len(agent.socket.sent) == 1

    sent = agent.socket.sent[0][0]
    resp = PANAMessage()
    resp.unpack(sent)
    assert any(avp.code == AVP_EAP_PAYLOAD and avp.value == b'reply' for avp in resp.avps)


def main():
    try:
        test_radius_forwarding()
        print("\n✅ RADIUS backend test passed")
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        raise


if __name__ == "__main__":
    main()
