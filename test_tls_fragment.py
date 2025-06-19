import struct
from pyPANA import EAPTLSHandler, EAP_REQUEST, EAP_RESPONSE, EAP_SUCCESS, EAP_TYPE_TLS

class DummyBIO:
    def __init__(self, data=b''):
        self._data = data
    def read(self):
        data = self._data
        self._data = b''
        return data
    def write(self, data):
        pass

class DummySSL:
    def __init__(self, data=b''):
        self.data = data
    def do_handshake(self):
        pass
    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.2", 128)
    def export_keying_material(self, label, length, context):
        return b"\x00" * length


def test_final_fragment_before_success():
    server = EAPTLSHandler(is_server=True)
    server.state = 'TLS_HANDSHAKE'
    server._derive_msk_emsk = lambda: None
    server.sslobj = DummySSL(b'finaltls')
    server.incoming = DummyBIO()
    server.outgoing = DummyBIO(b'finaltls')

    # Client sends final TLS fragment
    fragment = struct.pack('!BBHBB', EAP_RESPONSE, 1, 7, EAP_TYPE_TLS, 0) + b'X'
    resp = server.process_eap_message(fragment)
    # First response should be TLS fragment, not success
    assert resp is not None
    code = resp[0]
    assert code == EAP_REQUEST
    assert resp[4] == EAP_TYPE_TLS

    # Send ACK for this fragment
    ack = struct.pack('!BBHBB', EAP_RESPONSE, 2, 6, EAP_TYPE_TLS, 0)
    success = server.process_eap_message(ack)
    assert success[0] == EAP_SUCCESS

if __name__ == '__main__':
    test_final_fragment_before_success()
    print('test passed')
