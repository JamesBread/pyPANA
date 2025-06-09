#!/usr/bin/env python3
"""
Basic test without external dependencies
Tests core PANA message structure
"""

import struct

# Copy minimal constants and classes from pyPANA.py for testing
PANA_CLIENT_INITIATION = 1
PANA_AUTH = 2
FLAG_REQUEST = 0x8000
FLAG_START = 0x4000
FLAG_AUTH = 0x1000
AVP_NONCE = 5
AVP_AUTH = 1

class PANAMessage:
    def __init__(self):
        self.flags = 0
        self.msg_type = 0
        self.session_id = 0
        self.seq_number = 0
        self.avps = []
        
    def pack(self):
        header = struct.pack('!HHII', 
                           self.flags,
                           self.msg_type,
                           self.session_id,
                           self.seq_number)
        avp_data = b''
        for avp in self.avps:
            avp_data += avp.pack()
        return header + avp_data
    
    def unpack(self, data):
        if len(data) < 16:
            raise ValueError("Invalid PANA message length")
        (self.flags, self.msg_type, 
         self.session_id, self.seq_number) = struct.unpack('!HHII', data[:16])
        return len(data)

class AVP:
    def __init__(self, code=0, flags=0, value=b''):
        self.code = code
        self.flags = flags
        self.value = value
        
    def pack(self):
        length = 8 + len(self.value)
        padding = (4 - (len(self.value) % 4)) % 4
        header = struct.pack('!HHI', self.code, self.flags, length)
        return header + self.value + (b'\x00' * padding)

def test_basic_message():
    """Test basic message structure"""
    print("Testing basic PANA message structure...")
    
    # Create a simple PCI message
    msg = PANAMessage()
    msg.flags = FLAG_REQUEST | FLAG_START
    msg.msg_type = PANA_CLIENT_INITIATION
    msg.session_id = 0x12345678
    msg.seq_number = 1
    
    # Pack the message
    packed = msg.pack()
    print(f"Message packed: {len(packed)} bytes")
    print(f"Hex: {packed.hex()}")
    
    # Verify header
    flags, msg_type, sess_id, seq = struct.unpack('!HHII', packed[:16])
    assert flags == (FLAG_REQUEST | FLAG_START)
    assert msg_type == PANA_CLIENT_INITIATION
    assert sess_id == 0x12345678
    assert seq == 1
    
    print("✓ Basic message structure test passed")

def test_avp_structure():
    """Test AVP structure"""
    print("\nTesting AVP structure...")
    
    avp = AVP(AVP_NONCE, 0, b'test_nonce_data!')  # 16 bytes
    packed = avp.pack()
    
    # Verify AVP header
    code, flags, length = struct.unpack('!HHI', packed[:8])
    assert code == AVP_NONCE
    assert flags == 0
    assert length == 24  # 8 header + 16 data
    
    # Verify padding
    assert len(packed) == 24  # No padding needed for 16-byte value
    
    print(f"AVP packed: {len(packed)} bytes")
    print("✓ AVP structure test passed")

def main():
    print("pyPANA Basic Structure Tests")
    print("============================\n")
    
    try:
        test_basic_message()
        test_avp_structure()
        print("\n✅ All basic tests passed!")
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()