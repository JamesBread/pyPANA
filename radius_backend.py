#!/usr/bin/env python3
"""
RADIUS Backend Integration for PANA
Implements RADIUS client functionality for enterprise authentication

This module addresses Phase 3 requirement: RADIUS backend integration
Allows PANA to delegate authentication to enterprise RADIUS servers
"""

import os
import socket
import struct
import hashlib
import hmac
import time
import logging
import threading
from typing import Optional, Tuple, Dict, Any, List
from enum import IntEnum
import random

# RADIUS Constants
RADIUS_AUTH_PORT = 1812
RADIUS_ACCT_PORT = 1813

class RadiusCode(IntEnum):
    """RADIUS packet codes"""
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    ACCOUNTING_REQUEST = 4
    ACCOUNTING_RESPONSE = 5
    ACCESS_CHALLENGE = 11
    STATUS_SERVER = 12
    STATUS_CLIENT = 13

class RadiusAttribute(IntEnum):
    """Common RADIUS attributes"""
    USER_NAME = 1
    USER_PASSWORD = 2
    NAS_IP_ADDRESS = 4
    NAS_PORT = 5
    SERVICE_TYPE = 6
    FRAMED_PROTOCOL = 7
    CALLED_STATION_ID = 30
    CALLING_STATION_ID = 31
    NAS_IDENTIFIER = 32
    STATE = 24
    CLASS = 25
    SESSION_TIMEOUT = 27
    IDLE_TIMEOUT = 28
    TERMINATION_ACTION = 29
    NAS_PORT_TYPE = 61
    CONNECT_INFO = 77
    EAP_MESSAGE = 79
    MESSAGE_AUTHENTICATOR = 80
    NAS_PORT_ID = 87

class RadiusServiceType(IntEnum):
    """RADIUS Service Types"""
    LOGIN = 1
    FRAMED = 2
    CALLBACK_LOGIN = 3
    CALLBACK_FRAMED = 4
    OUTBOUND = 5
    ADMINISTRATIVE = 6
    NAS_PROMPT = 7
    AUTHENTICATE_ONLY = 8
    CALLBACK_NAS_PROMPT = 9

class RadiusNASPortType(IntEnum):
    """NAS Port Types"""
    ASYNC = 0
    SYNC = 1
    ISDN_SYNC = 2
    ISDN_ASYNC_V120 = 3
    ISDN_ASYNC_V110 = 4
    VIRTUAL = 5
    PIAFS = 6
    HDLC_CLEAR_CHANNEL = 7
    X25 = 8
    X75 = 9
    G3_FAX = 10
    SDSL = 11
    ADSL_CAP = 12
    ADSL_DMT = 13
    IDSL = 14
    ETHERNET = 15
    XDSL = 16
    CABLE = 17
    WIRELESS_OTHER = 18
    WIRELESS_802_11 = 19


class RadiusPacket:
    """RADIUS packet structure"""
    
    def __init__(self, code: RadiusCode, identifier: int = None, 
                 authenticator: bytes = None):
        """
        Initialize RADIUS packet
        
        Args:
            code: RADIUS packet code
            identifier: Packet identifier (0-255)
            authenticator: 16-byte authenticator
        """
        self.code = code
        self.identifier = identifier or random.randint(0, 255)
        self.authenticator = authenticator or os.urandom(16)
        self.attributes = []
        
    def add_attribute(self, attr_type: int, value: bytes):
        """Add attribute to packet"""
        if len(value) > 253:  # Max attribute length
            raise ValueError(f"Attribute too long: {len(value)} > 253")
        self.attributes.append((attr_type, value))
    
    def add_string(self, attr_type: int, value: str):
        """Add string attribute"""
        self.add_attribute(attr_type, value.encode('utf-8'))
    
    def add_integer(self, attr_type: int, value: int):
        """Add integer attribute"""
        self.add_attribute(attr_type, struct.pack('!I', value))
    
    def add_ipaddr(self, attr_type: int, ip: str):
        """Add IP address attribute"""
        parts = ip.split('.')
        if len(parts) != 4:
            raise ValueError(f"Invalid IP address: {ip}")
        ip_bytes = bytes([int(p) for p in parts])
        self.add_attribute(attr_type, ip_bytes)
    
    def add_eap_message(self, eap_data: bytes):
        """
        Add EAP-Message attribute (may fragment)
        
        Large EAP messages are split into multiple 253-byte attributes
        """
        offset = 0
        while offset < len(eap_data):
            chunk_size = min(253, len(eap_data) - offset)
            chunk = eap_data[offset:offset + chunk_size]
            self.add_attribute(RadiusAttribute.EAP_MESSAGE, chunk)
            offset += chunk_size
    
    def get_eap_message(self) -> bytes:
        """Extract and concatenate all EAP-Message attributes"""
        eap_data = b''
        for attr_type, value in self.attributes:
            if attr_type == RadiusAttribute.EAP_MESSAGE:
                eap_data += value
        return eap_data
    
    def pack(self, secret: bytes) -> bytes:
        """
        Pack packet into bytes
        
        Args:
            secret: RADIUS shared secret
            
        Returns:
            Packed RADIUS packet
        """
        # Pack attributes
        attr_data = b''
        for attr_type, value in self.attributes:
            attr_len = len(value) + 2  # Type(1) + Length(1) + Value
            attr_data += struct.pack('!BB', attr_type, attr_len) + value
        
        # Calculate length
        length = 20 + len(attr_data)  # Header(20) + Attributes
        
        # Pack header
        packet = struct.pack('!BBH16s',
            self.code,
            self.identifier,
            length,
            self.authenticator
        )
        packet += attr_data
        
        # Add Message-Authenticator if EAP-Message present
        if self.has_eap_message():
            # Calculate Message-Authenticator
            msg_auth = self.calculate_message_authenticator(packet, secret)
            # Add attribute
            packet += struct.pack('!BB', RadiusAttribute.MESSAGE_AUTHENTICATOR, 18)
            packet += msg_auth
            # Update length
            length += 18
            packet = packet[:2] + struct.pack('!H', length) + packet[4:]
        
        return packet
    
    def has_eap_message(self) -> bool:
        """Check if packet contains EAP-Message"""
        return any(attr[0] == RadiusAttribute.EAP_MESSAGE for attr in self.attributes)
    
    def calculate_message_authenticator(self, packet: bytes, secret: bytes) -> bytes:
        """Calculate Message-Authenticator for packet with EAP"""
        # Temporarily set Message-Authenticator to zeros
        temp_packet = packet + struct.pack('!BB16s', 
            RadiusAttribute.MESSAGE_AUTHENTICATOR, 18, b'\x00' * 16)
        # Calculate HMAC-MD5
        return hmac.new(secret, temp_packet, hashlib.md5).digest()
    
    @classmethod
    def unpack(cls, data: bytes, secret: bytes) -> 'RadiusPacket':
        """
        Unpack RADIUS packet from bytes
        
        Args:
            data: Raw packet data
            secret: RADIUS shared secret
            
        Returns:
            RadiusPacket object
        """
        if len(data) < 20:
            raise ValueError("Packet too short")
        
        # Unpack header
        code, identifier, length, authenticator = struct.unpack('!BBH16s', data[:20])
        
        if len(data) != length:
            raise ValueError(f"Length mismatch: {len(data)} != {length}")
        
        packet = cls(RadiusCode(code), identifier, authenticator)
        
        # Unpack attributes
        offset = 20
        while offset < length:
            if offset + 2 > length:
                break
            attr_type, attr_len = struct.unpack('!BB', data[offset:offset+2])
            if attr_len < 2 or offset + attr_len > length:
                break
            value = data[offset+2:offset+attr_len]
            packet.attributes.append((attr_type, value))
            offset += attr_len
        
        # Verify Message-Authenticator if present
        if packet.has_eap_message():
            msg_auth = packet.get_attribute(RadiusAttribute.MESSAGE_AUTHENTICATOR)
            if msg_auth:
                # Verify Message-Authenticator
                # Replace the Message-Authenticator with zeros for calculation
                temp_data = bytearray(data)
                for i in range(len(data) - 18):
                    if data[i:i+2] == struct.pack('!BB', RadiusAttribute.MESSAGE_AUTHENTICATOR, 18):
                        # Found Message-Authenticator attribute, zero it out
                        temp_data[i+2:i+18] = b'\x00' * 16
                        break
                
                # Calculate expected Message-Authenticator
                expected_auth = hmac.new(secret, bytes(temp_data), hashlib.md5).digest()
                
                # Verify it matches
                if msg_auth != expected_auth:
                    raise ValueError("Message-Authenticator verification failed")
        
        return packet
    
    def get_attribute(self, attr_type: int) -> Optional[bytes]:
        """Get first occurrence of attribute"""
        for t, v in self.attributes:
            if t == attr_type:
                return v
        return None


class RadiusClient:
    """
    RADIUS client for enterprise authentication
    
    Supports EAP pass-through for PANA-RADIUS integration
    """
    
    def __init__(self, server: str, secret: str, port: int = RADIUS_AUTH_PORT,
                 timeout: int = 5, retries: int = 3):
        """
        Initialize RADIUS client
        
        Args:
            server: RADIUS server address
            secret: Shared secret
            port: RADIUS port (default 1812)
            timeout: Response timeout in seconds
            retries: Number of retries
        """
        self.server = server
        self.secret = secret.encode('utf-8') if isinstance(secret, str) else secret
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.logger = logging.getLogger('RADIUSClient')
        
        # Socket for communication
        self.socket = None
        
        # Request tracking
        self.pending_requests = {}
        self.lock = threading.Lock()
        
        # NAS configuration
        self.nas_ip = self._get_local_ip()
        self.nas_identifier = socket.gethostname()
        
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote host to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.server, self.port))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return '127.0.0.1'
    
    def _create_socket(self):
        """Create UDP socket for RADIUS"""
        if self.socket:
            self.socket.close()
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(self.timeout)
        self.socket.bind(('', 0))  # Bind to any available port
    
    def send_access_request_eap(self, username: str, eap_data: bytes,
                                state: bytes = None) -> Tuple[RadiusCode, bytes, Dict]:
        """
        Send Access-Request with EAP data
        
        Args:
            username: User identity
            eap_data: EAP packet data
            state: State from previous Access-Challenge
            
        Returns:
            Tuple of (response_code, eap_response, attributes)
        """
        if not self.socket:
            self._create_socket()
        
        # Create Access-Request packet
        packet = RadiusPacket(RadiusCode.ACCESS_REQUEST)
        
        # Add attributes
        packet.add_string(RadiusAttribute.USER_NAME, username)
        packet.add_ipaddr(RadiusAttribute.NAS_IP_ADDRESS, self.nas_ip)
        packet.add_string(RadiusAttribute.NAS_IDENTIFIER, self.nas_identifier)
        packet.add_integer(RadiusAttribute.NAS_PORT, 0)
        packet.add_integer(RadiusAttribute.NAS_PORT_TYPE, RadiusNASPortType.VIRTUAL)
        packet.add_integer(RadiusAttribute.SERVICE_TYPE, RadiusServiceType.FRAMED)
        
        # Add State if provided (from Access-Challenge)
        if state:
            packet.add_attribute(RadiusAttribute.STATE, state)
        
        # Add EAP-Message
        packet.add_eap_message(eap_data)
        
        # Send packet and wait for response
        response = self._send_and_receive(packet)
        
        if not response:
            return (RadiusCode.ACCESS_REJECT, None, {})
        
        # Extract EAP from response
        eap_response = response.get_eap_message()
        
        # Extract other attributes
        attributes = {
            'state': response.get_attribute(RadiusAttribute.STATE),
            'class': response.get_attribute(RadiusAttribute.CLASS),
            'session_timeout': response.get_attribute(RadiusAttribute.SESSION_TIMEOUT),
        }
        
        return (response.code, eap_response, attributes)
    
    def _send_and_receive(self, packet: RadiusPacket) -> Optional[RadiusPacket]:
        """
        Send packet and receive response
        
        Args:
            packet: RADIUS packet to send
            
        Returns:
            Response packet or None
        """
        packet_data = packet.pack(self.secret)
        
        for attempt in range(self.retries):
            try:
                # Send packet
                self.socket.sendto(packet_data, (self.server, self.port))
                self.logger.debug(f"Sent {packet.code.name} to {self.server}:{self.port}")
                
                # Receive response
                response_data, addr = self.socket.recvfrom(4096)
                
                # Unpack response
                response = RadiusPacket.unpack(response_data, self.secret)
                
                # Verify response matches request
                if response.identifier == packet.identifier:
                    self.logger.debug(f"Received {response.code.name} from {addr}")
                    return response
                else:
                    self.logger.warning(f"Identifier mismatch: {response.identifier} != {packet.identifier}")
                    
            except socket.timeout:
                self.logger.warning(f"Timeout on attempt {attempt + 1}/{self.retries}")
                continue
            except Exception as e:
                self.logger.error(f"Error communicating with RADIUS server: {e}")
                break
        
        return None
    
    def close(self):
        """Close RADIUS client"""
        if self.socket:
            self.socket.close()
            self.socket = None


class RadiusEAPPassthrough:
    """
    RADIUS EAP pass-through handler for PANA integration
    
    This class bridges PANA EAP messages with RADIUS server
    """
    
    def __init__(self, radius_server: str, radius_secret: str, 
                 radius_port: int = RADIUS_AUTH_PORT):
        """
        Initialize RADIUS EAP pass-through
        
        Args:
            radius_server: RADIUS server address
            radius_secret: Shared secret
            radius_port: RADIUS port
        """
        self.radius_client = RadiusClient(
            radius_server, 
            radius_secret,
            radius_port
        )
        self.logger = logging.getLogger('RADIUS-EAP-Passthrough')
        
        # Session tracking
        self.sessions = {}  # session_id -> session_data
        
    def process_eap_for_radius(self, session_id: str, username: str, 
                               eap_data: bytes) -> Tuple[bool, bytes]:
        """
        Process EAP data through RADIUS
        
        Args:
            session_id: Session identifier
            username: User identity
            eap_data: EAP packet
            
        Returns:
            Tuple of (success, eap_response)
        """
        # Get or create session
        session = self.sessions.get(session_id, {})
        
        # Send to RADIUS
        code, eap_response, attributes = self.radius_client.send_access_request_eap(
            username,
            eap_data,
            session.get('state')
        )
        
        # Update session state
        if attributes.get('state'):
            session['state'] = attributes['state']
            self.sessions[session_id] = session
        
        # Handle response
        if code == RadiusCode.ACCESS_ACCEPT:
            self.logger.info(f"RADIUS authentication successful for {username}")
            # Clean up session
            self.sessions.pop(session_id, None)
            return (True, eap_response)
            
        elif code == RadiusCode.ACCESS_CHALLENGE:
            self.logger.debug(f"RADIUS Access-Challenge for {username}")
            return (None, eap_response)  # Continue authentication
            
        elif code == RadiusCode.ACCESS_REJECT:
            self.logger.warning(f"RADIUS authentication failed for {username}")
            # Clean up session
            self.sessions.pop(session_id, None)
            return (False, eap_response)
        
        else:
            self.logger.error(f"Unexpected RADIUS response: {code}")
            return (False, None)
    
    def close(self):
        """Close RADIUS client"""
        self.radius_client.close()


# Test function
def test_radius_backend():
    """Test RADIUS backend functionality"""
    logging.basicConfig(level=logging.DEBUG)
    
    print("\n" + "="*70)
    print("  Testing RADIUS Backend Integration")
    print("="*70)
    
    # Test packet creation
    print("\n1. Testing RADIUS packet creation...")
    packet = RadiusPacket(RadiusCode.ACCESS_REQUEST)
    packet.add_string(RadiusAttribute.USER_NAME, "test@example.com")
    packet.add_ipaddr(RadiusAttribute.NAS_IP_ADDRESS, "192.168.1.1")
    
    # Add EAP-Identity Response
    eap_identity = b'\x02\x01\x00\x15\x01test@example.com'
    packet.add_eap_message(eap_identity)
    
    secret = b"testing123"
    packed = packet.pack(secret)
    print(f"   Created Access-Request packet: {len(packed)} bytes")
    print(f"   Has EAP-Message: {packet.has_eap_message()}")
    
    # Test unpacking
    print("\n2. Testing packet unpacking...")
    unpacked = RadiusPacket.unpack(packed, secret)
    print(f"   Unpacked code: {unpacked.code.name}")
    print(f"   Attributes: {len(unpacked.attributes)}")
    
    eap_msg = unpacked.get_eap_message()
    print(f"   EAP message recovered: {len(eap_msg)} bytes")
    
    print("\n✅ RADIUS backend module ready for integration")
    
    # Note: Actual RADIUS server testing requires a real server
    print("\nNote: Full testing requires a RADIUS server.")
    print("Configure with: RadiusClient('radius.server.com', 'secret')")


if __name__ == "__main__":
    test_radius_backend()