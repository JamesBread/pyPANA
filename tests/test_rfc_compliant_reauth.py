#!/usr/bin/env python3
"""
Test RFC 5191 Compliant Re-authentication
Tests re-authentication using PANA-Notification with 'A' flag
"""

import unittest
import struct
import time
from unittest.mock import Mock, MagicMock, patch

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pana_messages import PANAMessage, AVP
from pana_constants import (
    PANA_NOTIFICATION,
    FLAG_REQUEST, FLAG_REAUTH,
    AVP_AUTH, AVP_SESSION_LIFETIME,
    DEFAULT_SESSION_LIFETIME
)
from pana_server import PANAAuthAgent
from pana_client import PANAClient
from pana_session import PANASession
from pana_crypto import CryptoContext
from pana_messages import create_avp_uint32, extract_avp_uint32


class TestRFCCompliantReauth(unittest.TestCase):
    """Test RFC 5191 compliant re-authentication using PANA-Notification"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.session_id = 0x12345678
        self.server_addr = ('127.0.0.1', 716)
        
    def test_reauth_request_format(self):
        """Test that re-auth request uses PANA-Notification with 'A' flag"""
        client = PANAClient('127.0.0.1')
        client.session_id = self.session_id
        client.seq_number = 10
        client.crypto_ctx = CryptoContext()
        client.crypto_ctx.pana_auth_key = b'test_key'
        client.socket = Mock()
        client.retransmit_mgr = Mock()
        
        # Call send_reauth_request
        client.send_reauth_request()
        
        # Verify message was sent
        client.socket.sendto.assert_called_once()
        sent_data = client.socket.sendto.call_args[0][0]
        
        # Parse the sent message
        msg = PANAMessage()
        msg.unpack(sent_data)
        
        # Verify message type is PANA_NOTIFICATION
        self.assertEqual(msg.msg_type, PANA_NOTIFICATION)
        
        # Verify both R and A flags are set
        self.assertTrue(msg.flags & FLAG_REQUEST, "Request flag should be set")
        self.assertTrue(msg.flags & FLAG_REAUTH, "Re-auth flag should be set")
        
        # Verify session ID
        self.assertEqual(msg.session_id, self.session_id)
        
        # Verify AUTH AVP is present
        auth_avp_found = False
        for avp in msg.avps:
            if avp.code == AVP_AUTH:
                auth_avp_found = True
                break
        self.assertTrue(auth_avp_found, "AUTH AVP should be present")
        
    def test_server_handles_reauth_notification(self):
        """Test that server properly handles re-auth notification with 'A' flag"""
        # Create mock server
        server = Mock()
        server.logger = Mock()
        server.socket = Mock()
        server.session_mgr = Mock()
        
        # Create a session
        session = PANASession(self.session_id, self.server_addr)
        session.crypto_ctx = CryptoContext()
        session.crypto_ctx.pana_auth_key = b'test_key'
        session.seq_number = 10
        session.lifetime = DEFAULT_SESSION_LIFETIME
        session.created_time = time.time()
        session.cancel_cleanup = Mock()
        session.mark_authenticated = Mock()
        session.schedule_cleanup = Mock()
        
        # Set up session manager to return our session
        server.session_mgr.get_session.return_value = session
        server.session_mgr.cleanup_authenticated_session = Mock()
        
        # Create re-auth request message
        msg = PANAMessage()
        msg.flags = FLAG_REQUEST | FLAG_REAUTH
        msg.msg_type = PANA_NOTIFICATION
        msg.session_id = self.session_id
        msg.seq_number = 5
        
        # Add AUTH AVP
        msg_without_auth = msg.pack()
        auth_value = session.crypto_ctx.compute_auth(msg_without_auth)
        msg.add_avp(AVP(AVP_AUTH, 0, auth_value))
        
        # Call the real handle_notification_msg method
        from pana_server import PANAAuthAgent
        real_handler = PANAAuthAgent.handle_notification_msg
        real_handler(server, msg, self.server_addr)
        
        # Verify re-authentication was processed
        session.cancel_cleanup.assert_called_once()
        session.mark_authenticated.assert_called_once()
        session.schedule_cleanup.assert_called_once()
        
        # Verify response was sent
        server.socket.sendto.assert_called_once()
        sent_data = server.socket.sendto.call_args[0][0]
        
        # Parse response
        response = PANAMessage()
        response.unpack(sent_data)
        
        # Verify response format
        self.assertEqual(response.msg_type, PANA_NOTIFICATION)
        self.assertTrue(response.flags & FLAG_REAUTH, "Re-auth flag should be set in response")
        self.assertFalse(response.flags & FLAG_REQUEST, "Request flag should not be set in response")
        
        # Verify Session-Lifetime AVP in response
        lifetime_avp_found = False
        for avp in response.avps:
            if avp.code == AVP_SESSION_LIFETIME:
                lifetime_avp_found = True
                lifetime = extract_avp_uint32(avp)
                self.assertEqual(lifetime, DEFAULT_SESSION_LIFETIME)
                break
        self.assertTrue(lifetime_avp_found, "Session-Lifetime AVP should be present")
        
    def test_client_handles_reauth_response(self):
        """Test that client properly handles re-auth response"""
        client = PANAClient('127.0.0.1')
        client.session_id = self.session_id
        client.seq_number = 10
        client.crypto_ctx = CryptoContext()
        client.crypto_ctx.pana_auth_key = b'test_key'
        client.retransmit_mgr = Mock()
        client.logger = Mock()
        client._start_session_monitoring = Mock()
        
        # Create re-auth response message
        msg = PANAMessage()
        msg.flags = FLAG_REAUTH  # Answer with A flag, no R flag
        msg.msg_type = PANA_NOTIFICATION
        msg.session_id = self.session_id
        msg.seq_number = 10
        
        # Add Session-Lifetime AVP
        new_lifetime = 7200  # 2 hours
        msg.add_avp(create_avp_uint32(AVP_SESSION_LIFETIME, new_lifetime))
        
        # Call handle_notification_msg
        client.handle_notification_msg(msg)
        
        # Verify retransmission was canceled
        client.retransmit_mgr.remove_message.assert_called_once_with(client.seq_number - 1)
        
        # Verify session lifetime was updated
        self.assertEqual(client.session_lifetime, new_lifetime)
        
        # Verify session monitoring was restarted
        client._start_session_monitoring.assert_called_once()
        
    def test_no_pana_reauth_message_type(self):
        """Verify PANA_REAUTH message type is not defined"""
        from pana_constants import __dict__ as constants
        
        # PANA_REAUTH should not exist in constants
        self.assertNotIn('PANA_REAUTH', constants, 
                        "PANA_REAUTH should not be defined in constants")
        
        # Verify only valid message types are defined
        valid_types = ['PANA_CLIENT_INITIATION', 'PANA_AUTH', 
                      'PANA_TERMINATION', 'PANA_NOTIFICATION']
        for msg_type in valid_types:
            self.assertIn(msg_type, constants, 
                         f"{msg_type} should be defined in constants")
            
    def test_message_validation_rejects_invalid_type(self):
        """Test that message validation rejects invalid message type 5"""
        msg_data = struct.pack('!HHHH II',
                              0,      # Reserved
                              16,     # Message Length (header only)
                              0,      # Flags
                              5,      # Invalid message type (was PANA_REAUTH)
                              0x12345678,  # Session ID
                              1)      # Sequence Number
        
        msg = PANAMessage()
        with self.assertRaises(ValueError) as context:
            msg.unpack(msg_data)
        
        self.assertIn("Invalid PANA message type", str(context.exception))
        

if __name__ == '__main__':
    unittest.main()