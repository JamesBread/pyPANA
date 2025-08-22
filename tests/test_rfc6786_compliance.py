#!/usr/bin/env python3
"""
Test RFC 6786 Compliance
Tests full RFC 6786 encryption implementation and policy compliance
"""

import unittest
import struct
import os
from unittest.mock import Mock, MagicMock

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pana_messages import PANAMessage, AVP, EncryptedAVPSet, create_avp_uint32
from pana_constants import (
    AVP_AUTH, AVP_EAP_PAYLOAD, AVP_INTEGRITY_ALGORITHM,
    AVP_KEY_ID, AVP_NONCE, AVP_PRF_ALGORITHM, AVP_RESULT_CODE,
    AVP_SESSION_LIFETIME, AVP_TERMINATION_CAUSE,
    AVP_PAC_INFORMATION, AVP_RELAYED_MESSAGE,
    AVP_ENCRYPTION_ALGORITHM, AVP_ENCRYPTION_ENCAP,
    AES128_CTR, PANA_AUTH, FLAG_REQUEST
)
from pana_encryption_policy import EncryptionPolicy, EncryptionContext
from pana_crypto import CryptoContext
from pana_session import PANASession


class TestRFC6786EncryptionPolicy(unittest.TestCase):
    """Test RFC 6786 Section 6.1 encryption policy table"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.policy = EncryptionPolicy()
        self.policy.encryption_enabled = True
    
    def test_never_encrypt_avps(self):
        """Test AVPs with 'N' (MUST NOT encrypt) requirement"""
        # RFC 5191 AVPs with 'N' requirement
        never_encrypt = [
            AVP_AUTH,
            AVP_INTEGRITY_ALGORITHM,
            AVP_KEY_ID,
            AVP_NONCE,
            AVP_PRF_ALGORITHM,
            AVP_RESULT_CODE,
        ]
        
        # RFC 6345 AVPs with 'N' requirement
        never_encrypt.extend([
            AVP_PAC_INFORMATION,
            AVP_RELAYED_MESSAGE,
        ])
        
        # RFC 6786 AVPs with 'N' requirement
        never_encrypt.extend([
            AVP_ENCRYPTION_ALGORITHM,
            AVP_ENCRYPTION_ENCAP,
        ])
        
        for avp_code in never_encrypt:
            requirement = self.policy.get_avp_encryption_requirement(avp_code)
            self.assertEqual(requirement, 'N', 
                           f"AVP {avp_code} should have 'N' requirement")
            self.assertFalse(self.policy.is_avp_encryption_required(avp_code))
            self.assertFalse(self.policy.is_avp_encryption_recommended(avp_code))
    
    def test_optional_encrypt_avps(self):
        """Test AVPs with 'X' (MAY encrypt) requirement"""
        optional_encrypt = [
            AVP_EAP_PAYLOAD,
            AVP_SESSION_LIFETIME,
            AVP_TERMINATION_CAUSE,
        ]
        
        for avp_code in optional_encrypt:
            requirement = self.policy.get_avp_encryption_requirement(avp_code)
            self.assertEqual(requirement, 'X', 
                           f"AVP {avp_code} should have 'X' requirement")
            self.assertFalse(self.policy.is_avp_encryption_required(avp_code))
            self.assertTrue(self.policy.is_avp_encryption_recommended(avp_code))
    
    def test_undefined_avp_defaults_to_may(self):
        """Test that undefined AVPs default to 'X' (MAY) per RFC 6786"""
        undefined_avp_code = 99999  # Not defined in spec
        requirement = self.policy.get_avp_encryption_requirement(undefined_avp_code)
        self.assertEqual(requirement, 'X', 
                        "Undefined AVPs should default to 'X' per RFC 6786")
    
    def test_no_mandatory_encrypt_avps(self):
        """Test that no AVPs have 'Y' (MUST encrypt) requirement in current RFC"""
        # Current RFC 6786 does not define any 'Y' AVPs
        self.assertEqual(len(self.policy.mandatory_encrypt_avps), 0,
                        "No AVPs should have mandatory encryption in current RFC")
    
    def test_get_avps_to_encrypt(self):
        """Test filtering AVPs for encryption"""
        avps = [
            AVP(AVP_AUTH, 0, b'auth_data'),  # Should NOT encrypt (N)
            AVP(AVP_SESSION_LIFETIME, 0, struct.pack('!I', 3600)),  # MAY encrypt (X)
            AVP(AVP_EAP_PAYLOAD, 0, b'eap_data'),  # MAY encrypt (X)
            AVP(AVP_NONCE, 0, b'nonce_data'),  # Should NOT encrypt (N)
        ]
        
        to_encrypt, plaintext = self.policy.get_avps_to_encrypt(avps)
        
        # Should encrypt optional AVPs
        self.assertEqual(len(to_encrypt), 2)
        avp_codes_to_encrypt = [avp.code for avp in to_encrypt]
        self.assertIn(AVP_SESSION_LIFETIME, avp_codes_to_encrypt)
        self.assertIn(AVP_EAP_PAYLOAD, avp_codes_to_encrypt)
        
        # Should keep 'N' AVPs in plaintext
        self.assertEqual(len(plaintext), 2)
        avp_codes_plaintext = [avp.code for avp in plaintext]
        self.assertIn(AVP_AUTH, avp_codes_plaintext)
        self.assertIn(AVP_NONCE, avp_codes_plaintext)


class TestEncryptionContext(unittest.TestCase):
    """Test encryption context and negotiation"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.policy = EncryptionPolicy()
        self.policy.encryption_enabled = True
        self.context = EncryptionContext(self.policy)
    
    def test_initial_state(self):
        """Test initial encryption context state"""
        self.assertIsNone(self.context.negotiated_algorithm)
        self.assertFalse(self.context.encryption_active)
        self.assertFalse(self.context.is_encryption_active())
    
    def test_successful_negotiation(self):
        """Test successful algorithm negotiation"""
        result = self.context.negotiate_encryption(AES128_CTR)
        
        self.assertTrue(result)
        self.assertEqual(self.context.negotiated_algorithm, AES128_CTR)
        self.assertTrue(self.context.encryption_active)
        self.assertTrue(self.context.is_encryption_active())
        self.assertEqual(self.context.get_negotiated_algorithm(), AES128_CTR)
    
    def test_failed_negotiation_unsupported(self):
        """Test negotiation failure with unsupported algorithm"""
        unsupported_algo = 99999
        result = self.context.negotiate_encryption(unsupported_algo)
        
        self.assertFalse(result)
        self.assertIsNone(self.context.negotiated_algorithm)
        self.assertFalse(self.context.encryption_active)
        self.assertFalse(self.context.is_encryption_active())
    
    def test_negotiation_disabled_policy(self):
        """Test negotiation when encryption is disabled"""
        self.policy.encryption_enabled = False
        result = self.context.negotiate_encryption(AES128_CTR)
        
        self.assertFalse(result)
        self.assertFalse(self.context.is_encryption_active())


class TestMessageEncryption(unittest.TestCase):
    """Test message-level encryption operations"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.crypto_ctx = CryptoContext()
        # Generate test keys
        self.crypto_ctx.derive_keys(
            b'test_msk' * 8,  # 64-byte MSK
            b'test_emsk' * 8  # 64-byte EMSK
        )
        
        self.policy = EncryptionPolicy()
        self.policy.encryption_enabled = True
        
        self.enc_context = EncryptionContext(self.policy)
        self.enc_context.negotiate_encryption(AES128_CTR)
    
    def test_encrypt_decrypt_avp_set(self):
        """Test encrypting and decrypting a set of AVPs"""
        # Create AVP set
        enc_set = EncryptedAVPSet(self.crypto_ctx)
        
        # Add AVPs to encrypt
        avp1 = AVP(AVP_SESSION_LIFETIME, 0, struct.pack('!I', 3600))
        avp2 = AVP(AVP_EAP_PAYLOAD, 0, b'test_eap_data')
        enc_set.add_avp(avp1)
        enc_set.add_avp(avp2)
        
        # Create Encryption-Encap AVP
        encap_avp = enc_set.create_encryption_encap_avp()
        
        self.assertEqual(encap_avp.code, AVP_ENCRYPTION_ENCAP)
        self.assertGreater(len(encap_avp.value), 0)
        
        # Decrypt AVPs
        dec_set = EncryptedAVPSet(self.crypto_ctx)
        decrypted_avps = dec_set.decrypt_encryption_encap_avp(encap_avp)
        
        self.assertEqual(len(decrypted_avps), 2)
        self.assertEqual(decrypted_avps[0].code, AVP_SESSION_LIFETIME)
        self.assertEqual(decrypted_avps[0].value, struct.pack('!I', 3600))
        self.assertEqual(decrypted_avps[1].code, AVP_EAP_PAYLOAD)
        self.assertEqual(decrypted_avps[1].value, b'test_eap_data')
    
    def test_message_apply_encryption(self):
        """Test applying encryption to a PANA message"""
        msg = PANAMessage(self.enc_context)
        msg.msg_type = PANA_AUTH
        msg.flags = FLAG_REQUEST
        msg.session_id = 0x12345678
        msg.seq_number = 1
        
        # Add AVPs
        msg.add_avp(AVP(AVP_AUTH, 0, b'auth_data'))  # Should NOT encrypt
        msg.add_avp(AVP(AVP_SESSION_LIFETIME, 0, struct.pack('!I', 3600)))  # MAY encrypt
        msg.add_avp(AVP(AVP_EAP_PAYLOAD, 0, b'eap_data'))  # MAY encrypt
        
        # Apply encryption
        result = msg.apply_encryption(self.crypto_ctx)
        
        self.assertTrue(result)
        
        # Check that appropriate AVPs were encrypted
        found_encap = False
        found_auth = False
        for avp in msg.avps:
            if avp.code == AVP_ENCRYPTION_ENCAP:
                found_encap = True
            elif avp.code == AVP_AUTH:
                found_auth = True
                self.assertEqual(avp.value, b'auth_data')  # Should remain plaintext
        
        self.assertTrue(found_encap, "Should have Encryption-Encap AVP")
        self.assertTrue(found_auth, "AUTH AVP should remain in plaintext")
    
    def test_message_decrypt(self):
        """Test decrypting AVPs from a message"""
        # First create an encrypted message
        msg = PANAMessage(self.enc_context)
        msg.add_avp(AVP(AVP_SESSION_LIFETIME, 0, struct.pack('!I', 7200)))
        msg.add_avp(AVP(AVP_EAP_PAYLOAD, 0, b'encrypted_eap'))
        
        msg.apply_encryption(self.crypto_ctx)
        
        # Now decrypt
        decrypted_avps = msg.decrypt_avps(self.crypto_ctx)
        
        self.assertEqual(len(decrypted_avps), 2)
        
        # Verify decrypted content
        session_lifetime_found = False
        eap_payload_found = False
        for avp in decrypted_avps:
            if avp.code == AVP_SESSION_LIFETIME:
                session_lifetime_found = True
                lifetime = struct.unpack('!I', avp.value)[0]
                self.assertEqual(lifetime, 7200)
            elif avp.code == AVP_EAP_PAYLOAD:
                eap_payload_found = True
                self.assertEqual(avp.value, b'encrypted_eap')
        
        self.assertTrue(session_lifetime_found)
        self.assertTrue(eap_payload_found)


class TestSessionEncryption(unittest.TestCase):
    """Test session-level encryption management"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.policy = EncryptionPolicy()
        self.policy.encryption_enabled = True
        self.session = PANASession(0x12345678, ('127.0.0.1', 716), self.policy)
        
        # Generate keys for session
        self.session.crypto_ctx.derive_keys(
            b'test_msk' * 8,
            b'test_emsk' * 8
        )
    
    def test_session_encryption_negotiation(self):
        """Test encryption negotiation at session level"""
        # Initially not active
        self.assertFalse(self.session.is_encryption_active())
        self.assertIsNone(self.session.get_encryption_algorithm())
        
        # Negotiate encryption
        result = self.session.negotiate_encryption(AES128_CTR)
        
        self.assertTrue(result)
        self.assertTrue(self.session.is_encryption_active())
        self.assertEqual(self.session.get_encryption_algorithm(), AES128_CTR)
    
    def test_session_encryption_disabled(self):
        """Test session when encryption is disabled"""
        self.policy.encryption_enabled = False
        
        result = self.session.negotiate_encryption(AES128_CTR)
        
        self.assertFalse(result)
        self.assertFalse(self.session.is_encryption_active())


class TestEncryptionErrorHandling(unittest.TestCase):
    """Test error handling in encryption operations"""
    
    def test_encrypt_without_key(self):
        """Test encryption fails gracefully without key"""
        crypto_ctx = CryptoContext()  # No keys generated
        enc_set = EncryptedAVPSet(crypto_ctx)
        enc_set.add_avp(AVP(AVP_SESSION_LIFETIME, 0, b'data'))
        
        with self.assertRaises(ValueError) as cm:
            enc_set.create_encryption_encap_avp()
        
        self.assertIn("No encryption key", str(cm.exception))
    
    def test_decrypt_invalid_avp(self):
        """Test decryption fails with invalid AVP"""
        crypto_ctx = CryptoContext()
        crypto_ctx.derive_keys(b'msk' * 8, b'emsk' * 8)
        
        enc_set = EncryptedAVPSet(crypto_ctx)
        invalid_avp = AVP(AVP_AUTH, 0, b'not_encap')  # Wrong AVP type
        
        with self.assertRaises(ValueError) as cm:
            enc_set.decrypt_encryption_encap_avp(invalid_avp)
        
        self.assertIn("Not an Encryption-Encap AVP", str(cm.exception))
    
    def test_encrypt_empty_avp_set(self):
        """Test encryption fails with empty AVP set"""
        crypto_ctx = CryptoContext()
        crypto_ctx.derive_keys(b'msk' * 8, b'emsk' * 8)
        
        enc_set = EncryptedAVPSet(crypto_ctx)
        
        with self.assertRaises(ValueError) as cm:
            enc_set.create_encryption_encap_avp()
        
        self.assertIn("No AVPs to encrypt", str(cm.exception))


if __name__ == '__main__':
    unittest.main()