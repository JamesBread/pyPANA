#!/usr/bin/env python3
"""
EAP-TLS Factory - Returns the best available EAP-TLS implementation
"""

import logging

logger = logging.getLogger(__name__)


def create_eap_tls_handler(is_server=False, cert_file=None, key_file=None, ca_cert=None):
    """
    Create the best available EAP-TLS handler
    
    Args:
        is_server: True if server, False if client
        cert_file: Path to certificate file
        key_file: Path to private key file
        ca_cert: Path to CA certificate file
    
    Returns:
        EAP-TLS handler instance
    """
    # Try PyOpenSSL implementation first (preferred for proper MSK export)
    try:
        from eap_tls_pyopenssl import EAPTLSWithPyOpenSSL
        logger.info("Using PyOpenSSL-based EAP-TLS implementation")
        return EAPTLSWithPyOpenSSL(
            is_server=is_server,
            cert_file=cert_file,
            key_file=key_file,
            ca_cert=ca_cert
        )
    except ImportError:
        logger.debug("PyOpenSSL implementation not available")
    except Exception as e:
        logger.warning(f"Failed to initialize PyOpenSSL implementation: {e}")
    
    # Fallback to standard implementation
    from eap_tls import EAPTLSHandler
    logger.info("Using standard EAP-TLS implementation (limited MSK export)")
    return EAPTLSHandler(
        is_server=is_server,
        cert_file=cert_file,
        key_file=key_file,
        ca_file=ca_cert
    )