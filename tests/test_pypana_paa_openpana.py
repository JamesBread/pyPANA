#!/usr/bin/env python3
"""
Test script for pyPANA PAA interoperability with OpenPANA PaC.
This PAA server accepts connections from OpenPANA PaC clients.

Usage:
    python3 test_pypana_paa_openpana.py --bind 127.0.0.1 --port 5555
    
Then run OpenPANA PaC:
    openpac -i 127.0.0.1 -p 5555 -t eap-tls
"""

import socket
import struct
import logging
import sys
import time
import argparse
import random
import os
import hashlib
import hmac

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pana_constants import *
from pana_messages import PANAMessage, AVP
from pana_crypto import CryptoContext
from eap_tls import EAPTLSHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('PyPANA-PAA')

class PyPANAPAAForOpenPANA:
    """PAA server for testing with OpenPANA PaC"""
    
    def __init__(self, bind_addr='0.0.0.0', port=5555):
        self.bind_addr = bind_addr
        self.port = port
        self.socket = None
        self.sessions = {}
        self.running = False
        
        # Initialize EAP-TLS handler
        self.eap_handler = EAPTLSHandler(is_server=True)
        
        # Statistics
        self.stats = {
            'pci_received': 0,
            'par_sent': 0,
            'pan_received': 0,
            'sessions_created': 0
        }
        
    def create_session_id(self):
        """Generate a random session ID"""
        return random.randint(1, 0xFFFFFFFF)
    
    def create_par_with_eap_request(self, session_id, seq_num):
        """Create PAR with EAP-Request/Identity"""
        par = PANAMessage()
        par.msg_type = PANA_AUTH
        par.flags = FLAG_REQUEST
        par.session_id = session_id
        par.seq_number = seq_num
        
        # Create EAP-Request/Identity
        eap_data = struct.pack('!BBH', 1, 1, 4) + b'\x01'  # Code=Request, ID=1, Length=4, Type=Identity
        
        # Add EAP-Payload AVP
        eap_avp = AVP(AVP_EAP_PAYLOAD, 0, eap_data)  # Added flags=0
        par.add_avp(eap_avp)
        
        logger.info(f"Created PAR with EAP-Request/Identity (session={session_id:08x}, seq={seq_num})")
        return par
    
    def process_pci(self, data, addr):
        """Process PANA-Client-Initiation message"""
        try:
            pci = PANAMessage()
            pci.unpack(data)
            
            logger.info(f"Received PCI from {addr[0]}:{addr[1]}")
            self.stats['pci_received'] += 1
            
            # Create new session
            session_id = self.create_session_id()
            session = {
                'id': session_id,
                'client_addr': addr,
                'seq_num': 1,
                'state': 'WAIT_PAN',
                'eap_id': 1
            }
            self.sessions[session_id] = session
            self.stats['sessions_created'] += 1
            
            # Send PAR with EAP-Request/Identity
            par = self.create_par_with_eap_request(session_id, session['seq_num'])
            par_data = par.pack()
            
            self.socket.sendto(par_data, addr)
            self.stats['par_sent'] += 1
            logger.info(f"Sent PAR with EAP-Request/Identity to {addr[0]}:{addr[1]}")
            
            session['seq_num'] += 1
            
        except Exception as e:
            logger.error(f"Error processing PCI: {e}")
    
    def process_pan(self, data, addr):
        """Process PANA-Auth-Answer message"""
        try:
            pan = PANAMessage()
            pan.unpack(data)
            
            logger.info(f"Received PAN from {addr[0]}:{addr[1]} (session={pan.session_id:08x})")
            self.stats['pan_received'] += 1
            
            # Find session
            session = self.sessions.get(pan.session_id)
            if not session:
                logger.warning(f"No session found for ID {pan.session_id:08x}")
                return
            
            # Extract EAP payload
            eap_avp = pan.get_avp(AVP_EAP_PAYLOAD)
            if eap_avp:
                eap_data = eap_avp.data
                logger.info(f"Processing EAP data ({len(eap_data)} bytes)")
                
                # For now, send EAP-Success after receiving EAP-Response/Identity
                if session['state'] == 'WAIT_PAN':
                    # Send PAR with EAP-Success
                    par = PANAMessage()
                    par.msg_type = PANA_AUTH
                    par.flags = FLAG_REQUEST | FLAG_COMPLETE
                    par.session_id = session['id']
                    par.seq_number = session['seq_num']
                    
                    # Create EAP-Success
                    eap_success = struct.pack('!BBH', 3, session['eap_id']+1, 4)  # Code=Success
                    eap_avp = AVP(AVP_EAP_PAYLOAD, 0, eap_success)  # Added flags=0
                    par.add_avp(eap_avp)
                    
                    # Add Result-Code AVP (Success)
                    result_avp = AVP(AVP_RESULT_CODE, 0, struct.pack('!I', 0))  # PANA_SUCCESS = 0 (RFC 5191), added flags=0
                    par.add_avp(result_avp)
                    
                    par_data = par.pack()
                    self.socket.sendto(par_data, addr)
                    logger.info(f"Sent PAR with EAP-Success to {addr[0]}:{addr[1]}")
                    
                    session['state'] = 'AUTHENTICATED'
                    logger.info(f"Session {session['id']:08x} authenticated successfully")
            
        except Exception as e:
            logger.error(f"Error processing PAN: {e}")
    
    def process_message(self, data, addr):
        """Process incoming PANA message"""
        try:
            # Check minimum message size
            if len(data) < 12:
                logger.warning(f"Message too short from {addr[0]}:{addr[1]}")
                return
            
            # Parse message type from header
            msg = PANAMessage()
            msg.unpack(data)
            
            if msg.msg_type == PANA_CLIENT_INITIATION:
                self.process_pci(data, addr)
            elif msg.msg_type == PANA_AUTH and not (msg.flags & FLAG_REQUEST):
                self.process_pan(data, addr)
            else:
                logger.debug(f"Received message type {msg.msg_type} from {addr[0]}:{addr[1]}")
                
        except Exception as e:
            logger.error(f"Error processing message from {addr[0]}:{addr[1]}: {e}")
    
    def run(self):
        """Main server loop"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.bind_addr, self.port))
        self.socket.settimeout(1.0)
        
        logger.info(f"PyPANA PAA listening on {self.bind_addr}:{self.port}")
        logger.info("Waiting for OpenPANA PaC connections...")
        
        self.running = True
        try:
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(65535)
                    if data:
                        self.process_message(data, addr)
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    break
                    
        finally:
            self.stop()
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("PyPANA PAA stopped")
        logger.info(f"Statistics: {self.stats}")

def main():
    parser = argparse.ArgumentParser(description='PyPANA PAA for OpenPANA interoperability testing')
    parser.add_argument('--bind', default='127.0.0.1', help='Bind address')
    parser.add_argument('--port', type=int, default=5555, help='UDP port')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    server = PyPANAPAAForOpenPANA(args.bind, args.port)
    
    try:
        server.run()
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
    except Exception as e:
        logger.error(f"Server error: {e}")

if __name__ == '__main__':
    main()