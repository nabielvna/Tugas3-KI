import os
import time
import base64
from dataclasses import dataclass
from typing import Optional, Tuple, Dict
from crypto.my_rsa import RSAKey, encrypt, decrypt, load_key_from_pem, save_key_to_pem, bytes_to_int, int_to_bytes
from utils.log import create_nonce_logger

loggers = create_nonce_logger()

@dataclass
class NonceSession: # Nonce challenge session
    nonce: bytes
    timestamp: float
    public_key: str
    verified: bool = False

class ServerNonceManager:
    def __init__(self, public_key: RSAKey, private_key: RSAKey):
        self.logger = loggers['server']
        self.logger.info("Initializing nonce manager")
        self.public_key = public_key
        self.private_key = private_key
        self.active_sessions: Dict[str, NonceSession] = {}
        self.session_timeout = 30
    
    def create_challenge(self, client_id: str) -> dict:
        nonce = os.urandom(32)
        self.logger.info(f"Creating challenge for {client_id}")
        
        # Store session
        server_public_key_pem = save_key_to_pem(self.public_key)
        self.active_sessions[client_id] = NonceSession(
            nonce=nonce,
            timestamp=time.time(),
            public_key=server_public_key_pem
        )
        
        return {
            'type': 'nonce_challenge',
            'nonce': base64.b64encode(nonce).decode(),
            'server_public_key': server_public_key_pem
        }

    def verify_response(self, client_id: str, response: dict) -> dict:
        self.logger.info(f"Verifying response from {client_id}")
        
        if client_id not in self.active_sessions:
            self.logger.error(f"No active session for {client_id}")
            return {'type': 'nonce_verification', 'verified': False}
            
        session = self.active_sessions[client_id]
        
        try:
            # Check timeout
            if time.time() - session.timestamp > self.session_timeout:
                self.logger.error(f"Session timeout for {client_id}")
                del self.active_sessions[client_id]
                return {'type': 'nonce_verification', 'verified': False}
            
            # Decode and verify nonce
            encrypted_nonce = base64.b64decode(response['encrypted_nonce'])
            client_nonce = base64.b64decode(response['client_nonce'])
            client_public_key = load_key_from_pem(response['client_public_key'])
            
            nonce_int = bytes_to_int(encrypted_nonce)
            decrypted_nonce = int_to_bytes(decrypt(nonce_int, self.private_key))
            
            if decrypted_nonce != session.nonce:
                self.logger.error("Nonce verification failed")
                return {'type': 'nonce_verification', 'verified': False}
            
            # Encrypt client's nonce
            client_nonce_int = bytes_to_int(client_nonce)
            encrypted_client_nonce = int_to_bytes(encrypt(client_nonce_int, client_public_key))
            session.verified = True
            
            self.logger.info(f"Session verified for {client_id}")
            return {
                'type': 'nonce_verification',
                'verified': True,
                'encrypted_client_nonce': base64.b64encode(encrypted_client_nonce).decode()
            }
            
        except Exception as e:
            self.logger.error(f"Verification error: {str(e)}")
            return {'type': 'nonce_verification', 'verified': False}

class ClientNonceManager:
    def __init__(self, public_key: RSAKey, private_key: RSAKey):
        self.logger = loggers['client']
        self.logger.info("Initializing nonce manager")
        self.public_key = public_key
        self.private_key = private_key
        self.session: Optional[NonceSession] = None
        self.session_timeout = 30
    
    def handle_challenge(self, challenge_data: dict) -> Tuple[dict, bytes]:
        """Process a nonce challenge from server"""
        self.logger.info("Processing server challenge")
        try:
            server_nonce = base64.b64decode(challenge_data['nonce'])
            server_public_key = load_key_from_pem(challenge_data['server_public_key'])
            client_nonce = os.urandom(32)
            
            # Store session
            self.session = NonceSession(
                nonce=client_nonce,
                timestamp=time.time(),
                public_key=challenge_data['server_public_key']
            )
            
            # Encrypt server's nonce
            encrypted_nonce = int_to_bytes(
                encrypt(bytes_to_int(server_nonce), server_public_key)
            )
            
            return {
                'type': 'nonce_response',
                'encrypted_nonce': base64.b64encode(encrypted_nonce).decode(),
                'client_nonce': base64.b64encode(client_nonce).decode(),
                'client_public_key': save_key_to_pem(self.public_key)
            }, client_nonce
            
        except Exception as e:
            self.logger.error(f"Challenge error: {str(e)}")
            raise
            
    def verify_server_response(self, verification: dict, original_nonce: bytes) -> bool:
        self.logger.info("Verifying server response")
        try:
            if not self.session:
                self.logger.error("No active session")
                return False
                
            if time.time() - self.session.timestamp > self.session_timeout:
                self.logger.error("Session timeout")
                return False
                
            if not verification['verified']:
                self.logger.error("Server reported verification failure")
                return False
                
            # Decrypt and verify nonce
            encrypted_nonce = base64.b64decode(verification['encrypted_client_nonce'])
            decrypted_nonce = int_to_bytes(
                decrypt(bytes_to_int(encrypted_nonce), self.private_key)
            )
            
            if decrypted_nonce != original_nonce:
                self.logger.error("Nonce verification failed")
                return False
                
            self.session.verified = True
            self.logger.info("Server verification successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Verification error: {str(e)}")
            return False