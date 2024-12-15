import base64
import hashlib
from crypto.my_rsa import (
    generate_keypair, sign, verify_signature,
    save_key_to_pem, load_key_from_pem, bytes_to_int, int_to_bytes
)
from utils.log import create_key_logger

loggers = create_key_logger()

class ServerKeyManager:
    def __init__(self):
        self.logger = loggers['server']
        self.logger.info("Initializing server key manager")
        self.public_key, self.private_key = generate_keypair(2048)
        self.logger.info("Key generation complete")
    
    def get_public_key_pem(self):
        return save_key_to_pem(self.public_key)
    
    def sign_client_key(self, client_key_pem):
        self.logger.info("Signing client key")
        
        # Hash and sign the key
        key_hash = hashlib.sha256(client_key_pem.encode()).digest()
        signature = sign(bytes_to_int(key_hash), self.private_key)
        
        return base64.b64encode(int_to_bytes(signature)).decode()
    
    def create_signed_key_package(self, username, client_key_pem):
        self.logger.info(f"Creating key package for {username}")
        signature = self.sign_client_key(client_key_pem)
        
        package = {
            'username': username,
            'public_key': client_key_pem,
            'signature': signature
        }
        
        # Log package contents in a clean format
        self.logger.info(f"Package created for user: {username}")
        self.logger.info(f"Signature length: {len(signature)} chars")
        return package

class ClientKeyVerifier:
    def __init__(self, server_public_key_pem):
        self.logger = loggers['client']
        self.logger.info("Initializing key verifier")
        self.server_public_key = load_key_from_pem(server_public_key_pem)
    
    def verify_key_package(self, key_package):
        username = key_package['username']
        self.logger.info(f"Verifying package for {username}")
        
        try:
            # Hash and verify signature
            key_hash = hashlib.sha256(key_package['public_key'].encode()).digest()
            signature = base64.b64decode(key_package['signature'].encode())
            
            # Verify signature
            result = verify_signature(
                bytes_to_int(key_hash), 
                bytes_to_int(signature), 
                self.server_public_key
            )
            
            if result:
                self.logger.info(f"Package verified for {username}")
            else:
                self.logger.error(f"Invalid signature for {username}")
            return result
            
        except Exception as e:
            self.logger.error(f"Verification failed for {username}", e)
            return False