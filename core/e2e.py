import base64
import json
from crypto.my_des import generate_random_key, encrypt as des_encrypt, decrypt as des_decrypt
from crypto.my_rsa import (
    generate_keypair, encrypt, decrypt, sign, verify_signature,
    save_key_to_pem, load_key_from_pem, bytes_to_int, int_to_bytes
)
from utils.log import create_e2e_logger

logger = create_e2e_logger()

def get_truncated_key(key_str, length=32):
    if len(key_str) <= length:
        return key_str
    return key_str[:length] + "..."

class E2EMessaging:
    def __init__(self):
        logger.info("Initializing new E2E messaging instance")
        self.public_key, self.private_key = generate_keypair(2048)
        logger.info("Key generation complete")
        self.peer_public_keys = {}
    
    def add_peer_key(self, username, public_key_pem):
        logger.info(f"Adding public key for peer: {username}")
        self.peer_public_keys[username] = load_key_from_pem(public_key_pem)
        logger.info(f"Public key added for {username}")
    
    def prepare_message(self, recipient, content):
        logger.info(f"Preparing encrypted message for {recipient}")
        if recipient not in self.peer_public_keys:
            logger.error(f"No public key found for {recipient}")
            raise ValueError(f"No public key found for {recipient}")
        
        # Generate and encrypt DES key
        des_key = generate_random_key()
        encrypted_content = des_encrypt(content, des_key)
        
        # Sign and encrypt DES key
        des_key_int = bytes_to_int(des_key.encode())
        signature = sign(des_key_int, self.private_key)
        signed_des_key_b64 = base64.b64encode(int_to_bytes(signature)).decode()
        
        encrypted_des_key_int = encrypt(des_key_int, self.peer_public_keys[recipient])
        encrypted_des_key_b64 = base64.b64encode(int_to_bytes(encrypted_des_key_int)).decode()
        
        # Create message package
        message_package = {
            'encrypted_content': encrypted_content,
            'encrypted_key': encrypted_des_key_b64,
            'signed_key': signed_des_key_b64,
            'sender_public_key': save_key_to_pem(self.public_key)
        }
        
        # Log truncated package info
        logger.info("Message package details:")
        logger.info(f"- Content length: {len(encrypted_content)} bytes")
        logger.info(f"- Encrypted key: {get_truncated_key(encrypted_des_key_b64)}")
        logger.info(f"- Signature: {get_truncated_key(signed_des_key_b64)}")
        
        return json.dumps(message_package)
    
    def decrypt_message(self, encrypted_package):
        logger.info("Decrypting message")
        try:
            package = json.loads(encrypted_package)
            
            # Decrypt DES key
            encrypted_key_bytes = base64.b64decode(package['encrypted_key'].encode())
            des_key = int_to_bytes(
                decrypt(bytes_to_int(encrypted_key_bytes), self.private_key)
            ).decode()
            logger.info(f"Decrypted key: {des_key}")
            
            # Verify signature
            signature = base64.b64decode(package['signed_key'].encode())
            sender_key = load_key_from_pem(package['sender_public_key'])
            
            if not verify_signature(
                bytes_to_int(des_key.encode()),
                bytes_to_int(signature),
                sender_key
            ):
                logger.error("Invalid message signature")
                raise Exception("Message authentication failed")
            
            # Decrypt content
            content = des_decrypt(package['encrypted_content'], des_key)
            logger.info("Message decrypted successfully")
            
            return content
            
        except Exception as e:
            logger.error("Decryption error", e)
            raise Exception(f"Failed to decrypt message: {str(e)}")
    
    def get_public_key_pem(self):
        return save_key_to_pem(self.public_key)

class SecureClient:
    def __init__(self, username):
        logger.info(f"Initializing secure client: {username}")
        self.username = username
        self.e2e = E2EMessaging()
        self.peer_keys = {}
    
    def handle_key_exchange(self, peer_username, peer_public_key_pem):
        logger.info(f"Exchanging keys with {peer_username}")
        self.e2e.add_peer_key(peer_username, peer_public_key_pem)
    
    def send_message(self, recipient, content):
        logger.info(f"Sending message to {recipient}")
        try:
            return self.e2e.prepare_message(recipient, content)
        except Exception as e:
            logger.error("Send error", e)
            return None
    
    def receive_message(self, encrypted_package):
        logger.info("Processing received message")
        try:
            return self.e2e.decrypt_message(encrypted_package)
        except Exception as e:
            logger.error("Receive error", e)
            return None