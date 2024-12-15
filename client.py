import socket
import threading
import json
from core.e2e import SecureClient
from core.server_signature_manager import ClientKeyVerifier
from core.nonce_manager import ClientNonceManager
from utils.log import SystemLogger

class ChatClient:
    def __init__(self, username, host='127.0.0.1', port=5000):
        self.logger = SystemLogger('client')
        self.logger.info(f"Initializing chat client for {username}")
        self.socket = socket.socket()
        self.username = username
        self.secure_client = SecureClient(username)
        self.active_users = {}
        self.key_verifier = None
        self.nonce_manager = None
        self.running = True
        
        try:
            self.logger.info(f"Connecting to server {host}:{port}")
            self.socket.connect((host, port))
            self.logger.info("Connected to server successfully")
            
            # Handle nonce challenge from server
            self.logger.info("Awaiting nonce challenge...")
            challenge_data = self.receive_message()
            if not challenge_data or challenge_data['type'] != 'nonce_challenge':
                raise ValueError("Expected nonce challenge")
            
            # Initialize nonce manager with our keys
            self.nonce_manager = ClientNonceManager(
                self.secure_client.e2e.public_key,
                self.secure_client.e2e.private_key
            )
            
            # Process challenge and send response
            response, original_nonce = self.nonce_manager.handle_challenge(challenge_data)
            self.send_message(response)
            self.logger.info("Sent nonce response to server")
            
            # Wait for verification
            verification = self.receive_message()
            if not verification or not verification['verified']:
                raise ValueError("Server nonce verification failed")
            
            # Verify server's response
            if not self.nonce_manager.verify_server_response(verification, original_nonce):
                raise ValueError("Failed to verify server's nonce response")
            
            self.logger.info("Mutual authentication completed successfully")
            
            # Now proceed with registration
            registration = {
                'type': 'register',
                'username': username,
                'public_key': self.secure_client.e2e.get_public_key_pem()
            }
            self.send_message(registration)
            self.logger.info("Sent registration to server")
            
            # Initialize key verifier with server's public key from nonce challenge
            self.key_verifier = ClientKeyVerifier(challenge_data['server_public_key'])
            
        except Exception as e:
            self.logger.error("Error during initialization", e)
            raise

    def send_message(self, message):
        """Send message with length header"""
        try:
            message_data = json.dumps(message).encode()
            length_header = len(message_data).to_bytes(8, byteorder='big')
            
            # Send length followed by data
            self.socket.send(length_header)
            self.socket.send(message_data)
            return True
        except Exception as e:
            self.logger.error("Error sending message", e)
            return False

    def receive_message(self):
        """Receive complete message from server"""
        try:
            # Read message length first (8 bytes)
            length_header = self.socket.recv(8)
            if not length_header:
                return None
                
            message_length = int.from_bytes(length_header, byteorder='big')
            
            # Read the full message
            chunks = []
            bytes_received = 0
            while bytes_received < message_length:
                chunk_size = min(4096, message_length - bytes_received)
                chunk = self.socket.recv(chunk_size)
                if not chunk:
                    return None
                chunks.append(chunk)
                bytes_received += len(chunk)
            
            data = b''.join(chunks).decode()
            return json.loads(data)
        except Exception as e:
            self.logger.error("Error receiving message", e)
            return None
    
    def start(self):
        self.logger.info("Starting client")
        try:
            # Start receive thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            self.logger.info("\nReady to send messages")
            self.logger.info("Format: recipient:message")
            self.logger.info("Type 'quit' to exit")
            
            self.send_loop()
            
        except Exception as e:
            self.logger.error("Error starting client", e)
        finally:
            self.running = False
            self.socket.close()
    
    def receive_messages(self):
        while self.running:
            try:
                message_data = self.receive_message()
                if not message_data:
                    self.logger.error("Lost connection to server")
                    break
                
                if message_data['type'] == 'user_list':
                    self.handle_user_list(message_data)
                
                elif message_data['type'] == 'message':
                    self.handle_incoming_message(message_data)
                
                print("\nEnter message (recipient:message):", end=' ', flush=True)
                
            except Exception as e:
                self.logger.error("Error receiving", e)
                if not self.running or "connection" in str(e).lower():
                    break
        
        self.logger.info("Receive loop ended")
        self.running = False
    
    def handle_user_list(self, message_data):
        old_users = set(self.active_users.keys())
        
        # Verify each user's key package before accepting
        verified_users = {}
        for username, key_package in message_data['users'].items():
            if username != self.username:
                if self.key_verifier.verify_key_package(key_package):
                    verified_users[username] = key_package['public_key']
                    # Exchange keys for E2E encryption
                    self.secure_client.handle_key_exchange(
                        username,
                        key_package['public_key']
                    )
                else:
                    self.logger.error(f"Invalid key package for {username}")
        
        self.active_users = verified_users
        new_users = set(self.active_users.keys())
        
        # Show user changes
        joined = new_users - old_users
        left = old_users - new_users
        
        if joined:
            self.logger.info(f"Users joined: {', '.join(joined)}")
        if left:
            self.logger.info(f"Users left: {', '.join(left)}")
        
        self.logger.data("Active users:", list(self.active_users.keys()))
    
    def handle_incoming_message(self, message_data):
        sender = message_data['sender']
        self.logger.info(f"Received message from {sender}")
        
        decrypted_content = self.secure_client.receive_message(
            message_data['encrypted_package']
        )
        
        if decrypted_content:
            print(f"\n[Message from {sender}]: {decrypted_content}")
        else:
            self.logger.error(f"Failed to decrypt message from {sender}")
    
    def send_loop(self):
        while self.running:
            try:
                user_input = input("\nEnter message (recipient:message): ")
                
                if user_input.lower() == 'quit':
                    self.logger.info("Quitting...")
                    break
                
                if ':' not in user_input:
                    self.logger.error("Invalid format. Use 'recipient:message'")
                    continue
                
                recipient, content = user_input.split(':', 1)
                recipient = recipient.strip()
                content = content.strip()
                
                if not content:
                    self.logger.error("Message content cannot be empty")
                    continue
                
                if recipient not in self.active_users:
                    self.logger.error(f"User {recipient} is not active")
                    self.logger.data("Active users:", list(self.active_users.keys()))
                    continue
                
                self.send_encrypted_message(recipient, content)
                
            except Exception as e:
                self.logger.error("Error in send loop", e)
                if not self.running:
                    break
    
    def send_encrypted_message(self, recipient, content):
        try:
            self.logger.info(f"Preparing message for {recipient}")
            encrypted_package = self.secure_client.send_message(recipient, content)
            
            if encrypted_package:
                message = {
                    'type': 'message',
                    'recipient': recipient,
                    'encrypted_package': encrypted_package
                }
                if self.send_message(message):
                    self.logger.info(f"Message sent to {recipient}")
                else:
                    self.logger.error(f"Failed to send message to {recipient}")
            else:
                self.logger.error(f"Failed to encrypt message for {recipient}")
            
        except Exception as e:
            self.logger.error("Error sending message", e)

def main():
    logger = SystemLogger('client')
    logger.info("=== Chat Client ===")
    username = input("Enter your username: ").strip()
    
    if not username:
        logger.error("Username cannot be empty")
        return
    
    try:
        client = ChatClient(username)
        client.start()
    except Exception as e:
        logger.error("Fatal error", e)

if __name__ == '__main__':
    main()