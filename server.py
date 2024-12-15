import socket
import threading
import json
from core.server_signature_manager import ServerKeyManager
from core.nonce_manager import ServerNonceManager
from utils.log import SystemLogger

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5000):
        self.logger = SystemLogger('server')
        self.logger.info("Initializing E2E secure chat server")
        self.host = host
        self.port = port
        self.server_socket = socket.socket()
        self.clients = {}  # {username: (connection, key_package)}
        self.key_manager = ServerKeyManager()
        self.nonce_manager = ServerNonceManager(
            self.key_manager.public_key,
            self.key_manager.private_key
        )
        self.logger.info(f"Server initialized on {host}:{port}")
    
    def start(self):
        try:
            self.logger.info("Starting server...")
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.logger.info(f"Server is listening on {self.host}:{self.port}")
            
            while True:
                self.logger.info("Waiting for new connections...")
                client_socket, address = self.server_socket.accept()
                self.logger.info(f"New connection from {address}")
                
                # Client handler thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                self.logger.info(f"Started handler thread for {address}")
                
        except Exception as e:
            self.logger.error("Server error", e)
        finally:
            self.server_socket.close()
            self.logger.info("Server shutdown")
    
    def check_existing_connection(self, username):
        if username in self.clients:
            old_socket, _ = self.clients[username]
            try:
                # Check connection
                old_socket.send(b'')
                return True  # Connection is still active
            except:
                # Connection is dead
                self.logger.info(f"Removing inactive client: {username}")
                del self.clients[username]
                return False
        return False

    def receive_full_message(self, client_socket):
        # Read message length first (8 bytes)
        length_header = client_socket.recv(8)
        if not length_header:
            return None
            
        message_length = int.from_bytes(length_header, byteorder='big')
        
        # Read the full message
        chunks = []
        bytes_received = 0
        while bytes_received < message_length:
            chunk_size = min(4096, message_length - bytes_received)
            chunk = client_socket.recv(chunk_size)
            if not chunk:
                return None
            chunks.append(chunk)
            bytes_received += len(chunk)
        
        return b''.join(chunks).decode()

    def send_message(self, client_socket, message):
        """Send message with length header"""
        try:
            message_data = json.dumps(message).encode()
            length_header = len(message_data).to_bytes(8, byteorder='big')
            
            # Send length followed by data
            client_socket.send(length_header)
            client_socket.send(message_data)
            return True
        except Exception as e:
            self.logger.error("Error sending message", e)
            return False

    def handle_client(self, client_socket, address):
        """Handle an individual client connection"""
        username = None
        try:
            # Send nonce challenge
            temp_client_id = f"temp_{address[0]}_{address[1]}"
            challenge = self.nonce_manager.create_challenge(temp_client_id)
            self.send_message(client_socket, challenge)
            self.logger.info(f"Sent nonce challenge to {address}")
            
            # Wait for nonce response and registration
            response_data = self.receive_full_message(client_socket)
            if not response_data:
                return
            
            response = json.loads(response_data)
            if response['type'] != 'nonce_response':
                raise ValueError("Expected nonce response")
            
            # Verify nonce response
            verification = self.nonce_manager.verify_response(temp_client_id, response)
            if not verification['verified']:
                self.logger.error(f"Nonce verification failed for {address}")
                client_socket.close()
                return
                
            # Send verification result
            self.send_message(client_socket, verification)
            self.logger.info(f"Nonce verified for {address}")
            
            # Now wait for registration
            reg_data = self.receive_full_message(client_socket)
            if not reg_data:
                return
                
            registration = json.loads(reg_data)
            if registration['type'] != 'register':
                raise ValueError("Expected registration message")
            
            username = registration['username']
            client_public_key = registration['public_key']
            
            # Check if username exists and connection is active
            if self.check_existing_connection(username):
                self.logger.error(f"Username {username} is already active")
                client_socket.close()
                return
            
            # Create signed key package for new client
            key_package = self.key_manager.create_signed_key_package(
                username,
                client_public_key
            )
            
            # Store client info
            self.clients[username] = (client_socket, key_package)
            self.logger.info(f"Registered new client: {username}")
            self.logger.data("Active clients:", list(self.clients.keys()))
            
            # Broadcast updated user list 
            self.broadcast_user_list()
            
            while True:
                try:
                    message_data = self.receive_full_message(client_socket)
                    if not message_data:
                        self.logger.info(f"Client {username} disconnected")
                        break
                    
                    message = json.loads(message_data)
                    
                    if message['type'] == 'message':
                        recipient = message['recipient']
                        if recipient in self.clients:
                            self.logger.info(f"Forwarding message: {username} -> {recipient}")
                            
                            # Get recipient's socket
                            recipient_socket = self.clients[recipient][0]
                            
                            try:
                                # Forward encrypted message
                                forward_message = {
                                    'type': 'message',
                                    'sender': username,
                                    'encrypted_package': message['encrypted_package']
                                }
                                
                                if not self.send_message(recipient_socket, forward_message):
                                    raise Exception("Failed to send message")
                                    
                                self.logger.info(f"Message forwarded to {recipient}")
                            except:
                                self.logger.error(f"Failed to send message to {recipient}, they might be offline")
                                if recipient in self.clients:
                                    del self.clients[recipient]
                                    self.broadcast_user_list()
                        else:
                            self.logger.error(f"Recipient {recipient} not found")
                    
                except json.JSONDecodeError:
                    self.logger.error(f"Invalid JSON from {username}")
                    continue
                except Exception as e:
                    self.logger.error(f"Error handling message from {username}", e)
                    if "connection" in str(e).lower():
                        break
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error with client {address}", e)
        
        finally:
            # Clean up client connection
            if username and username in self.clients:
                current_socket, _ = self.clients[username]
                if current_socket == client_socket:
                    del self.clients[username]
                    self.logger.info(f"Removed {username} from active clients")
                    self.broadcast_user_list()
            
            client_socket.close()
            self.logger.info(f"Closed connection with {username if username else address}")
            self.logger.data("Active clients:", list(self.clients.keys()))
    
    def broadcast_user_list(self):
        self.logger.info("Broadcasting updated user list")
        
        # Prepare user list with signed key packages
        user_list = {
            'type': 'user_list',
            'users': {username: key_package 
                     for username, (_, key_package) in self.clients.items()}
        }
        
        # Copy clients dict to avoid modification during iteration
        clients_copy = dict(self.clients)
        
        # Send to all connected clients
        for username, (client_socket, _) in clients_copy.items():
            try:
                if not self.send_message(client_socket, user_list):
                    raise Exception("Failed to send user list")
            except Exception as e:
                self.logger.error(f"Error broadcasting to {username}", e)
                continue

def main():
    logger = SystemLogger('server')
    logger.info("=== Chat Server ===")
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error("Fatal error", e)

if __name__ == '__main__':
    main()