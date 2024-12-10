import socket
import threading
import json
from encryption_utils import *
from collections import defaultdict
BUFFER_SIZE = 4096

class Client:
    def __init__(self, server_ip, port, client_name, log_callback=None):
        self.server_ip = server_ip
        self.port = port
        self.client_name = client_name
        self.session_key = None
        self.client_socket = None
        self.messages = []
        self.server_name = None
        self.participant_tree = defaultdict(list)  # Tree for participant hierarchy
        self.log_callback = log_callback
        self.client_running = threading.Event()

    def connect(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.server_ip, self.port))
        self.client_running.set()

        # Generate and send public key
        private_key, public_key = generate_rsa_keypair()
        self.client_socket.send(serialize_public_key(public_key))

        # Receive and decrypt session key
        encrypted_session_key = self.client_socket.recv(BUFFER_SIZE)
        self.session_key = decrypt_with_rsa(private_key, encrypted_session_key)

        # Receive and store the server's name
        encrypted_server_name = self.client_socket.recv(BUFFER_SIZE).decode('utf-8')
        self.server_name = decrypt_with_aes(self.session_key, encrypted_server_name)

        # Encrypt and send the client's name
        encrypted_name = encrypt_with_aes(self.session_key, self.client_name)
        self.client_socket.send(encrypted_name.encode('utf-8'))

        # Start receiving messages
        threading.Thread(target=self.receive_messages).start()

    def receive_messages(self):
        while self.client_running.is_set():
            try:
                data = self.client_socket.recv(1024) 
                if not data:
                    break

                # Respond to ping for latency check
                if data.strip() == b'ping':
                    self.client_socket.send(b'ping')
                    continue

                # Handle other messages
                decrypted_message = decrypt_with_aes(self.session_key, data.decode('utf-8'))

                if decrypted_message.startswith("{") and decrypted_message.endswith("}"):  # Basic JSON detection
                    try:
                        participant_tree = json.loads(decrypted_message)
                        self.participant_tree = participant_tree  # Update local tree
                        if self.log_callback:
                            self.log_callback("Updated participant tree.")
                    except json.JSONDecodeError:
                        if self.log_callback:
                            self.log_callback("Error decoding participant tree.")
                else:
                    self.messages.append(decrypted_message)
                    if self.log_callback:
                        self.log_callback(decrypted_message)
            except Exception as e:
                if self.log_callback:
                    self.log_callback("")
                break


    def get_metadata(self):
        return {
            "server_ip": self.server_ip,
            "messages": self.messages,
            "server_name": self.server_name,
            "participant_tree": self.participant_tree,
        }

    def send_message(self, message):
        try:
            encrypted_message = encrypt_with_aes(self.session_key, message)
            self.client_socket.send(encrypted_message.encode('utf-8'))
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error sending message: {e}")

    def disconnect(self):
        self.client_running.clear()
        if self.client_socket:
            self.client_socket.shutdown(socket.SHUT_RDWR)
            self.client_socket.close()
            self.client_socket = None
        if self.log_callback:
            self.log_callback("Disconnected from server.")

    def get_ip_port(self):
        return f"{self.server_ip}:{self.port}"


