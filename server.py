import socket
import threading
import time
import json
import queue
from encryption_utils import *
from collections import defaultdict
from network_graph import NetworkGraph
BUFFER_SIZE = 4096

class Server:
    def __init__(self, port, name, host_name, log_callback=None):
        self.port = port
        self.name = name
        self.host_name = host_name
        self.log_callback = log_callback
        self.server_socket = None
        self.clients = {}  # client_socket -> (session_key, client_name)
        self.messages = []  # List of messages sent on the server
        self.message_queue = queue.Queue()
        self.server_running = threading.Event()
        self.participant_tree = defaultdict(list)  # Tree for participant hierarchy
        self.network_graph = NetworkGraph()  # Graph for network connections

        # Initialize the tree with the host as the root
        self.participant_tree[self.host_name] = []

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("0.0.0.0", self.port))
        self.server_socket.listen(5)
        self.server_running.set()

        if self.log_callback:
            self.log_callback(f"Server '{self.name}' started on port {self.port}.")

        threading.Thread(target=self.accept_clients).start()

    def accept_clients(self):
        while self.server_running.is_set():
            try:
                client_socket, client_address = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
            except OSError as e:
                if self.log_callback:
                    self.log_callback("")
                break


    def handle_client(self, client_socket):
        try:
            # Receive client's public key
            client_pub_key_pem = client_socket.recv(BUFFER_SIZE)
            client_pub_key = deserialize_public_key(client_pub_key_pem)

            # Generate and send session key
            session_key = generate_session_key()
            encrypted_session_key = encrypt_with_rsa(client_pub_key, session_key)
            client_socket.send(encrypted_session_key)

            # Send the server's name
            encrypted_server_name = encrypt_with_aes(session_key, self.name)
            client_socket.send(encrypted_server_name.encode('utf-8'))

            # Receive and decrypt the client's name
            encrypted_name = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            client_name = decrypt_with_aes(session_key, encrypted_name)

            # Store client information
            self.clients[client_socket] = (session_key, client_name)
            self.participant_tree[self.host_name].append(client_name)

            # Add client to the graph
            latency = self.calculate_latency(client_socket)
            self.network_graph.add_connection(self.host_name, client_name, latency)

            if self.log_callback:
                self.log_callback(f"Client '{client_name}' connected.")

            # Broadcast updated participant list
            self.update_participants()

            if self.log_callback:
                self.log_callback(f"{client_name} connected.")
            self.broadcast(f"{client_name} connected.")

            while self.server_running.is_set():
                encrypted_message = client_socket.recv(BUFFER_SIZE).decode('utf-8')
                message = decrypt_with_aes(session_key, encrypted_message)
                full_message = f"{client_name}: {message}"
                self.broadcast(full_message, sender_socket=client_socket)

        except Exception as e:
            if self.log_callback:
                self.log_callback("")
        finally:
            if client_socket in self.clients:
                client_name = self.clients[client_socket][1]
                self.broadcast(f"{client_name} disconnected.")
            self.disconnect_client(client_socket)
            self.update_participants()

    def disconnect_client(self, client_socket):
        if client_socket in self.clients:
            client_name = self.clients[client_socket][1]
            del self.clients[client_socket]

            try:
                if client_socket.fileno() != -1:
                    client_socket.shutdown(socket.SHUT_RDWR)
                    client_socket.close()
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"Error while disconnecting client '{client_name}': {e}")


    def broadcast(self, message, sender_socket=None):
        if sender_socket is None:
            message = f"{self.host_name} (Host): {message}"
        self.message_queue.put(message)
        for client, (session_key, _) in self.clients.items():
            encrypted_message = encrypt_with_aes(session_key, message)
            try:
                client.send(encrypted_message.encode('utf-8'))
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"Error sending message: {e}")
        self.message_queue.get(timeout=1)
        self.messages.append(message)

    def update_participants(self):
        # Build the participant tree
        self.participant_tree.clear()
        self.participant_tree[self.host_name] = []  # Reset root
        for _, name in self.clients.values():
            self.participant_tree[self.host_name].append(name)

        serialized_tree = json.dumps(self.participant_tree)

        # Broadcast the serialized tree to all clients
        for client_socket, (session_key, _) in self.clients.items():
            try:
                encrypted_tree = encrypt_with_aes(session_key, serialized_tree)
                client_socket.send(encrypted_tree.encode('utf-8'))
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"Error sending participant tree: {e}")

    def get_metadata(self):
        """Retrieves metadata about the server."""
        return {
            "name": self.name,
            "participants": [self.host_name] + [name for _, name in self.clients.values()],
            "messages": self.messages,
            "participant_tree": self.participant_tree,
            "network_graph": self.network_graph.get_connections()
        }

    def calculate_latency(self, client_socket):
        try:
            start_time = time.time()
            client_socket.send(b'ping')

            response = client_socket.recv(1024).strip()
            if response == b'ping':
                end_time = time.time()
                return int((end_time - start_time) * 1000)  # Return latency in milliseconds
            else:
                return None  # Invalid response
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Latency check failed: {e}")
            return None

    
    def get_ip_port(self):
        return f"localhost:{self.port}"

    def shutdown(self):
        self.server_running.clear()

        for client_socket in list(self.clients.keys()):
            self.disconnect_client(client_socket)

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                if self.log_callback:
                    self.log_callback("")

        if self.log_callback:
            self.log_callback(f"Server '{self.name}' shut down.")
