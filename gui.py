import tkinter as tk
from tkinter import simpledialog, messagebox
from server import Server
from client import Client

class SecureMessengerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Messenger")

        # Dictionary to manage multiple servers
        self.servers = {}
        self.current_server = None

        # Server list pane
        self.server_frame = tk.Frame(self.root, width=200, bg="lightgray")
        self.server_frame.pack(side="left", fill="y")

        self.server_listbox = tk.Listbox(self.server_frame, width=30)
        self.server_listbox.pack(fill="both", expand=True)

        self.switch_server_button = tk.Button(self.server_frame, text="Switch Server", command=self.switch_server)
        self.switch_server_button.pack(pady=5)

        self.leave_server_button = tk.Button(self.server_frame, text="Leave Server", command=self.leave_server)
        self.leave_server_button.pack(pady=5)

        # Participants list
        self.participants_frame = tk.Frame(self.root, bg="lightgray")
        self.participants_frame.pack(side="right", fill="y")

        self.participants_label = tk.Label(self.participants_frame, text="Participants")
        self.participants_label.pack(pady=5)

        self.participants_listbox = tk.Listbox(self.participants_frame, width=20)
        self.participants_listbox.pack(fill="both", expand=True)

        # Network graph display
        self.network_frame = tk.Frame(self.root, bg="lightgray")
        self.network_frame.pack(side="right", fill="y")

        self.network_label = tk.Label(self.network_frame, text="Network Connections")
        self.network_label.pack(pady=5)

        self.network_text = tk.Text(self.network_frame, state="disabled", height=10, width=30, bg="white")
        self.network_text.pack(fill="both", expand=True)

        # Chat display
        self.chat_display = tk.Text(root, state="disabled", height=20, width=50, bg="lightgray")
        self.chat_display.pack(pady=10)

        # Message input
        self.message_var = tk.StringVar()
        self.input_frame = tk.Frame(root)
        self.input_frame.pack(pady=5)
        self.message_entry = tk.Entry(self.input_frame, textvariable=self.message_var, width=40)
        self.message_entry.pack(side="left", padx=5)
        self.send_button = tk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side="left")

        # Connection buttons
        self.connection_frame = tk.Frame(root)
        self.connection_frame.pack(pady=10)
        self.host_button = tk.Button(self.connection_frame, text="Host Server", command=self.host_server)
        self.host_button.pack(side="left", padx=10)
        self.connect_button = tk.Button(self.connection_frame, text="Connect to Server", command=self.connect_to_server)
        self.connect_button.pack(side="left", padx=10)

        self.update_gui()

    # updates gui from the server
    def update_gui(self):
        if self.current_server:
            metadata = self.current_server.get_metadata()
            self.update_chat_display(metadata["messages"])
            self.update_network_graph(metadata.get("network_graph", []))
            self.update_participants(metadata.get("participant_tree", {}))
        self.root.after(1000, self.update_gui)

    def update_chat_display(self, messages):
        self.chat_display.config(state="normal")
        self.chat_display.delete("1.0", tk.END)
        for message in messages:
            self.chat_display.insert("end", message + "\n")
        self.chat_display.config(state="disabled")
        self.chat_display.see("end")

    # Lists the participant tree
    def update_participants(self, participant_tree):
        self.participants_listbox.delete(0, tk.END)
        for parent, children in participant_tree.items():
            if parent is not None and parent != "null":
                self.participants_listbox.insert(tk.END, f"{parent}")
                for child in children:
                    self.participants_listbox.insert(tk.END, f"  {child}")

    # shows network graph
    def update_network_graph(self, connections):
        self.network_text.config(state="normal")
        self.network_text.delete("1.0", tk.END)
        for node1, node2, weight in connections:
            self.network_text.insert("end", f"{node1} --({weight}ms)-- {node2}\n")
        self.network_text.config(state="disabled")

    # Sends message to the current server
    def send_message(self):
        message = self.message_var.get()
        if message and isinstance(self.current_server, Server):
            self.current_server.broadcast(message)
            self.message_var.set("")
        elif message and isinstance(self.current_server, Client):
            self.current_server.send_message(message)
            self.message_var.set("")
        else:
            messagebox.showerror("Error", "No active server or message.")

    # Host a new server
    def host_server(self):
        port = simpledialog.askinteger("Host Server", "Enter the port to host on:", parent=self.root)
        server_name = simpledialog.askstring("Host Server", "Enter the server name:", parent=self.root)
        host_name = simpledialog.askstring("Host Server", "Enter your name: ", parent=self.root)
        if port and server_name and host_name:
            from server import Server
            new_server = Server(port, server_name, host_name, log_callback=self.display_message)
            new_server.start()
            self.servers[f"localhost:{port}"] = new_server
            self.current_server = new_server
            self.update_server_list()
        else:
            messagebox.showerror("Error", "Port, server name, and host name are required.")

    # Connect to an existing server
    def connect_to_server(self):
        ip = simpledialog.askstring("Connect to Server", "Enter the server's IP address:", parent=self.root)
        port = simpledialog.askinteger("Connect to Server", "Enter the server's port:", parent=self.root)
        name = simpledialog.askstring("Connect to Server", "Enter your name:", parent=self.root)
        if ip and port and name:
            from client import Client
            new_client = Client(ip, port, name, log_callback=self.display_message)
            new_client.connect()
            self.servers[f"{ip}:{port}"] = new_client
            self.current_server = new_client
            self.update_server_list()
        else:
            messagebox.showerror("Error", "IP, port, and name are required.")

    # Switches to whichever server you select
    def switch_server(self):
        selected = self.server_listbox.get(tk.ACTIVE)
        if selected and selected in self.servers:
            self.current_server = self.servers[selected]
            self.display_message(f"Switched to {selected}")
        else:
            messagebox.showerror("Error", "Invalid server selection.")

    # Updates the list of servers in the gui
    def update_server_list(self):
        self.server_listbox.delete(0, tk.END)
        self.update_participants
        for server_key in self.servers.keys():
            self.server_listbox.insert(tk.END, server_key)

    # Shows messages in the chat
    def display_message(self, message):
        self.chat_display.config(state="normal")
        self.chat_display.insert("end", message + "\n")
        self.chat_display.config(state="disabled")
        self.chat_display.see("end")

    # Disconnects from the current server, removes it from the list of servers, and switches the current server to the next instance 
    def leave_server(self):
        if self.current_server:
            # Store the current server key
            server_key = self.current_server.get_ip_port()

            try:
                server = self.servers[server_key]
                if isinstance(server, Server):
                    server.shutdown()
                elif isinstance(server, Client):
                    server.disconnect()
            except Exception as e:
                self.display_message("")

            # Remove the server from the list
            del self.servers[server_key]

            # Set the next available server or None
            self.current_server = self.servers[next(iter(self.servers), None)] if self.servers else None

            # Update the GUI
            self.update_server_list()
            if self.current_server:
                self.display_message(f"Switched to the next server: {self.current_server}")
            else:
                self.display_message("Left the server. No servers available.")
        else:
            self.display_message("No server selected to leave.")
