import sys
import socket
import threading
import json
import base64
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import random
import string

host = '127.0.0.1'

class ClientSession:
    def __init__(self, connection):
        self.connection = connection
        self.username = None
        self.public_key_data = None
        self.counter = 0
        self.server_address = None

client_sessions = {}
last_counters = {}
connections = []
peer_servers = {}  # Store connections to other servers
peers_to_connect = [("127.0.0.1", 12345), ("127.0.0.1", 12346)]  # List of peer servers

server_public_keys = {}

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

def generate_username():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def verify_all(session, counter, signature, data):
    public_key = serialization.load_pem_public_key(base64.b64decode(session.public_key_data), backend=default_backend())
    if session.public_key_data in last_counters and counter <= last_counters[session.public_key_data]:
        session.connection.send("Replay attack detected.".encode())
        return False
    last_counters[session.public_key_data] = counter

    if not verify_signature(public_key, data + str(counter), signature):
        session.connection.send("Signature verification failed.".encode())
        return False
    print('Successfully verified session')
    return True

def get_all_public_keys():
    # Return a list of non-null public_key_data values from each session in client_sessions
    return [session.public_key_data for session in client_sessions.values() if session.public_key_data is not None]

def send_client_list_response(connection):
    servers_list = []
    
    # Iterate over each server address and its set of public keys
    for server_address, keys in server_public_keys.items():
        # Prepare the list of clients (public keys)
        clients = list(keys)  # Convert set to list for JSON serialization
        
        # Append server and its clients to the server list
        servers_list.append({
            "address": server_address,
            "clients": clients
        })
    
    # Create the final JSON object
    response = {
        "type": "client_list",
        "servers": servers_list
    }
        # Convert JSON object to string and send it over the connection
    response_json = json.dumps(response) + '\n'
    print(response_json)
    connection.connection.send(response_json.encode())


def send_clients_of_this_server():
    message = json.dumps({
        "type": "client_update",
        "clients": get_all_public_keys()
    }) + '\n'
    
    print(f"I am now sending MY client update {message}")

    # Loop through all connected peer servers and send the update
    for peer_address, peer_socket in peer_servers.items():
        try:
            peer_socket.send(message.encode())
            print(f"Sent client update to peer {peer_address}")
        except Exception as e:
            print(f"Failed to send client update to peer {peer_address}: {e}")

def connect_to_peer_server(peer_host, peer_port):

    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        peer_socket.connect((peer_host, peer_port))
        peer_servers[(peer_host, peer_port)] = peer_socket
        print(f"Connected to peer server at {peer_host}:{peer_port}")
        send_initial_server_messages(peer_host, peer_port)
    except Exception as e:
        print(f"Failed to connect to peer server at {peer_host}:{peer_port}: {e}")

def send_initial_server_messages(peer_host, peer_port):
    print(f"Sending 'server_hello' to {peer_host}:{peer_port}")
    message = json.dumps({
        "data": {
            "type": "server_hello",
            "sender": f"{peer_host}:{peer_port}"
        }
    }) + '\n'
    peer_servers[(peer_host, peer_port)].send(message.encode())

    print(f"Sending request for new clients to {peer_host}:{peer_port}")
    # Fixed structure: use a dictionary not a set
    message = json.dumps({
        "type": "client_update_request"
    }) + '\n'
    peer_servers[(peer_host, peer_port)].send(message.encode())

def retry_peer_connections(local_port):
    while True:
        for peer_host, peer_port in peers_to_connect:
            if (peer_host, peer_port) not in peer_servers and peer_port != local_port:
                connect_to_peer_server(peer_host, peer_port)
        time.sleep(10)  # Retry every 10 seconds

def process_message(session, message_json):
    try:
        # Ensure 'type' is available and fetch it safely
        msg_type = message_json.get('type', '')
        print(f"Received message: {message_json}")

        # Check if 'data' is present and is a dictionary, otherwise use an empty dictionary
        data = message_json.get('data', {}) if isinstance(message_json.get('data', {}), dict) else {}

        # Handle server_hello type if present
        if data.get('type') == 'server_hello':
            sender_address = data.get('sender', 'Unknown sender')
            session.server_address = sender_address

        # Handle signed_data types
        if msg_type == 'signed_data':
            signature = message_json.get('signature', '')
            data_json = json.dumps(data, separators=(',', ':'))  # Convert data to JSON string
            counter = message_json.get('counter', 0)
            session.counter = counter  # Update session counter

            # Handle different data types within signed_data
            data_type = data.get('type', '')
            if data_type == 'hello':
                print('Running hello')
                session.public_key_data = data.get('public_key')
                session.username = generate_username()
                connections.append(session.connection)
                response_message = (
                    "Successfully authenticated! Type: 'list' to get a list of currently connected users. "
                    "Type: 'to: <public_key> <your message>' to send a message. Type: 'public: <message>' to broadcast a message."
                )
                session.connection.send(response_message.encode())

                public_key = data.get('public_key')
                server_address = f"{host}:{port}"
                if server_address not in server_public_keys:
                    server_public_keys[server_address] = set()
                server_public_keys[server_address].add(public_key)

            # Verify all conditions are met
            if not verify_all(session, counter, signature, data_json):
                return

            # Handle chat or public_chat types
            if data_type in ['chat', 'public_chat']:
                for conn in connections:
                    print("sending chat")
                    conn.send(json.dumps(message_json). encode())

        elif msg_type == 'client_list_request':
            print('I HAVE RECEIVED A REQUEST FROM A CLIENT FOR A LIST')
            send_client_list_response(session)

        elif msg_type == 'client_update_request':
            print('Running SERVER UPDATE request')
            send_clients_of_this_server()

        elif msg_type == 'client_update':
            print('Updating GLOBAL list with other servers connections')
            # Fetch the clients from the update message
            clients = data.get('clients', [])

            # Use the stored server address from the session to add clients to server_public_keys
            server_address = session.server_address
            if server_address:
                if server_address not in server_public_keys:
                    server_public_keys[server_address] = set()

                # Add each client to the server's list of public keys
                for client in clients:
                    public_key = client.get('public_key')
                    if public_key:
                        server_public_keys[server_address].add(public_key)
                        print(server_public_keys)

    except Exception as e:
        print(f"Exception processing message from {getattr(session, 'username', 'Unknown')}: {e}")

def client_handler(conn, server_address):
    session = ClientSession(conn)
    client_sessions[conn] = session
    message_buffer = ''
    try:
        while True:
            data = conn.recv(4096).decode()
            if not data:
                break

            message_buffer += data
            while '\n' in message_buffer:
                message, nl, message_buffer = message_buffer.partition('\n')
                if message:
                    try:
                        message_json = json.loads(message)
                        process_message(session, message_json)
                    except json.JSONDecodeError:
                        print(f"Debug: Processing plain text message - {message}")

    except (ConnectionResetError, ConnectionAbortedError) as e:
        print(f"Error with client {session.username}: {e}")

    finally:
        conn.close()
        if conn in connections:
            connections.remove(conn)
        if conn in client_sessions:
            del client_sessions[conn]

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server started and listening on port {port}")

    # Start a thread to manage retries for peer connections
    threading.Thread(target=retry_peer_connections,args=(port,), daemon=True).start()

    while True:
        conn, addr = server_socket.accept()
        print(f"Client connected at {addr}")
        thread = threading.Thread(target=client_handler, args=(conn, (host, port)))
        thread.start()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <port>")
        sys.exit(1)
    
    port = int(sys.argv[1])
    start_server(port)