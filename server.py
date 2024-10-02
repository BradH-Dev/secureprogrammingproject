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
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import time

from flask import Flask, request, jsonify, send_from_directory, abort
from werkzeug.utils import secure_filename, safe_join
from multiprocessing import Process
import os

host = '127.0.0.1'
processed_messages = set()  # Global set to track processed message IDs

app = Flask(__name__)
upload_folder = 'uploaded_files'
os.makedirs(upload_folder, exist_ok=True)
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' in request.files:
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join(upload_folder, filename))
        file_url = f"http://{request.host}/api/files/{filename}"
        return jsonify({'file_url': file_url})
    return "No file found", 400
@app.route('/api/files/<filename>', methods=['GET'])
def download_file(filename):
    safe_path = safe_join(upload_folder, filename)
    if os.path.exists(safe_path):
        return send_from_directory(upload_folder, filename, as_attachment=True, download_name=filename)
    else:
        abort(404)

def sign_data(private_key, data):
    signature = private_key.sign(
        data.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem, private_key

class ClientSession:
    def __init__(self, connection):
        self.connection = connection
        self.is_server = False
        self.username = None
        self.public_key_data = None
        self.counter = 0
        self.server_address = None
        pem, self.private_key = generate_keys()
        self.public_key_exported = base64.b64encode(pem).decode()

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
        #session.connection.send("Replay attack detected.".encode())
        print('Replay attack detected')
        return False
    last_counters[session.public_key_data] = counter

    if not verify_signature(public_key, data + str(counter), signature):
        #session.connection.send("Signature verification failed.".encode())
        print('Signature verification failed.')
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
        print(f"\nCONNECT TO PEER SERVER AT {peer_host}:{peer_port}")
        send_initial_server_messages(peer_host, peer_port)
    except Exception as e:
        print(f"Failed to connect to peer server at {peer_host}:{peer_port}: {e}")

def send_initial_server_messages(peer_host, peer_port):
    print(f"Sending 'server_hello' to {peer_host}:{peer_port}")
    message = json.dumps({
        "data": {
            "type": "server_hello",
            "sender": f"{host}:{port}"
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
            if (peer_host, peer_port) not in peer_servers and peer_port != port:
                connect_to_peer_server(peer_host, peer_port)
        time.sleep(10)  # Retry every 10 seconds

def process_message(session, message_json):
    try:
        # Ensure 'type' is available and fetch it safely
        msg_type = message_json.get('type', '')
        print(f"Received message: {message_json}")
        print(msg_type)

        # Check if 'data' is present and is a dictionary, otherwise use an empty dictionary
        data = message_json.get('data', {}) if isinstance(message_json.get('data', {}), dict) else {}

        # Handle server_hello type if present
        if data.get('type') == 'server_hello':
            sender_address = data.get('sender', 'Unknown sender')
            session.server_address = sender_address
            session.is_server = True

        # Handle signed_data types


        if msg_type == 'signed_data':
            signature = message_json.get('signature', '')
            data_json = json.dumps(data, separators=(',', ':'))  # Convert data to JSON string
            counter = message_json.get('counter', 0)
            session.counter = counter  # Update session counter
            

            # Extract the inner data and counter
            original_data = message_json.get('data', {})
            original_counter = message_json.get('counter', 0)
            original_signature = message_json.get('signature', '')
        
            # Only process chat messages
            if original_data.get('type', '') == 'chat':
                if not session.is_server: 
                    if not verify_all(session, counter, signature, data_json):
                        return
                    
                # Extract the list of destination servers from the chat data
                original_destinations = original_data.get('destination_servers', [])
                print(original_destinations)
                # Filter out the server itself from the destinations
                # Convert destination server strings to tuple format (host, port)
                # Convert string addresses to tuple format (host, port) for peer server lookup
                tuple_destinations = [tuple(server.split(':')) for server in original_destinations]
                tuple_destinations = [(host, int(port)) for host, port in tuple_destinations]

                # Filter out the server itself from the destinations
                filtered_servers = [server for server in tuple_destinations if server != (host, int(port))]

                print(filtered_servers)
                print(peer_servers)

                # For each server, create a new message with only that server as the destination
                for server in filtered_servers:
                    if server in peer_servers:
                        # Modify the destination_servers to only include the current server
                        modified_data = original_data.copy()
                        modified_data['destination_servers'] = [f"{server[0]}:{server[1]}"]  # Back to string format for JSON serialization

                        # Create a new signed_data message with the modified destination_servers
                        new_message_json = {
                            "type": "signed_data",
                            "data": modified_data,
                            "counter": original_counter,
                            "signature": original_signature
                        }
                        message_to_forward = json.dumps(new_message_json) + "\n"
                        peer_socket = peer_servers[server]
                        peer_socket.send(message_to_forward.encode())
                        print(f"Forwarded modified signed chat to peer server {server}")
            
            if original_data.get('type') == 'public_chat':
                message_id = f"{original_data.get('sender')}_{original_data.get('message')}"
                if message_id in processed_messages:
                    return

                processed_messages.add(message_id)
                message_to_send = json.dumps(message_json) + "\n"

                # Forward to all connected peer servers
                for peer, peer_socket in peer_servers.items():
                    if peer != session.server_address:
                        peer_socket.send(message_to_send.encode())
                time.sleep(1)
                processed_messages.clear()


            # Handle different data types within signed_data
            data_type = data.get('type', '')
            print(data_type)
            if data_type == 'hello':
                print('Running hello')
                session.public_key_data = data.get('public_key')
                session.username = generate_username()
                connections.append(session.connection)
                response_message = (
                    "Successfully authenticated!\n"
                    "Type: 'list' to get/update the list of currently connected users.\n"
                    "-= Messaging Format =-\n"
                    "Private Messages: 'to: <fingerprint> <message>'\n"
                    "Group Messages: 'to: <fingerprint>;<fingerprint>;... <message>'\n"
                    "Public Messages: 'public: <message>'\n"
                )
                session.connection.send(response_message.encode())

                public_key = data.get('public_key')
                server_address = f"{host}:{port}"
                if server_address not in server_public_keys:
                    server_public_keys[server_address] = set()
                server_public_keys[server_address].add(public_key)

                # Verify all conditions are met
                if not session.is_server: 
                    if not verify_all(session, counter, signature, data_json):
                        return

                time.sleep(3)
                send_clients_of_this_server()

            print(data_json)

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
            time.sleep(5) 
            send_clients_of_this_server()

        elif msg_type == 'client_update':
            print('Updating GLOBAL list with other servers connections')
            # Fetch the clients from the update message
            clients = message_json.get('clients')
            print(clients)

            # Use the stored server address from the session to add clients to server_public_keys
            server_address = session.server_address
            if server_address:
                if server_address not in server_public_keys:
                    server_public_keys[server_address] = set()

                # Assume each client is a public key already in the correct format (adjust if not)
                for public_key in clients:
                    server_public_keys[server_address].add(public_key)
                    print(f"Updated public keys for {server_address}: {server_public_keys[server_address]}")

            for server, keys in server_public_keys.items():
                print(f"Server: {server}")
                if keys:
                    print("Public Keys:")
                    for key in keys:
                        print(f" - {key}")
                else:
                    print("Public Keys: None")

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
                        if message.strip().lower() == "quit":
                            print(f"Client {session.username} has disconnected.")
                            conn.close()
                            return

                        message_json = json.loads(message)
                        process_message(session, message_json)
                    except json.JSONDecodeError:
                        print(f"Debug: Processing plain text message - {message}")

    except (ConnectionResetError, ConnectionAbortedError) as e:
        print(f"Error with client {session.username}: {e}")

    finally:
        close_connection(session, conn)

def close_connection(session, conn):
    """Handle closing the client connection and cleaning up."""
    public_key = session.public_key_data
    server_address = f"{host}:{port}"

    # Log and close the connection
    print(f"Closing connection for {public_key}")

    # Remove public key from server_public_keys
    if server_address in server_public_keys and public_key in server_public_keys[server_address]:
        server_public_keys[server_address].discard(public_key)
        print(f"Removed {public_key} from server_public_keys {server_address}.")

    # Remove from active connections and session lists
    if conn in connections:
        connections.remove(conn)

    if conn in client_sessions:
        del client_sessions[conn]
        
    conn.close()
    print(f'server_public_keys ====== {server_public_keys}')

def run_flask():
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server started and listening on port {port}")

    # Start a thread to manage retries for peer connections
    threading.Thread(target=retry_peer_connections,args=(port+1,), daemon=True).start()

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
    flask_process = Process(target=run_flask)
    flask_process.start()
    start_server(port)