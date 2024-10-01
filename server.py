import socket
import threading
import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import random
import string
import sys
import websockets
import asyncio

host = '127.0.0.1'

# List of connected servers in the neighborhood
neighborhood_servers = ["127.0.0.1:9001", "127.0.0.1:9002"]  # Add IP addresses of servers

# A list to hold WebSocket connections to other servers
server_connections = []

class ClientSession:
    def __init__(self, connection):
        self.connection = connection
        self.username = None
        self.public_key_data = None
        self.counter = 0

client_sessions = {}
last_counters = {}
connections = []

def verify_signature(public_key, message, signature):
    print(f"Verifying signature for data: {message}")
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
    """
    Retrieves all stored public keys in PEM format from the client sessions.
    Returns a list of dictionaries with usernames and their respective public keys.
    """
    clients = [{"username": session.username, "public_key": session.public_key_data} for session in client_sessions.values()]
    return clients

def push_client_list(session, counter, signature):
        all_clients = get_all_public_keys()
        session.connection.send(json.dumps({
            "type": "signed_data",
            "data": {"type": 'client_list', "address": host, "clients": all_clients},
            "counter": counter,
            "signature": signature
        }).encode())

# WebSocket functions for server-to-server communication
async def connect_to_server(server_address):
    uri = f"ws://{server_address}"
    try:
        websocket = await websockets.connect(uri)
        server_connections.append(websocket)
        print(f"Connected to server: {server_address}")
    except Exception as e:
        print(f"Failed to connect to {server_address}: {e}")

async def connect_to_all_servers():
    for server in neighborhood_servers:
        await connect_to_server(server)

async def forward_message_to_server(server_address, message):
    try:
        async with websockets.connect(f"ws://{server_address}") as websocket:
            await websocket.send(json.dumps(message))
            print(f"Message forwarded to {server_address}")
    except Exception as e:
        print(f"Error forwarding message to {server_address}: {e}")

async def broadcast_to_neighborhood(message):
    for websocket in server_connections:
        try:
            await websocket.send(json.dumps(message))
            print(f"Message broadcasted to {websocket.remote_address}")
        except Exception as e:
            print(f"Error sending message to {websocket.remote_address}: {e}")

async def request_client_lists():
    for websocket in server_connections:
        message = json.dumps({
            "type": "client_list_request",
        })
        await websocket.send(message)

def process_client_list_response(message):
    client_list = message['data']['clients']
    # Update local client list with received data
    update_local_client_list(client_list)

def update_local_client_list(client_list):
    # Logic to update local client list with the received client list from another server
    for client in client_list:
        # Add to local client_sessions if not already present
        pass

def process_message(session, message_json):
    try:
        if message_json['type'] == 'signed_data':
            signature = message_json['signature']
            data = json.dumps(message_json['data'], separators=(',', ':'))
            counter = message_json['counter']
            session.counter = counter

            if message_json['data']['type'] == 'hello':
                session.public_key_data = message_json['data']['public_key']
                session.username = generate_username()
                connections.append(session.connection)
                session.connection.send(f"Successfully authenticated! Type: 'list' to get a list of currently connected users. Type: 'to: <public_key> <your message>' to send a message. Type: 'public: <message>' to broadcast a message".encode())
            if not verify_all(session, counter, signature, data):
                return
            
            if message_json['data']['type'] == 'client_list_request':
                push_client_list(session, counter, signature)

            #checks if it is a private message or message needs to be forwarded to another server
            elif message_json['data']['type'] == 'chat':
                destination_server = message_json['data']['destination_servers'][0]  # Assuming first server is the target
                if destination_server == host:
                    # Process chat message locally
                    for conn in connections:
                        conn.send(json.dumps(message_json).encode())
                else:
                    # Forward message to another server
                    asyncio.create_task(forward_message_to_server(destination_server, message_json))

            elif message_json['data']['type'] == 'chat' or message_json['data']['type'] == 'public_chat':
                 # Broadcast to all connected servers
                asyncio.create_task(broadcast_to_neighborhood(message_json))
                # Broadcast locally
                for conn in connections:
                    conn.send(json.dumps(message_json).encode())

    except Exception as e:
        print(f"Exception processing message from {session.username}: {e}")

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
     # Start WebSocket connections to other servers in the neighborhood
    asyncio.get_event_loop().run_until_complete(connect_to_all_servers())

    while True:
        conn, addr = server_socket.accept()
        print(f"Client connected at {addr}")
        thread = threading.Thread(target=client_handler, args=(conn, (host, port)))
        thread.start()

if __name__ == "__main__":
    start_server(int(sys.argv[1]))
