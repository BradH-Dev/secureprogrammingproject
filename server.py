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
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK

host = '127.0.0.1'

# List of connected servers in the neighborhood
neighborhood_servers = ["127.0.0.1:9004"]  # Add IP addresses of servers

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

            elif message_json['data']['type'] == 'chat':
                destination_servers = message_json['data']['destination_servers']
                if host in destination_servers:
                    # Process locally
                    for conn in connections:
                        conn.send(json.dumps(message_json).encode())
                else:
                    # Forward to other servers
                    for server_address in destination_servers:
                        if server_address != host:
                            # Schedule forwarding to server
                            asyncio.run_coroutine_threadsafe(forward_message_to_server(server_address, message_json), async_loop)

            elif message_json['data']['type'] == 'public_chat':
                # Broadcast to all connected clients locally
                for conn in connections:
                    conn.send(json.dumps(message_json).encode())
                    # Broadcast to neighborhood
                asyncio.run_coroutine_threadsafe(broadcast_to_neighborhood(message_json), async_loop)

    except Exception as e:
        print(f"Exception processing message from {session.username}: {e}")

def process_message_from_server(message_json):
    # Process the message received from another server
    # For example, forward it to local clients if necessary
    try:
        if message_json['type'] == 'signed_data':
            # Handle message
            if message_json['data']['type'] == 'chat' or message_json['data']['type'] == 'public_chat':
                # Forward to local clients
                for conn in connections:
                    conn.send(json.dumps(message_json).encode())
            # Handle other message types if necessary
    except Exception as e:
        print(f"Exception processing message from server: {e}")

async def server_ws_handler(websocket, path):
    print(f"New WebSocket connection established: {websocket.remote_address}")
    
    try:
        async for message in websocket:
            # Only process valid WebSocket messages (after handshake)
            try:
                message_json = json.loads(message)
                process_message_from_server(message_json)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON message: {e}")
            except Exception as e:
                print(f"Error in WebSocket message handling: {e}")
    except ConnectionClosedError as e:
        print(f"Connection closed with error: {e}")
    except ConnectionClosedOK:
        print("Connection closed cleanly")
    except Exception as e:
        print(f"Unexpected error in WebSocket connection: {e}")
    finally:
        print(f"WebSocket connection closed: {websocket.remote_address}")

async def connect_to_server(server_address):
    uri = f"ws://{server_address}"
    retries = 0  # Add a retry counter to avoid endless loops
    max_retries = 5  # Maximum number of retries before giving up

    while retries < max_retries:
        try:
            websocket = await websockets.connect(uri)
            server_connections.append(websocket)
            print(f"Connected to server: {server_address}")

            # Start listening to messages from this server
            async for message in websocket:
                if message:
                    message_json = json.loads(message)
                    process_message_from_server(message_json)
            break  # Exit loop if connection is successful

        except Exception as e:
            print(f"Failed to connect to {server_address}: {e}")
            retries += 1
            print(f"Retrying connection to {server_address} in 5 seconds... (Retry {retries}/{max_retries})")
            await asyncio.sleep(5)  # Wait 5 seconds before retrying

    if retries == max_retries:
        print(f"Max retries reached. Could not connect to {server_address}.")


async def connect_to_all_servers():
    await asyncio.sleep(5)  # Add a delay to ensure both servers are up
    tasks = []
    for server in neighborhood_servers:
        tasks.append(asyncio.create_task(connect_to_server(server)))
    await asyncio.gather(*tasks)

async def forward_message_to_server(server_address, message):
    try:
        async with websockets.connect(f"ws://{server_address}") as websocket:
            await websocket.send(json.dumps(message))
            print(f"Message forwarded to {server_address}")
    except Exception as e:
        print(f"Error forwarding message to {server_address}: {e}")

async def broadcast_to_neighborhood(message):
    for server in neighborhood_servers:
        if server != f"{host}:{ws_port}":  # Make sure not to broadcast to self
            await forward_message_to_server(server, message)


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

async def start_websocket():
    print(f"Starting WebSocket server on port {ws_port}...")
    async with websockets.serve(server_ws_handler, host, ws_port):
        await asyncio.Future()  # Run forever

def start_server(port):
    global async_loop, ws_port
    # Start the asyncio event loop in a separate thread
    async_loop = asyncio.new_event_loop()
    async_thread = threading.Thread(target=async_loop.run_forever)
    async_thread.start()

    # Start WebSocket server
    ws_port = port + 1000  # Use a different port for WebSocket server

    # Schedule the WebSocket server coroutine in the event loop
    asyncio.run_coroutine_threadsafe(start_websocket(), async_loop)

    print(f"WebSocket server started and listening on port {ws_port}")

    # Start connecting to neighborhood servers
    asyncio.run_coroutine_threadsafe(connect_to_all_servers(), async_loop)

    # Start TCP server for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server started and listening on port {port}")

    while True:
        conn, addr = server_socket.accept()
        print(f"Client connected at {addr}")
        thread = threading.Thread(target=client_handler, args=(conn, (host, port)))
        thread.start()




if __name__ == "__main__":
    start_server(int(sys.argv[1]))

