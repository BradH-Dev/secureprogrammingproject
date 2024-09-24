import socket
import threading
import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import random
import string

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
                session.connection.send(f"Your username: {session.username} | Authenticated".encode())

            if not verify_all(session, counter, signature, data):
                return

            if message_json['data']['type'] == 'fetch_key':
                requested_username = message_json['data'].get('username')
                for uname, pkey in [(s.username, s.public_key_data) for s in client_sessions.values()]:
                    if uname == requested_username:
                        session.connection.send(json.dumps({
                            "type": "signed_data",
                            "data": {"type": 'fetch_key', "username": requested_username, "public_key": pkey},
                            "counter": counter,
                            "signature": signature  # this should be properly generated, but for demo purposes, we reuse
                        }).encode())
                        break
                else:
                    session.connection.send(json.dumps({"type": "error", "message": f"No public key found for {requested_username}"}).encode())

            elif message_json['data']['type'] == 'chat':
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
    host = '127.0.0.1'
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
    start_server(12345)
