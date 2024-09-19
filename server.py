import socket
import threading
import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


# Storage for client public keys
client_keys = []


# This dictionary will keep the last counter value received from each client
last_counters = {}

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

import random
import string

# Helper function to generate random usernames
def generate_username():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def client_handler(conn, server_address):
    username = None
    public_key_data = None
    try:
        # Receive the initial message
        message_data = conn.recv(4096).decode()
        message_json = json.loads(message_data)

        # Extract the signature and signed data
        signature = message_json['signature']
        data = json.dumps(message_json['data'], separators=(',', ':'))
        counter = message_json['counter']

        public_key_data = message_json['data']['public_key']
        public_key = serialization.load_pem_public_key(base64.b64decode(public_key_data), backend=default_backend())

        # Check the counter to prevent replay attacks
        if public_key_data in last_counters and counter <= last_counters[public_key_data]:
            conn.send("Replay attack detected.".encode())
            return

        last_counters[public_key_data] = counter

        # Verify the signature
        if not verify_signature(public_key, data + str(counter), signature):
            conn.send("Signature verification failed.".encode())
            return

        # Process hello message
        if message_json['data']['type'] == 'hello':
            username = generate_username()
            client_keys.append((username, public_key_data))
            print(f"New client {username} connected with public key.")
            print(f"Updated client keys: {client_keys}")
            conn.send(f"Your username: {username} | Authenticated".encode())

        # Handle ongoing messages
        while True:
            message = conn.recv(1024).decode()
            if message.lower() == "quit":
                break
            if message:
                print(f"Received message from {username}: {message}")
                conn.send(f"Message received: {message}".encode())  # Acknowledge the normal message
                
    except (ConnectionResetError, ConnectionAbortedError):
        print(f"Client {username} has forcibly closed the connection.")

    finally:
        conn.close()
        # Remove client from the list and print the updated list
        if username and public_key_data:
            client_keys.remove((username, public_key_data))
            print(f"Client {username} disconnected.")
            print(f"Updated client keys: {client_keys}")

def parse_message(message):
    parts = message.split(':')
    return parts[0], parts[1], parts[2]

def validate_message(sender, receiver, body):
    return len(sender) > 0 and len(receiver) > 0 and len(body) > 0

def route_message(conn, sender, receiver, body, server_address):
    print(f"Routing message from {sender} to {receiver}: {body}")
    response_message = f"Message successfully routed from {sender} to {receiver}."
    conn.send(response_message.encode())

def start_server(port):
    host = '127.0.0.1'
    server_address = (host, port)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_address)
    server_socket.listen(5)
    print(f"Server started and listening on on port {port}")

    while True:
        conn, addr = server_socket.accept()
        print(f"Client connected at {addr}")
        thread = threading.Thread(target=client_handler, args=(conn, server_address))
        thread.start()

if __name__ == "__main__":
    start_server(12345)
