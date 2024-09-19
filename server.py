import socket
import threading
import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Storage for client public keys and usernames
client_keys = []
client_connections = {}  # Store client connections by username

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
    import random, string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def client_handler(conn, server_address):
    username = None
    public_key_data = None
    try:
        # Initial connection setup (hello message)
        message_data = conn.recv(4096).decode()
        message_json = json.loads(message_data)

        print(f"Received message: {message_data}")

        signature = message_json['signature']
        data = json.dumps(message_json['data'], separators=(',', ':'))
        counter = message_json['counter']

        public_key_data = message_json['data']['public_key']
        public_key = serialization.load_pem_public_key(
            base64.b64decode(public_key_data),
            backend=default_backend()
        )

        if not verify_signature(public_key, data + str(counter), signature):
            conn.send("Signature verification failed.".encode())
            return

        if message_json['data']['type'] == 'hello':
            username = generate_username()
            client_keys.append((username, public_key_data))
            client_connections[username] = conn
            print(f"New client {username} connected.")
            conn.send(f"Your username: {username} | Authenticated".encode())

        # Handle ongoing communication
        while True:
            message_data = conn.recv(4096).decode()

            if message_data.lower() == "quit":
                break

            message_json = json.loads(message_data)
            # Check if 'type' exists in the message
            print(f"Received message: {message_data}")
            if 'type' in message_json:
                # Handle "fetch_key" request
                if message_json['type'] == 'fetch_key':
                    requested_username = message_json['username']
                    for uname, ukey in client_keys:
                        if uname == requested_username:
                            response = {'type': 'public_key', 'public_key': ukey}
                            conn.send(json.dumps(response).encode())
                            print(f"Public key for {requested_username} sent.")
                            break
                    else:
                        conn.send(json.dumps({'error': 'Username not found'}).encode())
                        print(f"Public key for {requested_username} not found.")


    # Handle "chat" request and forward the message to all recipients
                elif message_json['type'] == 'chat':
                    sender_conn = conn  # Save the sender's connection
                    iv = message_json['data']['iv']
                    symm_key = message_json['data']['symm_keys'][0]
                    encrypted_chat = message_json['data']['chat']['message']
                    participants = message_json['data']['chat']['participants']

                    # Forward the message to all participants except the sender
                    for participant in participants[1:]:  # Skip the sender
                        if participant in client_connections:
                            recipient_conn = client_connections[participant]
                            
                            forward_message = {
                                'type': 'chat',
                                'iv': iv,
                                'symm_key': symm_key,
                                'encrypted_chat': encrypted_chat
                            }

                            recipient_conn.send(json.dumps(forward_message).encode())
                            print(f"Message forwarded to {participant}.")
                        else:
                            print(f"Participant {participant} is not connected.")

    except (ConnectionResetError, ConnectionAbortedError):
        print(f"Client {username} has forcibly closed the connection.")
    finally:
        conn.close()
        if username:
            client_keys.remove((username, public_key_data))
            client_connections.pop(username, None)
            print(f"Client {username} disconnected.")

def start_server(port):
    host = '127.0.0.1'
    server_address = (host, port)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_address)
    server_socket.listen(5)
    print(f"Server started and listening on port {port}")

    while True:
        conn, addr = server_socket.accept()
        print(f"Client connected at {addr}")
        thread = threading.Thread(target=client_handler, args=(conn, server_address))
        thread.start()

if __name__ == "__main__":
    start_server(12345)