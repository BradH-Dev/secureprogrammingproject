import socket
import threading
import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    # Export the public key to PEM format
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem, private_key

def sign_data(private_key, data):
    signature = private_key.sign(
        data.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def send_message(server_ip, port):
    pem, private_key = generate_keys()
    # Correctly handle the PEM encoded public key
    public_key_exported = base64.b64encode(pem).decode()

    counter = 1  # This should be managed to ensure it's always unique and increasing
    data = {
        "type": "hello",
        "public_key": public_key_exported
    }
    signed_data = json.dumps(data, separators=(',', ':'))
    signature = sign_data(private_key, signed_data + str(counter))

    initial_message = json.dumps({
        "type": "signed_data",
        "data": data,
        "counter": counter,
        "signature": signature
    })

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_ip, port))
        
        # Send the initial hello message
        sock.sendall(initial_message.encode())
        response = sock.recv(1024)
        print(f"Received from server: {response.decode()}")

        # Keep the client running until "quit" is input
        while True:
            message = input("Enter message (type 'quit' to exit): ")
            if message.lower() == "quit":
                sock.sendall(message.encode())
                break
            sock.sendall(message.encode())
            response = sock.recv(1024)
            print(f"Received from server: {response.decode()}")

if __name__ == "__main__":
    server_ip = '127.0.0.1'
    port = 12345
    send_message(server_ip, port)