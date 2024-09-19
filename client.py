import socket
import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate RSA keys (private and public)
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

# Sign data with RSA private key
def sign_data(private_key, data):
    signature = private_key.sign(
        data.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

# Encrypt data using AES and RSA (for AES key)
def encrypt_data(public_key, data):
    aes_key = os.urandom(16)  # Generate a 128-bit AES key
    iv = os.urandom(16)  # Generate a random initialization vector
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend()).encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Encrypt the AES key with the recipient's public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(iv).decode(), base64.b64encode(encrypted_aes_key).decode(), base64.b64encode(encrypted_data).decode()

def send_message(server_ip, port):
    pem, private_key = generate_keys()  # Generate client's RSA keys
    public_key_exported = base64.b64encode(pem).decode()
    counter = 1  # Incremented for each new message

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_ip, port))

        # Initial hello message to register client
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

        sock.sendall(initial_message.encode())  # Send hello message
        response = sock.recv(1024)
        print(f"Received from server: {response.decode()}")

        while True:
            message = input("Enter message (type 'quit' to exit): ")
            if message.lower() == "quit":
                sock.sendall(message.encode())
                break

            if message.startswith('to:'):
                _, username, user_message = message.split(' ', 2)

                # Fetch recipient's public key from the server
                request = {'type': 'fetch_key', 'username': username}
                sock.sendall(json.dumps(request).encode())
                
                response = sock.recv(4096)
                response_data = json.loads(response.decode())
                
                if 'public_key' in response_data:
                    recipient_public_key_pem = response_data['public_key']
                    recipient_public_key = serialization.load_pem_public_key(
                        base64.b64decode(response_data['public_key']),
                        backend=default_backend()
                    )

                    iv, encrypted_aes_key, encrypted_chat = encrypt_data(recipient_public_key, user_message)

                    # Construct the message with the encrypted AES key and chat data
                    chat_data = {
                        'type': 'chat',
                        'destination_server': server_ip,
                        'iv': iv,
                        'symm_keys': [encrypted_aes_key],  # AES key encrypted with the recipient's public key
                        'chat': {
                            'participants': [public_key_exported, recipient_public_key_pem],
                            'message': encrypted_chat
                        }
                    }

                    # Send the chat data to the server
                    sock.sendall(json.dumps({'data': chat_data}).encode())
                else:
                    print(f"Error: {response_data.get('error')}")
            else:
                sock.sendall(message.encode())

if __name__ == "__main__":
    server_ip = '127.0.0.1'
    port = 12345
    send_message(server_ip, port)
