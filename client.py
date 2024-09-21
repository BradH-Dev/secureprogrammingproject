import socket
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
    public_key_exported = base64.b64encode(pem).decode()

    counter = 1  # Initialize the counter

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_ip, port))

        # Receive the prompt for the username
        prompt = sock.recv(1024).decode()                
        # Send the username
        username = input(prompt)
        sock.send(username.encode())

        # Wait for the server's acknowledgment of the username
        response = sock.recv(1024).decode()
        if "Username already taken" in response:
            print(response)
            return  # Exit client program if duplicate username is used
        print(response)

        # Send the initial hello message
        hello_data = {
            "data": {
                "type": "hello",
                "public_key": public_key_exported
            }
        }
        signed_data = json.dumps(hello_data, separators=(',', ':'))
        signature = sign_data(private_key, signed_data + str(counter))

        initial_message = json.dumps({
            "type": "signed_data",
            "data": hello_data,
            "counter": counter,
            "signature": signature
        })

        sock.sendall(initial_message.encode())
        response = sock.recv(1024)
        print(f"Received from server: {response.decode()}")

        # Keep the client running until "quit" is input
        while True:
            message = input("Enter message (type 'quit' to exit): ")
            if message.lower() == "quit":
                break

            # Prepare the chat message
            chat_data = {
                "data": {
                    "type": "chat",
                    "destination_servers": [],
                    "iv": "<Base64 encoded AES IV>",
                    "symm_keys": [],
                    "chat": base64.b64encode(message.encode()).decode()
                }
            }

            counter += 1
            signed_data = json.dumps(chat_data, separators=(',', ':'))
            signature = sign_data(private_key, signed_data + str(counter))

            chat_message = json.dumps({
                "type": "signed_data",
                "data": chat_data,
                "counter": counter,
                "signature": signature
            })

            sock.sendall(chat_message.encode())
            response = sock.recv(1024)
            print(f"Received from server: {response.decode()}")

if __name__ == "__main__":
    server_ip = '127.0.0.1'
    port = 12345
    send_message(server_ip, port)
