import socket
import json
import base64
import hashlib
import threading
import sys
import termios
import tty
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
    
    # Compute the SHA-256 fingerprint of the public key
    fingerprint = hashlib.sha256(pem).digest()
    fingerprint_base64 = base64.b64encode(fingerprint).decode()
    
    return pem, private_key, fingerprint_base64

def sign_data(private_key, data):
    signature = private_key.sign(
        data.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def clear_current_input():
    # Clear the current line by overwriting it with spaces and returning to the start
    sys.stdout.write('\r' + ' ' * 80 + '\r')
    sys.stdout.flush()

def flush_input_buffer():
    # Get the current terminal settings
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        # Disable terminal echo and buffering
        tty.setraw(fd)
        termios.tcflush(fd, termios.TCIFLUSH)  # Flush the input buffer

    finally:
        # Restore the original terminal settings
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def receive_public_chat_messages(sock):
    while True:
        try:
            response = sock.recv(1024).decode()
            if response:
                # Clear the current input prompt before printing the received message
                clear_current_input()

                # Print the received message
                sys.stdout.write(response + '\n')
                sys.stdout.flush()

                # Flush the input buffer to remove any previous input
                flush_input_buffer()

                # Restore the prompt (without previous input)
                print("Enter message (type 'quit' to exit): ", end='', flush=True)
            else:
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break


def send_message(server_ip, port):
    pem, private_key, fingerprint = generate_keys()
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
        print(f"Server: {response.decode()}")

        # Start a thread to listen for incoming messages public messages
        threading.Thread(target=receive_public_chat_messages, args=(sock,), daemon=True).start()

        # Keep the client running until "quit" is input
        while True:
            message = input("Enter message (type 'quit' to exit): ")
            if message.lower() == "quit":
                break

            # Check if the message is a private message (starts with "@")
            if message.startswith("@"):
                recipient = message.split(' ')[0][1:]  # Extract recipient username
                private_message = message[len(recipient) + 2:]  # Extract the private message text

                # Private chat data (WIP)
                chat_data = {
                    "data": {
                        "type": "chat",
                        "destination_servers": [
                            "<Address of each recipient's destination server>"
                        ],
                        "iv": "<Base64 encoded AES initialization vector>",
                        "symm_keys": [
                            "<Base64 encoded AES key, encrypted with each recipient's public RSA key>"
                        ],
                        "chat": "<Base64 encoded AES encrypted segment>"
                    },
                    "chat": {
                        "participants": [
                            "<Base64 encoded list of fingerprints of participants, starting with sender>"
                        ],
                        "message": private_message
                    }
                }

            else:
                # Public chat data
                public_chat_data = {
                    "data": {
                        "type": "public_chat",
                        "sender": fingerprint,
                        "message": message
                    }
                }

            # Increment the counter and send the appropriate message
            counter += 1
            chat_data_to_send = public_chat_data if not message.startswith("@") else chat_data
            signed_data = json.dumps(chat_data_to_send, separators=(',', ':'))
            signature = sign_data(private_key, signed_data + str(counter))

            chat_message = json.dumps({
                "type": "signed_data",
                "data": chat_data_to_send,
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
