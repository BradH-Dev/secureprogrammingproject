import json
import socket
import os
import threading
import base64
import tkinter as tk
from tkinter import scrolledtext

from queue import Queue

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


#### ENCRYPTION ####

def load_public_key_from_string(pem_str):
    try:
        pem_data = base64.b64decode(pem_str)
        public_key = load_pem_public_key(pem_data, backend=default_backend())
        return public_key
    except Exception as e:
        print(f"Failed to load public key: {e}")
        return None

def encrypt_aes_key(aes_key, recipient_public_key):
    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Encoded and encrypted AES key:", encrypted_key)
    return base64.b64encode(encrypted_key).decode()


def generate_aes_key_and_iv():
    aes_key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)       # AES block size for CBC mode
    return aes_key, base64.b64encode(iv).decode()

def encrypt_message(aes_key, iv, plaintext):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(base64.b64decode(iv)), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = plaintext + (16 - len(plaintext) % 16) * chr(16 - len(plaintext) % 16)  # PKCS#7 padding
    encrypted_message = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return base64.b64encode(encrypted_message).decode()

def fingerprint(public_key):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(public_key)
    return base64.b64encode(digest.finalize()).decode()

#### DECRYPTION ####

def decrypt_aes_key(encrypted_key, private_key):
    try:
        decoded_key = base64.b64decode(encrypted_key)
        decrypted_key = private_key.decrypt(
            decoded_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )
        return decrypted_key
    except Exception as e:
        print(f"Error decrypting AES key: {e}")
        return None

def decrypt_message(encrypted_message, aes_key, iv):
    try:
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(base64.b64decode(iv)), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(base64.b64decode(encrypted_message)) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()  # 128 bit = 16 byte block size for AES
        decrypted_message = unpadder.update(decrypted_data) + unpadder.finalize()
        return decrypted_message.decode('utf-8')
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return None

def verify_participant(fingerprint, public_key):
    my_fingerprint = base64.b64encode(SHA256().finalize(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))).decode()
    return my_fingerprint in fingerprint



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

def client_thread(sock, gui, response_queue):
    while True:
        try:
            response = sock.recv(4096).decode()
            if response:
                response_queue.put(response)
            else:
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def send_message(sock, data):
    formatted_data = f"{data}\n"
    sock.sendall(formatted_data.encode())

class ChatClient:
    def __init__(self, master, server_ip, port):
        self.master = master
        self.master.title("Chat Client")
        self.text_area = scrolledtext.ScrolledText(master, state='disabled')
        self.text_area.grid(column=0, row=0, columnspan=2)
        self.msg_entry = tk.Entry(master, width=50)
        self.msg_entry.grid(column=0, row=1)
        self.send_button = tk.Button(master, text="Send", command=self.send)
        self.send_button.grid(column=1, row=1)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((server_ip, port))
        pem, self.private_key = generate_keys()
        self.public_key_exported = base64.b64encode(pem).decode()
        self.counter = 1
        data = {
            "type": "hello",
            "public_key": self.public_key_exported
        }
        signed_data = json.dumps(data, separators=(',', ':'))
        signature = sign_data(self.private_key, signed_data + str(self.counter))
        initial_message = json.dumps({
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature
        })
        send_message(self.sock, initial_message)
        self.counter += 1
        self.response_queue = Queue()
        self.thread = threading.Thread(target=client_thread, args=(self.sock, self, self.response_queue))
        self.thread.daemon = True
        self.thread.start()
        self.master.after(100, self.process_responses)
        self.pending_messages = {}

    def process_responses(self):
        while not self.response_queue.empty():
            response = self.response_queue.get()
            
            
            try:
                response_data = json.loads(response)
                print(response_data)
                    
                # Check if 'data' needs to be parsed or is already a dictionary
                if isinstance(response_data['data'], str):
                    inner_data = json.loads(response_data['data'])  # Parse the inner JSON string
                else:
                    inner_data = response_data['data']  # Use as is, already a dictionary

                print("Inner Data:", inner_data)
                
                if inner_data['type'] == 'fetch_key':
                    username = inner_data.get('username')
                    if username in self.pending_messages:
                        print("Processing fetch_key for user:", username)
                    message, msg_body = self.pending_messages.pop(username)
                    
        
                    # Load the public key from the string
                    recipient_public_key_str = inner_data["public_key"]
                    recipient_public_key = load_public_key_from_string(recipient_public_key_str)

                    if recipient_public_key is None:
                        print("Invalid public key received, unable to encrypt message.")
                        return

                    aes_key, iv = generate_aes_key_and_iv()
                    encrypted_message = encrypt_message(aes_key, iv, msg_body)
                    encrypted_key = encrypt_aes_key(aes_key, recipient_public_key)
                    
                    data = {
                        "type": "chat",
                        "destination_servers": ["127.0.0.1"],
                        "iv": iv,
                        "symm_keys": [encrypted_key],
                        "chat": encrypted_message
                    }

                    signed_data = json.dumps(data, separators=(',', ':'))
                    signature = sign_data(self.private_key, signed_data + str(self.counter))

                    chat_message = json.dumps({
                        "type": "signed_data",
                        "data": data,
                        "counter": self.counter,
                        "signature": signature
                    })
                    
                    send_message(self.sock, chat_message)
                    self.counter += 1

                # Assuming 'inner_data' comes decrypted and contains keys 'iv', 'symm_keys', 'chat'
                if inner_data['type'] == 'chat':
                    encrypted_key = inner_data['symm_keys'][0]  # Assume first key is for this recipient
                    aes_key = decrypt_aes_key(encrypted_key, self.private_key)
                    if aes_key:
                        iv = inner_data['iv']
                        encrypted_message = inner_data['chat']
                        decrypted_chat = decrypt_message(encrypted_message, aes_key, iv)
                        if decrypted_chat:
                            chat_message = f"Message received: {decrypted_chat}"
                            self.display_message(chat_message)
                            print(chat_message)
                        else:
                            print("Failed to decrypt the message.")
                    else:
                        print("Failed to decrypt AES key.")

            except json.JSONDecodeError:
                self.display_message(response)
        self.master.after(100, self.process_responses)

    def send(self):
        message = self.msg_entry.get()
        if message.startswith("to:"):
            _, username, msg_body = message.split(" ", 2)
            self.pending_messages[username] = (message, msg_body)
            data = {
                "type": "fetch_key",
                "username": username
            }
            
            signed_data = json.dumps(data, separators=(',', ':'))
            signature = sign_data(self.private_key, signed_data + str(self.counter))
            msg = json.dumps({
                "type": "signed_data",
                "data": data,
                "counter": self.counter,
                "signature": signature
            })
            
            send_message(self.sock, msg)
            self.counter += 1
        elif message.lower() == "quit":
            send_message(self.sock, message)
            self.sock.close()
            self.master.quit()
            return
        self.msg_entry.delete(0, tk.END)

    def display_message(self, message):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, message + '\n')
        self.text_area.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root, '127.0.0.1', 12345)
    root.mainloop()
