import json
import socket
import os
import threading
import base64
import tkinter as tk
from tkinter import scrolledtext, filedialog
import hashlib
import requests 

from queue import Queue
from urllib.parse import urlparse
import re

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
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()  # Use AES block size for padding

    # Check if plaintext is already bytes, if not, encode it
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode()

    padded_message = padder.update(plaintext) + padder.finalize()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(encrypted_message).decode()

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

def add_base64_padding(base64_string):
    """Ensure base64 string is properly padded with '=' characters."""
    return base64_string + '=' * (-len(base64_string) % 4)

def decrypt_message(encrypted_message, aes_key, iv):
    try:
        # Add padding to the encrypted message if needed
        encrypted_message = add_base64_padding(encrypted_message)
        
        print("Decrypting Message:", encrypted_message)  # Debug: Check the encrypted message before decoding
        
        # Proceed with decryption
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(base64.b64decode(encrypted_message)) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_message = unpadder.update(decrypted_data) + unpadder.finalize()
        
        print("Decrypted Message:", decrypted_message.decode('utf-8'))  # Debug: Check the output after decryption
        return decrypted_message.decode('utf-8')
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return None

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


def compute_fingerprint(public_key_pem):
    # Compute SHA-256 hash on the exported PEM format of the public key
    hasher = hashlib.sha256()
    hasher.update(public_key_pem.encode())
    # Return the Base64 encoded version of the hash
    return base64.b64encode(hasher.digest()).decode('utf-8')

class ChatClient:

    def __init__(self, master, server_ip, port):
        self.fingerprint_window = None 
        self.fingerprint_to_public_key = {}
        pem, self.private_key = generate_keys()
        self.public_key_exported = base64.b64encode(pem).decode()
        # Compute the client's public key fingerprint
        self_public_key_fingerprint = compute_fingerprint(self.public_key_exported)
        
        # Set the window title to the fingerprint of the client
        self.master = master
        self.master.title("Chat Client")
        
        self.text_area = scrolledtext.ScrolledText(master, state='disabled')
        self.text_area.grid(column=0, row=0, columnspan=3)
        
        self.msg_entry = tk.Entry(master, width=50)
        self.msg_entry.grid(column=0, row=1)
        
        self.send_button = tk.Button(master, text="Send", command=self.send)
        self.send_button.grid(column=1, row=1)
        
        self.upload_button = tk.Button(master, text="Upload File", command=self.upload_file)
        self.upload_button.grid(column=2, row=1)

        self.download_button = tk.Button(master, text="Download File", command=self.download_file)
        self.download_button.grid(column=3, row=1)
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((server_ip, port))


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


        client_request = json.dumps({
            "type": "client_list_request",
        })

        send_message(self.sock, client_request)
        self.counter += 1

        self.response_queue = Queue()
        self.thread = threading.Thread(target=client_thread, args=(self.sock, self, self.response_queue))
        self.thread.daemon = True
        self.thread.start()
        self.master.after(100, self.process_responses)
        self.pending_messages = {}

    

    def create_fingerprint_window(self, clients):
        # If a window already exists, destroy it
        if self.fingerprint_window is not None:
            self.fingerprint_window.destroy()

        # Create a new window
        self.fingerprint_window = tk.Toplevel(self.master)
        self.fingerprint_window.title("Public Key Fingerprints")

        # Add fingerprints to the new window
        for client in clients:
            fingerprint = compute_fingerprint(client['public_key'])
            button = tk.Button(self.fingerprint_window, text=fingerprint, command=lambda fp=fingerprint: self.copy_to_clipboard(fp))
            button.pack()

    def copy_to_clipboard(self, text):
        self.master.clipboard_clear()
        self.master.clipboard_append(text)
        self.master.update()  # Now it stays on the clipboard after the window is closed


    def upload_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            files = {'file': open(filepath, 'rb')}
            response = requests.post(f"http://127.0.0.1:5000/api/upload", files=files)
            if response.ok:
                file_url = response.json().get('file_url')
                self.display_message(f"File uploaded successfully: {file_url}")
            else:
                self.display_message("Failed to upload file.")

    def download_file(self):
        url = self.msg_entry.get()
        if url:
            try:
                response = requests.get(url, stream=True)
                if response.status_code == 200:
                    # Attempt to extract filename from the Content-Disposition header
                    content_disposition = response.headers.get('content-disposition')
                    if content_disposition:
                        filename = re.findall('filename="(.+)"', content_disposition)
                        if filename:
                            filename = filename[0]
                        else:
                            # Fall back to extracting from URL
                            filename = os.path.basename(urlparse(url).path)
                    else:
                        filename = os.path.basename(urlparse(url).path)
                    
                    path = filedialog.asksaveasfilename(defaultextension=os.path.splitext(filename)[1], filetypes=[("All files", "*.*")], initialfile=filename)
                    if path:
                        with open(path, 'wb') as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                f.write(chunk)
                        self.display_message(f"File downloaded successfully: {path}")
                else:
                    self.display_message("Failed to download file. Server responded with error.")
            except Exception as e:
                self.display_message(f"Error downloading file: {e}")

    # FUNCTION FOR ALL CLIENTS ongoing which allows them to RECEIVE messages regardless of their current typing/chat
    def process_responses(self):
        while not self.response_queue.empty():
            response = self.response_queue.get()

            try:
                response_data = json.loads(response)
                print(response_data)
                    
                if response_data['type'] == 'client_list':
                    servers = response_data['servers']
                    all_clients = []  # Prepare a list to hold all clients across servers
                    for server in servers:
                        server_address = server['address']
                        clients = server['clients']
                        for client_public_key in clients:
                            fingerprint = compute_fingerprint(client_public_key)
                            self.fingerprint_to_public_key[fingerprint] = {
                                'public_key': client_public_key,
                                'server_address': server_address
                            }
                            all_clients.append({'public_key': client_public_key, 'fingerprint': fingerprint})

                    # Update the GUI with the list of all clients
                    self.create_fingerprint_window(all_clients)
             
                if 'data' in response_data:  # Check if 'data' key is present
                    # Check if 'data' needs to be parsed or is already a dictionary
                    if isinstance(response_data['data'], str):
                        inner_data = json.loads(response_data['data'])  # Parse the inner JSON string
                    else:
                        inner_data = response_data['data']  # Use as is, already a dictionary

                    print("Inner Data:", inner_data)
                    
                    #### RECEIVING CHATS BELOW HERE! This is where a client is being sent a chat directly from the server
                    #### They must try to decrypt it in order to determine if they are the recipient.
                    if inner_data['type'] == 'chat':
                        aes_key = None  # Will store the successfully decrypted AES key
                        for encrypted_key in inner_data['symm_keys']:  # Iterate over all symmetric keys
                            aes_key = decrypt_aes_key(encrypted_key, self.private_key)
                            if aes_key:  # If we successfully decrypt the key, break the loop
                                break

                        if aes_key:  # If decryption of any AES key was successful
                            iv = base64.b64decode(inner_data['iv'])  # Decode IV from base64
                            encrypted_message = inner_data['chat']  # Encrypted message

                            # Decrypt the message using the decrypted AES key and IV
                            decrypted_chat_b64 = decrypt_message(encrypted_message, aes_key, iv)
                            if decrypted_chat_b64:
                                decrypted_chat_json = decrypted_chat_b64  # Already a string
                                chat_info = json.loads(decrypted_chat_json)

                                # Extract the sender fingerprint and message body
                                sender_fingerprint = chat_info['participants'][0]
                                msg_body = chat_info['message']

                                client_fingerprint = compute_fingerprint(self.public_key_exported)
                                # Filter out the client's own fingerprint from the participant list
                                recipients = [fp for fp in chat_info['participants'] if fp != client_fingerprint]
                                # Build the display message
                                if len(recipients) > 1:
                                    recipients_list = ', '.join(recipients)
                                    display_message = f"Message received from: {sender_fingerprint}\n{msg_body}\n(Sent to: You, {recipients_list})"
                                else:
                                    display_message = f"Message received from: {sender_fingerprint}\n{msg_body}"
                                
                                # Display the formatted message
                                self.display_message(display_message)
                                print(display_message)
                            else:
                                print("Failed to decrypt the message.") # Just for debug
                        else: 
                            print("Failed to decrypt any AES key.")# Just for debug

                    #### RECEIVING PUBLIC CHATS! Every client should just immediately display it. 
                    # We however need to request the username of the client by using the public key
                    if inner_data['type'] == 'public_chat':
                        message = inner_data['message']
                        sender_fingerprint = inner_data['sender']  # Retrieve the sender's fingerprint
                        chat_message = f"PUBLIC MESSAGE RECEIVED FROM: {sender_fingerprint}\nPUBLIC MESSAGE CONTENT: {message}"
                        self.display_message(chat_message)
                        print(chat_message)


            except json.JSONDecodeError:
                self.display_message(response)
        self.master.after(100, self.process_responses)

    def send(self):
        message = self.msg_entry.get()


        if message.startswith("to:"):
            # Extract the recipient fingerprints and message body
            recipients_and_body = message[3:].strip()  # Skip the "to:" prefix
            recipient_info, msg_body = recipients_and_body.split(' ', 1)

            # Split multiple recipient entries by ';'
            recipient_entries = recipient_info.split(';')
            
            symm_keys = []  # To store encrypted AES keys for each recipient
            participants = []  # To store fingerprints of participants
            destination_servers = []  # To store server addresses

            aes_key, iv = generate_aes_key_and_iv()  # Generate AES key and IV for this message

            for recipient_fingerprint in recipient_entries:
                # Retrieve recipient public key and server address using the fingerprint
                recipient_info = self.fingerprint_to_public_key.get(recipient_fingerprint)
                if recipient_info is None:
                    print(f"Information for the given fingerprint {recipient_fingerprint} not found.")
                    self.display_message(f"Information for the given fingerprint {recipient_fingerprint} not found.")
                    return

                recipient_public_key = load_public_key_from_string(recipient_info['public_key'])
                if recipient_public_key is None:
                    print(f"Invalid public key for fingerprint {recipient_fingerprint}.")
                    self.display_message(f"Invalid public key for fingerprint {recipient_fingerprint}.")
                    return

                # Encrypt AES key for this recipient
                encrypted_key = encrypt_aes_key(aes_key, recipient_public_key)
                symm_keys.append(encrypted_key)  # Add the encrypted AES key to the list

                # Add recipient's fingerprint and server address to participants and servers
                participants.append(recipient_fingerprint)
                destination_servers.append(recipient_info['server_address'])

            # Add sender's fingerprint to participants
            self_public_key_fingerprint = compute_fingerprint(self.public_key_exported)
            participants.insert(0, self_public_key_fingerprint)  # Add the sender's fingerprint as the first participant

            # Prepare chat message info
            chat_info = {
                "participants": participants,
                "message": msg_body
            }
            chat_info_json = json.dumps(chat_info).encode()  # Ensure it's encoded to bytes
            chat_info_encrypted = encrypt_message(aes_key, iv, chat_info_json)  # This should return a base64 encoded string

            # Prepare data to send
            data = {
                "type": "chat",
                "destination_servers": destination_servers,  # List of destination servers
                "iv": iv,  # Already base64 encoded
                "symm_keys": symm_keys,  # Multiple encrypted AES keys
                "chat": chat_info_encrypted  # Already base64 encoded
            }

            # Sign the data and send
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

        #### REQUEST CLIENT LIST
        if message.startswith("list"):
            chat_message = json.dumps({
                "type": "client_list_request",
            })

            send_message(self.sock, chat_message)
            self.counter += 1

        #### SEND PUBLIC CHAT
        if message.startswith("public:"):
            msg_body = message[len("public: "):]

            # Get the fingerprint of the sender's public key
            self_public_key_fingerprint = compute_fingerprint(self.public_key_exported)

            data = {
                "type": "public_chat",
                "sender": self_public_key_fingerprint,  # Include sender fingerprint
                "message": msg_body
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
