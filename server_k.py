import asyncio
import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# List to keep track of connected clients and their public keys
clients = {}      # {username: websocket}
usernames = {}    # {websocket: username}
public_keys = {}  # {username: public_key}

# Function to handle communication with a single client
async def handle_client(websocket, path):
    print(f"[NEW CONNECTION] {websocket.remote_address} connected.")
    
    # Ask the client to provide a username
    username = await websocket.recv()

    # Check for duplicate
    if username in clients:
        # Send a message to the client informing about the duplicate username
        await websocket.send(f"Username '{username}' is already taken. Connection will be closed.")
        
        # Forcibly close the connection after informing the client
        await websocket.close()
        print(f"[DISCONNECT] {websocket.remote_address} disconnected due to duplicate username.")
        return  # Stop processing for this client
    
    # Ask the client to provide their public key
    public_key_pem = await websocket.recv()  # Receive public key as a string
    
    # Load the public key from PEM format
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),  # Convert string to bytes
            backend=default_backend()
        )
        # Store the client's username, socket, and public key
        clients[username] = websocket
        usernames[websocket] = username
        public_keys[username] = public_key
        print(f"Stored public key for {username}.")
    except ValueError as e:
        print(f"[ERROR] Invalid public key format: {e}")
        await websocket.close()
        return

    try:
        async for message in websocket:
            # Check if the message is a private message
            if message.startswith("@"):
                recipient, private_message = parse_private_message(message)
                if recipient in clients:
                    # Encrypt the private message here (future step)
                    await clients[recipient].send(f"Private message from {username}: {private_message}")
                else:
                    await websocket.send(f"User {recipient} not found.")
            else:
                # Format the message before broadcasting
                formatted_message = f"From {username}: {message}"
                # Broadcast received message to all clients except the sender
                await broadcast_message(formatted_message, websocket)
    except websockets.ConnectionClosed:
        print(f"[ERROR] Connection closed with {websocket.remote_address}.")
    finally:
        clients.pop(username, None)
        usernames.pop(websocket, None)
        public_keys.pop(username, None)
        print(f"[DISCONNECT] {websocket.remote_address} disconnected.")

# Function to parse private messages
def parse_private_message(message):
    parts = message.split(' ', 1)  # Split once to keep full message intact
    recipient = parts[0][1:]  # Remove '@' from recipient's name
    private_message = parts[1] if len(parts) > 1 else ""
    return recipient, private_message

# Function to broadcast messages to all connected clients except the sender
async def broadcast_message(message, sender_socket):
    sender_username = usernames.get(sender_socket, None)
    for client_username, client_socket in clients.items():
        if client_socket != sender_socket:
            try:
                await client_socket.send(message)
            except websockets.ConnectionClosed:
                print(f"[ERROR] Could not send to {client_username}, closing connection.")
                del clients[client_username]

# Set up WebSocket server
async def start_server():
    print("[STARTING] Server is listening on ws://0.0.0.0:5555")
    async with websockets.serve(handle_client, "0.0.0.0", 5555):
        await asyncio.Future()  # Run server forever

# Main loop
if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        print("\n[SHUTTING DOWN] Server is closing.")
