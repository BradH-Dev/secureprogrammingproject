import asyncio
import websockets
import aioconsole
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

# Generate keys at startup
private_key, public_key = generate_rsa_keys()

# Function to handle receiving messages from the server
async def receive_messages(websocket):
    while True:
        try:
            message = await websocket.recv()
            print("\r" + message)
        except websockets.ConnectionClosed:
            print("[ERROR] Connection lost or terminated.")
            break

# Function to handle sending messages
async def send_messages(websocket):
    while True:
        try:
            message = await aioconsole.ainput()  # Non-blocking input
            if message:
                await websocket.send(message)
        except EOFError:
            print("Connection closed.")
            break
        except Exception as e:
            print(f"[ERROR] Exception in send_messages: {e}")

# Main function to set up and run the WebSocket client
async def main():
    uri = "ws://127.0.0.1:5555"
    
    # Connect to the WebSocket server
    async with websockets.connect(uri) as websocket:
        # Prompt the user for their username
        username = await aioconsole.ainput("Enter your username: ")
        
        # Send the username to the server
        await websocket.send(username)
        
        # After sending the username, send the public key
        await websocket.send(public_key.decode())
        
        # Start tasks for sending and receiving messages
        recv_task = asyncio.create_task(receive_messages(websocket))
        send_task = asyncio.create_task(send_messages(websocket))

        # Wait for both tasks to complete
        await asyncio.gather(recv_task, send_task)

# Run the main function
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nClient shutting down.")
