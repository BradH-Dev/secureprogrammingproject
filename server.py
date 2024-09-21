import socket
import threading
import json

client_counters = {}
client_usernames = {}   # {'username':('IP', PORT)}
client_public_keys = {} # {'username':public key}

# Function to handle client connections
def client_handler(conn, addr):
    conn.send("Enter your username: ".encode())  # Send username prompt
    username = conn.recv(1024).decode().strip()  # Receive the username from the client
    print(f"{addr} provided username: {username}")

    if username in client_usernames:
        print(f"{addr} provided duplicate username: {username}")
        conn.send("Username already taken. Closing connection. Exiting program".encode())
        conn.close()  # Close the connection if the username is taken
        return
    
    # Associate the username with the connection
    client_usernames[username] = addr
    client_counters[username] = 0  # Initialize the counter for this client

    print(f"Client {username} connected from {addr}")
    conn.send(f"Welcome, {username}!".encode())

    print(client_usernames)

    buffer = ""
    while True:
        chunk = conn.recv(1024).decode()
        if not chunk:
            break
        buffer += chunk

        while True:
            # Attempt to parse JSON from the buffer
            try:
                data = json.loads(buffer)
                # If successful, handle the data
                client_counter = data.get('counter')
                message_type = data.get('type')
                break  # Exit if parsing was successful
            except json.JSONDecodeError:
                # If parsing fails, wait for more data
                break  # Exit the while loop to receive more data

        # After successfully parsing
        if 'data' in locals():  # Check if data was successfully parsed
            last_counter = client_counters.get(username, 0)

            if client_counter > last_counter:
                client_counters[username] = client_counter
                if message_type == "signed_data":
                    process_signed_data(data, conn, username)
                else:
                    print(f"Unknown message type from {username}.")
                    conn.send("Invalid message type.".encode())
            else:
                print(f"Counter not greater than last from: {username}.")
                conn.send("Invalid counter.".encode())

            # Reset the buffer after processing a message
            buffer = buffer[buffer.index(chunk) + len(chunk):]  # Remove the processed part

    # Client disconnected
    print(f"Client {username} from {addr} disconnected.")
    del client_usernames[addr]
    del client_counters[username]
    conn.close()

def process_signed_data(data, conn, username):
    # Extract the relevant data
    inner_data = data.get('data', {}).get('data', {})
    data_type = inner_data.get('type')

    # Handle the hello message
    if data_type == "hello":
        # print(f"Received hello from {username}: {inner_data['public_key']}")
        client_public_keys[username] = inner_data['public_key']
        conn.send("Hello message received.".encode())

    # Handle chat messages
    elif data_type == "chat":
        chat_message = inner_data.get('chat')
        print(f"Received chat message from {username}: {chat_message}")
        response_message = "Chat message received."
        conn.send(response_message.encode())
    else:
        print(f"Invalid message format from {username}.")
        conn.send("Invalid message format.".encode())

# Start the server on a specified port and IP
def start_server(port):
    host = '127.0.0.1'
    server_address = (host, port)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_address)
    server_socket.listen(5)
    print(f"Server started and listening on port {port}")

    while True:
        # Accept new connections
        conn, addr = server_socket.accept()
        print(f"Client connected from {addr}")
        thread = threading.Thread(target=client_handler, args=(conn, addr))
        thread.start()

# Main entry point of the script
if __name__ == "__main__":
    start_server(12345)
