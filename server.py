import socket
import threading
import json

client_counters = {}

# Function to handle client connections
def client_handler(conn, server_address):
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
            last_counter = client_counters.get(server_address, 0)

            if client_counter > last_counter:
                client_counters[server_address] = client_counter
                if message_type == "signed_data":
                    process_signed_data(data, conn, server_address)
                else:
                    print(f"Unknown message type: {message_type}")
                    conn.send("Invalid message type.".encode())
            else:
                print(f"Counter not greater than last from: {server_address}.")
                conn.send("Invalid counter.".encode())

            # Reset the buffer after processing a message
            buffer = buffer[buffer.index(chunk) + len(chunk):]  # Remove the processed part

    conn.close()  # Close connection on exit

def process_signed_data(data, conn, server_address):
    # Extract the relevant data
    inner_data = data.get('data', {}).get('data', {})
    data_type = inner_data.get('type')

    # Handle the hello message
    if data_type == "hello":
        print(f"Received hello from {server_address}: {inner_data['public_key']}")
        conn.send("Hello message received.".encode())

    # Handle chat messages
    elif data_type == "chat":
        # Process the chat message
        chat_message = inner_data.get('chat')
        print(f"Received chat message from {server_address}: {chat_message}")
        # Here, you would typically route the message to its intended recipients

        response_message = "Chat message received."
        conn.send(response_message.encode())
    else:
        print("Invalid message format.")
        conn.send("Invalid message format.".encode())

    print(client_counters)

# Start the server on a specified port and ip
def start_server(port):
    host = '127.0.0.1'
    server_address = (host, port)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the server address
    server_socket.bind(server_address)
    # Start listening for client connections
    server_socket.listen(5)
    print(f"Server started and listening on port {port}")

    while True:
        # Accept new connections
        conn, addr = server_socket.accept()
        print(f"Client connected at {addr}")
        # Start a new thread to handle the client
        thread = threading.Thread(target=client_handler, args=(conn, server_address))
        thread.start()

# Main entry point of the script
if __name__ == "__main__":
    start_server(12345)
