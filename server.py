import socket
import threading

# Function to handle client connections
def client_handler(conn, server_address):
    while True:
        # Receive a message from the client
        message = conn.recv(1024).decode()
        # If no message, break the loop and close the connection
        if not message:
            break
        
        # Output the received message on the server console
        print(f"This server received message: {message}")
        # Extract parts of the message
        sender, receiver, body = parse_message(message)
        # Validate the message format
        if validate_message(sender, receiver, body):
            # Route the message if valid
            route_message(conn, sender, receiver, body, server_address)
        else:
            # If invalid, notify the sender I guess
            print("Invalid message received.")
            conn.send("Invalid message format.".encode())

    # Close the connection when done
    conn.close()

# Parse the message into sender, receiver, and body
def parse_message(message):
    parts = message.split(':')
    return parts[0], parts[1], parts[2]

# Validate the parts of the message
def validate_message(sender, receiver, body):
    return len(sender) > 0 and len(receiver) > 0 and len(body) > 0

# Route the message and send a confirmation back to the sender
def route_message(conn, sender, receiver, body, server_address):
    print(f"Routing message from {sender} to {receiver}: {body}")
    response_message = f"Message successfully routed from {sender} to {receiver}."
    conn.send(response_message.encode())

# Start the server on a specified port and ip
def start_server(port):
    host = '127.0.0.1'
    server_address = (host, port)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the server address
    server_socket.bind(server_address)
    # Start listening for client connections
    server_socket.listen(5)
    print(f"Server started and listening on on port {port}")

    while True:
        # Accept new connections
        conn, addr = server_socket.accept()
        print(f"Client connected at {addr}")
        # Start a new thread to handle the client
        thread = threading.Thread(target=client_handler, args=(conn, server_address))
        thread.start()

# Main entry point of the script, just using any old port
if __name__ == "__main__":
    start_server(12345)
