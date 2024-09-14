import socket

# Function to send a message to a server and receive a response
def send_message(server_ip, port, message):
    # Create a socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_ip, port))
        print(f"Attempting to send: {message}")
        sock.sendall(message.encode())
        # Receive the response from the server
        response = sock.recv(1024)
        # Print the response received from the server and kill itt
        print(f"Received back from server: {response.decode()}")
        return 0

# Just a test main to pign server
if __name__ == "__main__":
    server_ip = '127.0.0.1'
    port = 12345
    message = 'client1:server1:Hello, Server!'
    send_message(server_ip, port, message)
