### Group 5:

Members:

- Bradley Hill
- James Nguyen
- Natanand Akomsoontorn
- Vincent Scaffidi-Muta

# Current system and how to build:

Currently, our system works like this:

Launch `server.js <port>` which creates a server instance. (The port should be specified based on the agreed server ports/hosts from the admins when we run it properly)

Running a `client.js <port>` instance will generate a client with a public and private key. It will send the required 'hello' data type to the server.

The server will respond by storing the public key against a randomly generated username, AND an associated session object. 

The client then receives back that they have been accepted by the server, and are returned instructions on how to use the client to send messages.

On the initial connect, they are also sent an updated `client_list` such that they can copy the `public_key` of a client and send them a message, as required by the protocol.

# How to use

In the GUI, typing (or clicking the buttons in the GUI to copy the fingerprints to clipboard):

`to:<fingerprint> <message>`

or

`to:<fingerprint>;<fingerprint>;... <message>` if wanting to send a group message

This encrypt the message following the protocol. It will then wrap it in signed_data and send it to the server. The server will then ensure it is correctly signed (protects against replay attacks and incorrect signatures) and then blast it to every client connected to the server, as per the protocol.

Each client will then attempt to decrypt the message using their private key. If they are the intended recepient, they will successfuly decrypt the message and have it displayed in the GUI.

Typing: `public: <message>` will send a message in plaintext to the server along with the sender's fingerprint which then gets immediately broadcasted to all connected clients. They do no decryption, they simply print the message

Typing: `list` will request a new `client_list` from the server. It was not a requirement of the protocol for this to be automatic, so instead this is a manual requirement.

Typing 'quit' in the client (or just closing the client itself) will kill the client and remove it from the server client list.

# IN ORDER TO USE WITH OTHER GROUPS

We just assume the host to be 127.0.0.1 and specify ports. Simply create a new server.py file with a different hard-coded host if you wish to connect with a different IP

# Dependencies
Python Libraries:

- `cryptography:` Used for encryption, decryption, and secure key management.
- `Flask:` Utilized for handling HTTP requests in your server application.
- `werkzeug:` Used in Flask for utilities like secure_filename and safe_join.
- `multiprocessing:` For running the Flask application in a separate process from the socket server.
- `socket:` For TCP/IP communications between client and server.
- `threading:` For handling concurrent client connections on the server.
- `json:` For serialization and deserialization of data exchanged between client and server.
- `base64:` For encoding binary data into ASCII characters, which is used extensively in handling keys and encrypted messages.
- `tkinter:` For the client-side graphical user interface.
- `os:` For interacting with the operating system, such as file system operations.
- `hashlib:` For hashing operations, particularly when generating public key fingerprints.
- `queue:` For thread-safe queues that are used in managing responses in the client GUI.
- `urllib.parse:` For parsing URLs in file download operations.
- `re:` For regular expressions, used in parsing content disposition headers.
- `requests:` For making HTTP requests, used in file upload and download operations.
- `time:` Used for timing and delays.

# A note

A lot of the initial code structure was AI generated, but as this is getting more complex with classes, it's largely coded by hand. I'd say as of this commit, at least 80% of this code has been manually debugged and/or written


