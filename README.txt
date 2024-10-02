Group 5:

Members:

    Bradley Hill
    James Nguyen
    Natanand Akomsoontorn
    Vincent Scaffidi-Muta

========================================================================================================

How to use:
Before use please use:
	sudo apt-get install python3-tk
	pip install flask

In the directory where server.py and client.py are located, open terminals. 

To run a server:	
	python3 server.py <server_port> <flask_port>
		eg. python3 server.py 12345 5555

To run a client:
	python3 client.py <server_ip> <port> <flask_port>
		eg. python3 client.py 127.0.0.1 12345 5555
		

You can run multiple servers and clients by opening new terminals in the directory.

In the client window UI:
	If you have multiple clients running:
		Type "list" and press send to update the fingerprint list window of other clients if they do not show up

	(You can copy a fingerprint from the fingerprint window by clicking on one (it will copy to clipboard))

	To send a PRIVATE MESSAGE:
		Type "to: <fingerprint> <message>"
			eg. "to: AEIWEPQ3256324=- Hello

	To send a GROUP MESSAGE:
		Type "to: <fingerprint>;<fingerprint>;... <message>"
			eg. "to: AEIWEPQ3256324=-;SDIOJSOIDV=- Hello group members

	To send a PUBLIC MESSAGE:
		Type "public: <message>"
			eg. "public: Hello everyone"

	To UPLOAD A FILE
		1. Press the "Upload File" button
		2. Select the file you wish to upload from the file browser popup
		3. A URL will be displayed on successful file upload

	To DOWNLOAD A FILE:
		1. In the same client or different client copy the URL displayed after a successful file upload into the message field
			(May have to manually type the URL)
		2. Press the "Download File" button
		3. Select where you want to save the file in the file browser popup	

	To QUIT:
		1. Type "quit"
		2. Press "Send"


========================================================================================================

NOTES:
Right now starting multiple servers is hard coded to be on IP 127.0.0.1. But starting servers on different ports is still possible by passing a different port as well as a different flask port as an argument when launching the server.py for each new server.

Clients can connect to different servers on different ports and fingerprints can be updated and displayed using the "list" command.
Chatting and file transfers are possible.
There is an issue when a client on a different server disconnects but their fingerprint still remains on the list. (This is unfinnished part of the code)

=========================================================================================================

Dependencies

Python Libraries:

    cryptography: 		Used for encryption, decryption, and secure key management.
    Flask: 			Utilized for handling HTTP requests in your server application.
    werkzeug: 			Used in Flask for utilities like secure_filename and safe_join.
    multiprocessing:		For running the Flask application in a separate process from the socket server.
    socket: 			For TCP/IP communications between client and server.
    threading: 			For handling concurrent client connections on the server.
    json: 			For serialization and deserialization of data exchanged between client and server.
    base64: 			For encoding binary data into ASCII characters, which is used extensively in handling keys and encrypted messages.
    tkinter: 			For the client-side graphical user interface.
    os: 			For interacting with the operating system, such as file system operations.
    hashlib: 			For hashing operations, particularly when generating public key fingerprints.
    queue: 			For thread-safe queues that are used in managing responses in the client GUI.
    urllib.parse: 		For parsing URLs in file download operations.
    re: 			For regular expressions, used in parsing content disposition headers.
    requests: 			For making HTTP requests, used in file upload and download operations.
    time: 			Used for timing and delays.
