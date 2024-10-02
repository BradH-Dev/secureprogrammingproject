# FOR ALL TEAM MEMBERS:

***The purpose of `main` is that our best WORKING code is stored here. It is ground zero for new development.***

**Thus, remember we are developing from the main branch. If YOUR branch is behind main:**

`git checkout main` - This moves you to the main branch

`git pull` - This grabs all new files from the main branch

`git checkout <your branch>` - This moves you back to your branch to dev your own code back inside your own branch

If a team member has pushed changes into their branch and it hasn't made it to main yet, check to make sure if a pull request needs to be made. Otherwise, just pull straight from main and carry on as normal - their code wasn't ready for `main` yet

# Really important stuff to note

OUR client implementation does not matter so long as servers can talk to each other! As long as our chats are packaged up correctly and sent to the server and that our server can forward these on to OTHER servers, everything will be interoperable.

# Current system:

Currently, our system works like this:

Launch server.js <port> which creates a server instance.

Running a client.js instance will generate a client with a public and private key. It will send the required 'hello' data type to the server. (This may need to be a user manually typing 'hello' but its okay for now).

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

Typing: `list` will request a new `client_list` from the server. (We MAY need to add the ability that this is broadcast to all users when a new client connects).

Typing 'quit' in the client (or just closing the client itself) will kill the client and remove it from the server client list.

TO-DO: 
- Tidy up code
- Make it so file uploads can work across ports (they dont need to be cross server, but if a client is connected to a particular server, they need to be able to upload to THAT server)
- Remove dead clients from servers
- Quickly look at when receiving group chats in the client, the sender's name can sometimes appear

# A note

A lot of the initial code structure was AI generated, but as this is getting more complex with classes, it's largely coded by hand. I'd say as of this commit, at least 80% of this code has been manually debugged and/or written


