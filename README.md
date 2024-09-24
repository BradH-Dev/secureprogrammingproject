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

Launch server.js which creates a server instance.

Running a client.js instance will generate a client with a public and private key. It will send the required 'hello' data type to the server. (This may need to be a user manually typing 'hello' but its okay for now).

The server will respond by storing the public key against a randomly generated username, AND an associated session object. 

The client then receives back their username, and that they have been accepted by the server.

# How to use

In the GUI, typing:

`to: <username> <message>`

This will contact the server and request the username's public key (we may need to change this such that we just KNOW the recipient's public key). Using the received recipient's public key, it will encrypt the message following the protocol. It will then wrap it in signed_data and send it to the server. The server will then ensure it is correctly signed (protects against replay attacks and incorrect signatures) and then blast it to every client connected to the server, as per the protocol.

Each client will then attempt to decrypt the message using their private key. If they are the intended recepient, they will successfuly decrypt the message and have it displayed in the GUI.

Typing 'quit' in the client (or just closing the client itself) will kill the client and remove it from the server client list.

TO-DO: 
- Add the ability to just send broadcast plaintext messages
- Potentially add the ability to see who sent the message? The protocol does not mention this.
- Create server to server communication and thus actually use the "destination_servers" part of the `chat` protocol (this can be done on the same network for debugging purposes by using different ports)

# A note

A lot of the initial code structure was AI generated, but as this is getting more complex with classes, it's largely coded by hand

