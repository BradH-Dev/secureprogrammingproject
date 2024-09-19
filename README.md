# FOR ALL TEAM MEMBERS:

**Remember we are developing from the main branch. If YOUR branch is behind main:**

***The purpose of `main` is that our best WORKING code is stored here. It is ground zero for new development.***

`git checkout main` - This moves you to the main branch

`git pull` - This grabs all new files from the main branch

`git checkout <your branch>` - This moves you back to your branch to dev your own code back inside your own branch

If a team member has pushed changes into their branch and it hasn't made it to main yet, check to make sure if a pull request needs to be made. Otherwise, just pull straight from main and carry on as normal.

# Current system:

Currently, our system works like this:

Launch server.js which creates a server instance.

Running a client.js instance will generate a client with a public and private key. It will send the required 'hello' data type to the server. (This may need to be a user manually typing 'hello' but its okay for now).

The server will respond by storing the public key against a randomly generated username. (We can likely add real usernames later?)

The client then receives back their username, and that they have been accepted by the server.

The client can then freely type to the server. The server will acknowledge from which client the message was received and print it to console. The client then also receives back from the server that it received the message.

Typing 'quit' in the client (or just closing the client itself) will kill the client and remove it from the server client list.

TO-DO: 
- Ensure that the counter for each client increments
- Send a message between two clients on the local server

Then later
- Set up the client list broadcast feature for other servers
