Blockchat

A simple, decentralized, blockchain-based chat application. Decentralized, communal, and secure.

Features
    Decentralized Chat: Each message is stored as a block in the blockchain, ensuring immutability and transparency.
    Peer-to-Peer Communication: Nodes communicate directly with each other, without relying on a central server.
    Automatic Blockchain Synchronization: The blockchain is automatically synchronized between peers to ensure consistency.
    User Registration and Login: Users can register with a unique username and log in using a seed phrase, which generates consistent RSA keys for encryption.
    Secure Messaging: Messages are encrypted using RSA and symmetric key encryption to ensure privacy and security.
    Command Handling: Users can execute various commands to interact with the system.


Installation

Don't be a pussy, use the command prompt/terminal like a man. Press the windows key, type 'cmd' and hit enter. You'll feel like a hacker. 

Clone the repository: 
    git clone https://github.com/JBeardon88/blockchat.git
    cd blockchat

Install the required dependencies:
    pip install -r requirements.txt

Usage

Start a node:
    python node.py
Enter your username when prompted.
Connect to other nodes! Through magic I haven't figured out yet, the nodes will find each other.


Commands - lots of em don't work!

/exit: Exit the application.
/help: Display the help message.
/ping: Check the connection to peers.
/list: List all connected peers.
/blockchain: Display the latest block in the blockchain.
/history: Display the chat history.
/save: Save the current blockchain and peer list to disk.
/load: Load the blockchain and peer list from disk.
/clear: Clear the console.
/register: Register a new user with a unique username.
/login <seed_phrase>: Log in using a seed phrase.
/fullname: Display the full registered username.


How It Works

Decentralized Chat
Blockchat is a decentralized chat application that uses blockchain technology to store messages. Each message is stored as a block in the blockchain, ensuring that messages are immutable and transparent. This decentralized approach eliminates the need for a central server, making the system more resilient and secure.

Peer-to-Peer Communication
Nodes in the Blockchat network communicate directly with each other using peer-to-peer connections. This allows for direct message exchange and blockchain synchronization between nodes. Each node maintains a list of known peers and can connect to new peers to expand the network.

User Registration and Login
Users can register with a unique username, which is stored in the blockchain. During registration, a seed phrase is generated, which the user can use to log in later. The seed phrase generates consistent RSA keys for encryption, ensuring that the user's identity and messages are secure.

Secure Messaging
Messages in Blockchat are encrypted using RSA and symmetric key encryption. This ensures that only the intended recipients can read the messages, providing privacy and security for users.

Command Handling
Blockchat supports various commands that allow users to interact with the system. These commands include options to display the chat history, list connected peers, save and load the blockchain state, and more.

Conclusion
Blockchat is a simple yet powerful decentralized chat application that leverages blockchain technology to provide secure and transparent messaging. Its peer-to-peer communication and automatic blockchain synchronization ensure that the system is resilient and consistent. With features like user registration, secure messaging, and command handling, Blockchat offers a robust platform for decentralized communication.
—------------------
