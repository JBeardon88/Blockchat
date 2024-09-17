
import socket
import threading
import json
import time
import os
from blockchain import Blockchain, Block
import uuid
import struct
from display import display_help, display_chat_history, display_new_block, display_latest_block, display_constitution
from commands import handle_command
from config import KNOWN_PEERS, SYNC_INTERVAL
from network import send_to_peer, receive_from_peer, recvall, get_peer_addr
from encryption import encrypt_message, decrypt_message, generate_rsa_key_pair, encrypt_key_with_rsa, decrypt_key_with_rsa, decrypt_private_message
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from mnemonic import Mnemonic
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hashlib



class Node:
    def __init__(self, host, port, username):
        self.host = host
        self.port = port
        self.username = username
        self.registered_username = None
        self.blockchain = Blockchain()
        self.peers = {}
        self.running = True
        self.lock = threading.Lock()
        self.chat_history = []
        self.server_thread = threading.Thread(target=self.run_server)
        self.server_thread.daemon = True
        self.processed_messages = set()
        self.sync_lock = threading.Lock()
        self.last_sync_time = time.time()
        self.sync_interval = SYNC_INTERVAL
        self.handshake_lock = threading.Lock()
        self.handshake_completed = set()
        self.display_constitution()
        self.peer_threads = []

        # Generate RSA key pair
        self.private_key, self.public_key = generate_rsa_key_pair()
        # - it used to be this instead of the below - self.symmetric_key = None
        self.symmetric_key = None  # Generate a default symmetric key
        self.recipient_symmetric_keys = {}   # Dictionary to store keys for private messages
        self.private_message_keys = {}
        self.last_private_message_sender = None

    def start(self):
        self.server_thread.start()
        self.connect_to_network()
        self.handle_user_input()

    def run_server(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((self.host, self.port))
        server_sock.listen(5)
        self.server_sock = server_sock
        print(f"Listening on {self.host}:{self.port}")

        while self.running:
            try:
                client_sock, addr = server_sock.accept()
                print(f"Accepted connection from {addr}")
                self.peers[addr] = client_sock
                peer_thread = threading.Thread(target=self.handle_peer, args=(client_sock, addr))
                peer_thread.start()
                self.peer_threads.append(peer_thread)
            except socket.error:
                break

    def connect_to_network(self):
        for peer in KNOWN_PEERS:
            if peer != (self.host, self.port):
                self.connect_to_peer(peer[0], peer[1])

    def connect_to_peer(self, host, port):
        if (host, port) in self.peers:
            print(f"\033[93mAlready connected to peer {host}:{port}\033[0m")
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            self.peers[(host, port)] = sock
            print(f"\033[92mConnected to peer {host}:{port}\033[0m")
            self.initiate_handshake(sock, (host, port))
            peer_thread = threading.Thread(target=self.handle_peer, args=(sock, (host, port)))
            peer_thread.start()
            self.peer_threads.append(peer_thread)
            return True
        except Exception as e:
            print(f"\033[91mError connecting to peer {host}:{port}: {e}\033[0m")
            return False

    def initiate_handshake(self, sock, addr):
        handshake_message = json.dumps({
            'type': 'handshake',
            'data': {
                'host': self.host,
                'port': self.port,
                'username': self.username,
                'public_key': self.public_key.decode('utf-8')
            }
        })
        send_to_peer(sock, handshake_message)

    def handle_handshake(self, message, sock, addr):
        with self.handshake_lock:
            if addr not in self.handshake_completed:
                self.handshake_completed.add(addr)
                peer_info = message['data']
                print(f"\033[92mHandshake completed with {peer_info['username']} at {peer_info['host']}:{peer_info['port']}\033[0m")
                self.peer_public_key = peer_info['public_key'].encode('utf-8')

                # Generate and encrypt symmetric key if not already set
                if self.symmetric_key is None:
                    self.symmetric_key = os.urandom(32)
                encrypted_symmetric_key = encrypt_key_with_rsa(self.peer_public_key, self.symmetric_key)

                # Base64 encode the encrypted symmetric key
                encoded_encrypted_symmetric_key = base64.b64encode(encrypted_symmetric_key).decode('utf-8')

                send_to_peer(sock, json.dumps({
                    'type': 'symmetric_key',
                    'data': encoded_encrypted_symmetric_key  # Use Base64-encoded string
                }))

                # Send blockchain or request it
                self.send_blockchain(sock)
                self.request_full_blockchain(sock)

    def handle_peer(self, sock, addr):
        while self.running:
            message = receive_from_peer(sock)
            if message is None:
                break
            self.process_message(message, sock)
        self.remove_peer(sock, addr)

    def add_public_key(self, username, public_key):
        # Store the public key for the given username
        if not hasattr(self, 'public_keys'):
            self.public_keys = {}
        self.public_keys[username] = public_key


    def handle_regular_message(self, message):
        if isinstance(message, dict):
            if message.get('type') == 'registration':
                username = message.get('username')
                public_key = message.get('public_key')
                print(f"\033[92mNew user registered: {username}\033[0m")
                self.add_public_key(username, public_key)
    
    def is_registered_user(self, username):
        for block in self.blockchain.chain:
            if isinstance(block.data, str):
                try:
                    data = json.loads(decrypt_message(block.data, self.symmetric_key))
                    if data.get('type') == 'registration' and data.get('username') == username:
                        return True
                except Exception as e:
                    print(f"Error during decryption: {e}")
        return False

    def get_public_key(self, username):
        if hasattr(self, 'public_keys') and username in self.public_keys:
            public_key = self.public_keys[username]
            print(f"\033[92mPublic key for {username} found in memory\033[0m")
            return public_key.encode('utf-8') if isinstance(public_key, str) else public_key

        # If not found in memory, search in the blockchain
        for block in self.blockchain.chain:
            if isinstance(block.data, str):
                try:
                    data = json.loads(decrypt_message(block.data, self.symmetric_key))
                    if data.get('type') == 'registration' and data.get('username') == username:
                        public_key = data.get('public_key')
                        print(f"\033[92mPublic key for {username} found in blockchain\033[0m")
                        # Store the key in memory for future use
                        self.add_public_key(username, public_key)
                        return public_key.encode('utf-8') if isinstance(public_key, str) else public_key
                except Exception as e:
                    print(f"Error during decryption: {e}")
        print(f"Public key for {username} not found.")
        return None

    #will this weird shit help? Let's find out!? 

    def print_public_key(self):
        public_key = self.public_key.export_key().decode()
        print(f"My public key:\n{public_key}")

    def process_message(self, message, sock):
        if isinstance(message, str):
            try:
                message = json.loads(message)
            except json.JSONDecodeError:
                print(f"\033[91mError: Unable to parse message as JSON\033[0m")
                return

        message_type = message.get('type')

        if message_type == 'new_block':
            block_data = message.get('data')
            if not block_data:
                print(f"\033[91mError: New block message doesn't contain data\033[0m")
                return

            self.receive_block(block_data)

            try:
                # Decrypting block data
                decrypted_block_data = decrypt_message(block_data['data'], self.symmetric_key)

                # Checking the result of decryption
                if not decrypted_block_data:
                    print(f"\033[91mError: Decrypted block data is None, possibly incorrect key or block format.\033[0m")
                    return

                print(f"Decrypted Block Data (raw): {decrypted_block_data[:100]}...")  # Show the first 100 characters

                # Attempt to parse the decrypted data as JSON
                try:
                    parsed_block_data = json.loads(decrypted_block_data)
                    print(f"Parsed Block Data (as JSON): {json.dumps(parsed_block_data, indent=2)}")
                    
                    if parsed_block_data.get('type') == 'private_message_key':
                        self.handle_private_message_key(parsed_block_data)
                    elif parsed_block_data.get('type') == 'private_message_content':
                        self.handle_private_message_content(parsed_block_data)
                    else:
                        #print(f"\033[93mProcessing non-private message: {json.dumps(parsed_block_data, indent=2)}\033[0m")
                        self.handle_regular_message(parsed_block_data)

                except json.JSONDecodeError:
                    print(f"\033[93mBlock data failed JSON decoding. Treating as raw string.\033[0m")
                    self.handle_regular_message({'content': decrypted_block_data})

            except Exception as e:
                print(f"\033[91mException during block processing: {e}\033[0m")
                import traceback
                traceback.print_exc()

        elif message_type == 'handshake':
            self.handle_handshake(message, sock, get_peer_addr(self.peers, sock))
        elif message_type == 'blockchain':
            self.handle_blockchain(message['data'])
        elif message_type == 'request_blockchain':
            self.send_blockchain(sock)
        elif message_type == 'symmetric_key':
            self.handle_symmetric_key(message['data'])
        elif message_type == 'ping':
            print(f"\033[92mReceived ping from {get_peer_addr(self.peers, sock)}\033[0m")
        elif message_type == 'private_message':
            print(f"\033[92mReceived private message: {message}\033[0m")
            self.handle_private_message(message)
        elif message_type == 'private_message_content':
            self.handle_private_message(message['data'])
        elif message_type == 'poke':
            self.handle_poke(message)
        elif message_type == 'poke_response':
            self.handle_poke_response(message)
        else:
            print(f"\033[91mUnknown message type: {message_type}\033[0m")


    def send_private_message(self, recipient, message):
        print(f"Attempting to send private message to {recipient}")
        print(f"Current private_message_keys: {list(self.private_message_keys.keys())}")

        if recipient in self.private_message_keys:
            print(f"Found existing key for {recipient}")
            symmetric_key = self.private_message_keys[recipient]
        else:
            print(f"No existing key found for {recipient}. Initiating key exchange.")
            recipient_public_key = self.get_public_key(recipient)
            if not recipient_public_key:
                print(f"\033[91mCould not retrieve public key for {recipient}.\033[0m")
                return

            # Generate a new symmetric key for this conversation
            symmetric_key = os.urandom(32)  # 256-bit key
            encrypted_symmetric_key = encrypt_key_with_rsa(recipient_public_key, symmetric_key)
            
            # Store the symmetric key for future use
            self.private_message_keys[recipient] = symmetric_key
            print(f"Generated and stored new symmetric key for {recipient}")

            # Send the encrypted symmetric key
            key_message = {
                'type': 'private_message_key',
                'sender': self.get_fullname(),
                'recipient': recipient,
                'symmetric_key': base64.b64encode(encrypted_symmetric_key).decode('utf-8')
            }
            self.add_to_blockchain(key_message)
            print(f"Sent encrypted symmetric key to {recipient}")

        # Encrypt the actual message content
        encrypted_content = encrypt_message(message, symmetric_key)
        
        # Send the encrypted message
        private_message = {
            'type': 'private_message_content',
            'sender': self.get_fullname(),
            'recipient': recipient,
            'content': encrypted_content,
            'timestamp': time.time()
        }
        self.add_to_blockchain(private_message)
        print(f"\033[92mSent private message content to {recipient}\033[0m")

        # Update last private message sender
        self.last_private_message_sender = recipient


    def handle_private_message(self, message):
        sender = message['sender']
        recipient = message['recipient']
        encrypted_content = message['content']
        timestamp = message['timestamp']

        if recipient != self.get_fullname():
            return  # This message is not for us

        print(f"Received private message from {sender}")
        
        if sender not in self.private_message_keys:
            print(f"Error: No symmetric key found for {sender}")
            return

        message_symmetric_key = self.private_message_keys[sender]
        
        try:
            # Decrypt the message content using the message-specific symmetric key
            decrypted_content = decrypt_message(encrypted_content, message_symmetric_key)
            
            print(f"\033[92mDecrypted private message from {sender}: {decrypted_content}\033[0m")
            
            # Add the decrypted message to chat history
            self.chat_history.append({
                'type': 'private_message',
                'sender': sender,
                'content': decrypted_content,
                'timestamp': timestamp
            })
            self.update_display()
            
            # Store the sender of the last private message for quick replies
            self.last_private_message_sender = sender

        except Exception as e:
            print(f"\033[91mError decrypting private message: {e}\033[0m")
            import traceback
            traceback.print_exc()





    def handle_private_message_key(self, message):
        if message['recipient'] != self.get_fullname():
            return  # This message is not for us

        sender = message['sender']
        encrypted_symmetric_key = message['symmetric_key']
        
        print(f"Received symmetric key for private message from {sender}")

        try:
            # Base64 decode the encrypted symmetric key
            encrypted_symmetric_key_bytes = base64.b64decode(encrypted_symmetric_key)
            
            # Decrypt using recipient's private RSA key
            message_symmetric_key = decrypt_key_with_rsa(self.private_key, encrypted_symmetric_key_bytes)
            
            # Store the decrypted message-specific symmetric key
            self.private_message_keys[sender] = message_symmetric_key
            print(f"Stored symmetric key for {sender}")
            print(f"Current private_message_keys: {list(self.private_message_keys.keys())}")
        except Exception as e:
            print(f"Error decrypting message-specific symmetric key: {e}")
            import traceback
            traceback.print_exc()


    def display_private_message_keys(self):
        print("\nCurrent Private Message Keys:")
        for sender, key in self.private_message_keys.items():
            print(f"Sender: {sender}, Key: {key.hex()[:10]}...")


    def fix_base64_padding(self, base64_string):
        return base64_string + '=' * (-len(base64_string) % 4)

    def handle_private_message_content(self, message):
        sender = message['sender']
        if sender in self.private_message_keys:
            encrypted_content = message['content']

            try:
                # If encrypted_content is a string, decode it to bytes
                if isinstance(encrypted_content, str):
                    encrypted_content_bytes = base64.b64decode(encrypted_content)
                else:
                    encrypted_content_bytes = encrypted_content

                print(f"Encrypted content (first 16 bytes): {encrypted_content_bytes[:16].hex()}")

                # Retrieve the message-specific symmetric key
                message_symmetric_key = self.private_message_keys[sender]
                print(f"Decrypting message from {sender} using key: {message_symmetric_key.hex()}")

                # Decrypt the message content using the message-specific symmetric key
                decrypted_content = decrypt_message(encrypted_content_bytes, message_symmetric_key)

                # Convert decrypted content to string if necessary
                if isinstance(decrypted_content, bytes):
                    decrypted_content = decrypted_content.decode('utf-8')

                # Add the decrypted message to chat history
                self.chat_history.append({
                    'username': f"{sender} (Private)",
                    'content': decrypted_content,
                    'timestamp': message['timestamp']
                })

                # Update the display
                self.update_display()

                # Store the sender of the last private message for quick replies
                self.last_private_message_sender = sender

                print(f"\033[92mDecrypted private message from {sender}: {decrypted_content}\033[0m")
            except Exception as e:
                print(f"\033[91mError decrypting private message: {e}\033[0m")
                import traceback
                traceback.print_exc()
        else:
            print(f"No symmetric key found for private message from {sender}")

        # Debug: Print the current state of private_message_keys
        print(f"Current private_message_keys: {[k for k in self.private_message_keys.keys()]}")



    def handle_symmetric_key(self, encoded_encrypted_key):
        # Base64 decode the encrypted symmetric key
        encrypted_key_bytes = base64.b64decode(encoded_encrypted_key)

        # Decrypt the symmetric key using our private RSA key
        self.symmetric_key = decrypt_key_with_rsa(self.private_key, encrypted_key_bytes)





    def add_to_blockchain(self, data):
        encrypted_data = encrypt_message(json.dumps(data), self.symmetric_key)
        print(f"Encrypted data to be added to blockchain: {encrypted_data}")
        new_block = Block(
            index=len(self.blockchain.chain),
            timestamp=time.time(),
            data=encrypted_data,
            previous_hash=self.blockchain.get_latest_block().hash
        )
        if self.blockchain.add_block(new_block):
            self.sync_chat_history()
            self.broadcast_new_block(new_block)
            print(f"\033[92mNew block added: {new_block.index}\033[0m")
        else:
            print(f"\033[91mFailed to add new block: {new_block.index}\033[0m")

    def broadcast_new_block(self, block):
        for peer in self.peers.values():
            send_to_peer(peer, json.dumps({
                'type': 'new_block',
                'data': block.to_dict()
            }))
        print(f"\033[92mBroadcasted new block: {block.index}\033[0m")

    def handle_blockchain(self, blockchain_data):
        incoming_chain = Blockchain()
        incoming_chain.from_dict(json.loads(blockchain_data))
        if incoming_chain.is_chain_valid() and len(incoming_chain.chain) > len(self.blockchain.chain):
            self.blockchain = incoming_chain
            self.sync_chat_history()
            self.update_display()
            print("\033[92mBlockchain updated with longer chain from peer.\033[0m")
        else:
            print("\033[91mReceived blockchain is invalid or not longer.\033[0m")


    def register_user(self):
        seed_phrase = self.generate_seed_phrase()
        mnemo = Mnemonic("english")
        seed = mnemo.to_seed(seed_phrase)

        # Derive the RSA key pair from the seed
        private_key = self.derive_rsa_key_from_seed(seed)
        self.private_key = private_key.export_key()
        self.public_key = private_key.publickey().export_key()

        block_index = len(self.blockchain.chain)
        block_hash = self.blockchain.get_latest_block().hash[:4]  # First 4 chars of hash
        unique_username = f"{self.username}.{block_index}.{block_hash}"

        registration_data = {
            'username': unique_username,
            'type': 'registration',
            'timestamp': time.time(),
            'public_key': self.public_key.decode('utf-8')
        }
        self.add_to_blockchain(registration_data)
        print(f"User registered: {unique_username}")
        print(f"Seed phrase: {seed_phrase}")
        print("Please save your seed phrase securely. You will need it to log in.")

        # Automatically log in the user
        self.username = unique_username
        self.login_user(seed_phrase)

    def broadcast_registration(self, registration_data):
        for peer_sock in self.peers.values():
            try:
                send_to_peer(peer_sock, json.dumps({
                    'type': 'registration',
                    'data': registration_data
                }))
            except Exception as e:
                print(f"Failed to send registration to peer: {e}")

    def generate_seed_phrase(self):
        mnemo = Mnemonic("english")
        seed_phrase = mnemo.generate(strength=128)  # Generates a 12-word seed phrase
        return seed_phrase

    def login_user(self, seed_phrase):
        print("Starting login process...")
        mnemo = Mnemonic("english")
        if mnemo.check(seed_phrase):
            print("Seed phrase is valid.")
            seed = mnemo.to_seed(seed_phrase)
            print("Seed generated from seed phrase.")

            # Derive the RSA key pair from the seed
            private_key = self.derive_rsa_key_from_seed(seed)
            self.private_key = private_key.export_key()
            self.public_key = private_key.publickey().export_key()

            print("RSA key derived from seed phrase.")
            print(f"Public Key: {self.public_key.decode('utf-8')}")
            print(f"Private Key: {self.private_key.decode('utf-8')}")

            # Retrieve and store the registered username
            for block in self.blockchain.chain:
                if isinstance(block.data, str):
                    try:
                        data = json.loads(decrypt_message(block.data, self.symmetric_key))
                        if data.get('type') == 'registration' and data.get('username').startswith(self.username):
                            self.registered_username = data.get('username')
                            print(f"Registered username found: {self.registered_username}")
                            break
                    except Exception as e:
                        print(f"Error during decryption: {e}")
        else:
            print("\033[91mInvalid seed phrase.\033[0m")



    def derive_rsa_key_from_seed(self,seed):
        seed_hash = hashlib.sha256(seed).digest()
        counter = 0

        def deterministic_get_random_bytes(n):
            nonlocal counter
            output = b''
            while len(output) < n:
                counter_bytes = counter.to_bytes(4, 'big')
                data = seed_hash + counter_bytes
                output += hashlib.sha256(data).digest()
                counter += 1
            return output[:n]

        key = RSA.generate(2048, randfunc=deterministic_get_random_bytes)
        return key





    def get_fullname(self):
        return self.registered_username if self.registered_username else self.username


    def receive_block(self, block_data):
        block = Block.from_dict(block_data)
        if self.blockchain.is_valid_new_block(block, self.blockchain.get_latest_block()):
            self.blockchain.add_block(block)
            self.sync_chat_history()
            self.update_display()
            print(f"\033[92mNew block received and added: {block.index}\033[0m")
        else:
            print(f"\033[91mReceived block is invalid: {block.index}\033[0m")

    def remove_peer(self, sock, addr):
        with self.lock:
            if addr in self.peers:
                del self.peers[addr]
                try:
                    sock.close()
                except Exception as e:
                    print(f"\033[91mError closing socket: {e}\033[0m")
                print(f"\033[93mRemoved peer {addr}\033[0m")

    def sync_chat_history(self):
        try:
            self.chat_history = [json.loads(decrypt_message(block.data, self.symmetric_key)) for block in self.blockchain.chain if isinstance(block.data, str)]
            self.update_display()
        except Exception as e:
            print(f"Error during chat history sync: {e}")

    def handle_user_input(self):
        while self.running:
            try:
                message = input(f"{self.username}> ")
                if message.startswith('/'):
                    handle_command(message, self)
                else:
                    chat_message = {
                        'username': self.username,
                        'content': message,
                        'timestamp': time.time()
                    }
                    self.add_to_blockchain(chat_message)
            except (EOFError, KeyboardInterrupt):
                self.running = False
                self.shutdown()

    def shutdown(self):
        print("\033[91mShutting down...\033[0m")
        self.running = False
        self.server_sock.close()
        for sock in list(self.peers.values()):
            try:
                sock.close()
            except Exception as e:
                print(f"\033[91mError closing socket: {e}\033[0m")
        self.server_thread.join()
        for thread in self.peer_threads:
            thread.join()
        print("\033[92mNode has been shut down.\033[0m")

    def ping_peers(self):
        for peer in self.peers:
            print(f"\033[92mPinging {peer[0]}:{peer[1]}\033[0m")
            send_to_peer(self.peers[peer], json.dumps({'type': 'ping'}))

    def list_peers(self):
        print("\033[93mConnected peers:\033[0m")
        for peer in self.peers:
            print(f"{peer[0]}:{peer[1]}")

    def save_state(self):
        with open('blockchain.json', 'w') as f:
            json.dump(self.blockchain.to_dict(), f)
        with open('peers.json', 'w') as f:
            json.dump(list(self.peers.keys()), f)
        print("\033[92mState saved to disk.\033[0m")

    def load_state(self):
        try:
            with open('blockchain.json', 'r') as f:
                self.blockchain.from_dict(json.load(f))
            with open('peers.json', 'r') as f:
                peers = json.load(f)
                for peer in peers:
                    self.connect_to_peer(peer[0], peer[1])
            print("\033[92mState loaded from disk.\033[0m")
        except Exception as e:
            print(f"\033[91mFailed to load state: {e}\033[0m")

    def clear_console(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def update_display(self):
        self.clear_console()
        display_chat_history(self.chat_history, self.get_fullname())
        if self.blockchain.chain:
            display_latest_block(self.blockchain.get_latest_block(), self.symmetric_key)

    def display_chat_history(self):
        display_chat_history(self.chat_history)

    def display_constitution(self):
        genesis_block = self.blockchain.chain[0]
        constitution = genesis_block.data
        display_constitution(constitution)

    def display_blockchain(self):
        for block in self.blockchain.chain:
            print(f"Block {block.index}:")
            print(f"  Timestamp: {time.ctime(block.timestamp)}")
            print(f"  Previous Hash: {block.previous_hash}")
            print(f"  Hash: {block.hash}")
            print(f"  Data: {json.dumps(block.data, indent=4)}")
            print("-" * 40)

    def send_blockchain(self, sock):
        blockchain_data = json.dumps(self.blockchain.to_dict())
        send_to_peer(sock, json.dumps({
            'type': 'blockchain',
            'data': blockchain_data
        }))

    def request_full_blockchain(self, sock):
        send_to_peer(sock, json.dumps({'type': 'request_blockchain'}))


if __name__ == "__main__":

    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5001
    username = input("Enter your username: ")
    node = Node('localhost', port, username)
    
    while True:
        choice = input("Do you want to (1) Connect or (2) Login? Enter 1 or 2: ")
        if choice == '1':
            break
        elif choice == '2':
            seed_phrase = input("Enter your seed phrase: ")
            node.login_user(seed_phrase)
            break
        else:
            print("Invalid choice. Please enter 1 or 2.")
    
    node.start()
