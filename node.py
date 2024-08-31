import socket
import threading
import json
import time
import os
from blockchain import Blockchain, Block
import uuid
import struct

class Node:
    def __init__(self, host, port, username):
        self.host = host
        self.port = port
        self.username = username
        self.blockchain = Blockchain()
        self.peers = {}
        self.running = True
        self.lock = threading.Lock()
        self.chat_history = []
        self.server_thread = threading.Thread(target=self.run_server)
        self.server_thread.daemon = True
        self.processed_messages = set()  # Track processed messages
        self.sync_lock = threading.Lock()
        self.last_sync_time = time.time()
        self.sync_interval = 60  # Sync every 60 seconds
        self.handshake_lock = threading.Lock()
        self.handshake_completed = set()
        self.display_constitution()

    def start(self):
        self.server_thread.start()
        self.connect_to_network()
        self.handle_user_input()

    def run_server(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((self.host, self.port))
        server_sock.listen(5)
        print(f"Listening on {self.host}:{self.port}")

        while self.running:
            client_sock, addr = server_sock.accept()
            print(f"Accepted connection from {addr}")
            self.peers[addr] = client_sock
            threading.Thread(target=self.handle_peer, args=(client_sock, addr)).start()

    def connect_to_network(self):
        # Connect to known peers
        known_peers = [('localhost', 5001), ('localhost', 5002), ('localhost', 5003)]
        for peer in known_peers:
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
            
            # Start handshake
            self.initiate_handshake(sock, (host, port))
            
            threading.Thread(target=self.handle_peer, args=(sock, (host, port))).start()
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
                'username': self.username
            }
        })
        self.send_to_peer(sock, handshake_message)
        print(f"\033[92mInitiated handshake with {addr[0]}:{addr[1]}\033[0m")

    def handle_handshake(self, message, sock, addr):
        with self.handshake_lock:
            if addr not in self.handshake_completed:
                self.handshake_completed.add(addr)
                peer_info = message['data']
                print(f"\033[92mHandshake completed with {peer_info['username']} at {peer_info['host']}:{peer_info['port']}\033[0m")
                
                # Send our blockchain
                self.send_blockchain(sock)
                # Request their blockchain
                self.request_full_blockchain(sock)

    def handle_peer(self, sock, addr):
        print(f"\033[94mHandling peer {addr}\033[0m")
        while self.running:
            message = self.receive_from_peer(sock)
            if message is None:
                break
            self.process_message(message, sock)
        self.remove_peer(sock, addr)

    def remove_peer(self, sock, addr):
        with self.lock:
            if addr in self.peers:
                del self.peers[addr]
            try:
                sock.close()
            except Exception as e:
                print(f"\033[91mError closing socket: {e}\033[0m")
        print(f"\033[93mDisconnected from peer {addr}\033[0m")

    def send_to_peer(self, sock, message):
        try:
            # Serialize the message to JSON
            msg = json.dumps(message).encode('utf-8')
            # Prefix each message with a 4-byte length (network byte order)
            msg = struct.pack('>I', len(msg)) + msg
            sock.sendall(msg)
        except Exception as e:
            print(f"\033[91mError sending message to peer: {e}\033[0m")
            self.remove_peer(sock, self.get_peer_addr(sock))

    def receive_from_peer(self, sock):
        try:
            # Read message length and unpack it into an integer
            raw_msglen = self.recvall(sock, 4)
            if not raw_msglen:
                return None
            msglen = struct.unpack('>I', raw_msglen)[0]
            # Read the message data
            message = json.loads(self.recvall(sock, msglen).decode('utf-8'))
            print(f"\033[94mReceived message: {message}\033[0m")
            return message
        except Exception as e:
            print(f"\033[91mError receiving message: {e}\033[0m")
            self.remove_peer(sock, self.get_peer_addr(sock))
            return None

    def process_message(self, message, sock):
        if not isinstance(message, dict):
            print(f"\033[91mInvalid message format: {message}\033[0m")
            return

        message_type = message.get('type')
        if not message_type:
            print("\033[91mMessage has no 'type' field\033[0m")
            return

        print(f"\033[94mProcessing message of type: {message_type}\033[0m")

        if message_type == 'handshake':
            self.handle_handshake(message, sock, self.get_peer_addr(sock))
        elif message_type == 'new_block':
            self.receive_block(message['data'])
        elif message_type == 'request_blockchain':
            self.send_blockchain(sock)
        elif message_type == 'blockchain':
            self.handle_blockchain(message['data'])
        else:
            print(f"\033[91mUnknown message type: {message_type}\033[0m")

    def relay_message(self, message, origin_sock):
        for peer_sock in self.peers.values():
            if peer_sock != origin_sock:
                try:
                    self.send_to_peer(peer_sock, message)
                except Exception as e:
                    print(f"\033[91mError relaying message to peer: {e}\033[0m")

    def add_to_blockchain(self, data):
        new_block = self.blockchain.add_block(data)
        if new_block:
            self.broadcast_block(new_block)
            self.sync_chat_history()  # Update chat history after adding a new block
            self.update_display()

    def broadcast_block(self, block):
        message = {
            'type': 'new_block',
            'data': block.to_dict()
        }
        self.broadcast_to_peers(message)

    def receive_block(self, block_data):
        new_block = Block.from_dict(block_data)
        if self.blockchain.add_block(new_block):
            self.sync_chat_history()  # Update chat history when a new block is added
            self.update_display()
            print(f"\033[92mNew block added: {new_block.index}\033[0m")
        else:
            print(f"\033[91mFailed to add new block: {new_block.index}\033[0m")
            self.request_full_blockchain()

    def broadcast_to_peers(self, message):
        for sock in list(self.peers.values()):
            try:
                self.send_to_peer(sock, message)
            except Exception as e:
                print(f"\033[91mError broadcasting to peer: {e}\033[0m")
                self.peers = {k: v for k, v in self.peers.items() if v != sock}

    def send_blockchain(self, sock):
        message = {
            'type': 'blockchain',
            'data': self.blockchain.to_dict()
        }
        self.send_to_peer(sock, message)

    def request_full_blockchain(self, sock=None):
        message = {'type': 'request_blockchain'}
        if sock:
            self.send_to_peer(sock, message)
        else:
            self.broadcast_to_peers(message)

    def sync_chat_history(self):
        self.chat_history = [block.data for block in self.blockchain.chain if isinstance(block.data, dict) and 'content' in block.data]
        self.update_display()

    def handle_user_input(self):
        while self.running:
            try:
                message = input(f"{self.username}> ")
                if message.startswith('/'):
                    self.handle_command(message)
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

    def handle_command(self, command):
        if command == '/exit':
            self.running = False
            self.shutdown()
        elif command == '/help':
            self.display_help()
        elif command == '/ping':
            self.ping_peers()
        elif command == '/list':
            self.list_peers()
        elif command == '/blockchain':
            self.display_latest_block()
        elif command == '/history':
            self.display_chat_history()
        elif command == '/save':
            self.save_state()
        elif command == '/load':
            self.load_state()
        elif command == '/clear':
            self.clear_console()
        else:
            print("\033[91mUnknown command. Type /help for a list of commands.\033[0m")

    def shutdown(self):
        print("\033[91mShutting down...\033[0m")
        self.running = False
        for sock in list(self.peers.values()):
            try:
                sock.close()
            except Exception as e:
                print(f"\033[91mError closing socket: {e}\033[0m")
        self.server_thread.join()
        print("\033[92mNode has been shut down.\033[0m")

    def display_help(self):
        print("\033[93mAvailable commands:\033[0m")
        print("/exit - Exit the application")
        print("/help - Display this help message")
        print("/ping - Check the connection to peers")
        print("/list - List all connected peers")
        print("/blockchain - Display the latest block in the blockchain")
        print("/history - Display the chat history")
        print("/save - Save the current blockchain and peer list to disk")
        print("/load - Load the blockchain and peer list from disk")
        print("/clear - Clear the console")

    def ping_peers(self):
        for peer in self.peers:
            print(f"\033[92mPinging {peer[0]}:{peer[1]}\033[0m")
            self.send_to_peer(self.peers[peer], json.dumps({'type': 'ping'}))

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
        self.display_chat_history()
        self.display_new_block()

    def display_chat_history(self):
        print("\n--- Chat History ---")
        for msg in self.chat_history:
            if isinstance(msg, dict):
                print(f"\033[94m{msg['username']}\033[0m: {msg['content']}")
        print("--------------------")

    def display_new_block(self):
        if not self.blockchain.chain:
            return
        latest_block = self.blockchain.chain[-1]
        block_info = (
            f"\n\033[93m--- New Block Added ---\033[0m\n"
            f"Index: \033[96m{latest_block.index}\033[0m\n"
            f"Timestamp: \033[96m{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(latest_block.timestamp))}\033[0m\n"
            f"Data: \033[96m{json.dumps(latest_block.data)}\033[0m\n"
            f"Hash: \033[96m{latest_block.hash}\033[0m\n"
            f"Previous Hash: \033[96m{latest_block.previous_hash}\033[0m\n"
            f"--------------------\n"
        )
        print(block_info)

    def display_latest_block(self):
        if not self.blockchain.chain:
            print("\033[91mNo blocks in the chain yet.\033[0m")
        else:
            latest_block = self.blockchain.chain[-1]
            block_info = (
                f"\n\033[93m--- Latest Block ---\033[0m\n"
                f"Index: \033[96m{latest_block.index}\033[0m\n"
                f"Timestamp: \033[96m{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(latest_block.timestamp))}\033[0m\n"
                f"Data: \033[96m{json.dumps(latest_block.data)}\033[0m\n"
                f"Hash: \033[96m{latest_block.hash}\033[0m\n"
                f"Previous Hash: \033[96m{latest_block.previous_hash}\033[0m\n"
                f"--------------------\n"
            )
            print(block_info)

    def display_constitution(self):
        genesis_block = self.blockchain.chain[0]
        constitution = genesis_block.data
        print("\n\033[1m" + "=" * 50 + "\n" + constitution['title'] + "\n" + "=" * 50 + "\033[0m")
        print("\n\033[3m" + constitution['preamble'] + "\033[0m\n")
        for article in constitution['articles']:
            print(article)
        print("\n" + "=" * 50 + "\n")

    def recvall(self, sock, n):
        # Helper function to recv n bytes or return None if EOF
        data = bytearray()  # Initialize the data variable
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def handle_blockchain(self, blockchain_data):
        new_blockchain = Blockchain()
        new_blockchain.from_dict(blockchain_data)
        
        if new_blockchain.is_valid_chain():
            if len(new_blockchain.chain) > len(self.blockchain.chain):
                self.blockchain = new_blockchain
                self.sync_chat_history()
                print("\033[92mBlockchain synchronized.\033[0m")
            else:
                print("\033[93mReceived blockchain is not longer than the current blockchain. No update performed.\033[0m")
        else:
            print("\033[91mReceived blockchain is invalid.\033[0m")

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5001
    username = input("Enter your username: ")
    node = Node('localhost', port, username)
    node.start()
