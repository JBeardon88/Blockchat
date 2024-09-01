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
        self.sync_interval = SYNC_INTERVAL  # Sync every 60 seconds
        self.handshake_lock = threading.Lock()
        self.handshake_completed = set()
        self.display_constitution()
        self.peer_threads = []  # Track peer threads

    def start(self):
        self.server_thread.start()
        self.connect_to_network()
        self.handle_user_input()

    def run_server(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((self.host, self.port))
        server_sock.listen(5)
        self.server_sock = server_sock  # Store the server socket for later use
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
        # Connect to known peers
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
            
            # Start handshake
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
                'username': self.username
            }
        })
        send_to_peer(sock, handshake_message)
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
            message = receive_from_peer(sock)
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

    def send_blockchain(self, sock):
        message = {
            'type': 'blockchain',
            'data': self.blockchain.to_dict()
        }
        send_to_peer(sock, message)

    def request_full_blockchain(self, sock=None):
        request_message = json.dumps({
            'type': 'request_blockchain'
        })
        if sock:
            send_to_peer(sock, request_message)
        else:
            for peer_sock in self.peers.values():
                send_to_peer(peer_sock, request_message)
        print(f"\033[92mRequested full blockchain from peer\033[0m")

    def process_message(self, message, sock):
        if isinstance(message, str):
            try:
                message = json.loads(message)
            except json.JSONDecodeError as e:
                print(f"\033[91mError decoding message: {e}\033[0m")
                return
        message_type = message.get('type')
        if message_type == 'handshake':
            self.handle_handshake(message, sock, get_peer_addr(self.peers, sock))
        elif message_type == 'blockchain':
            self.handle_blockchain(message['data'])
        elif message_type == 'new_block':
            self.receive_block(message['data'])
        elif message_type == 'request_blockchain':
            self.send_blockchain(sock)
        elif message_type == 'ping':
            print(f"\033[92mReceived ping from {get_peer_addr(self.peers, sock)}\033[0m")
        else:
            print(f"\033[91mUnknown message type: {message_type}\033[0m")

    def handle_blockchain(self, blockchain_data):
        new_blockchain = Blockchain()
        new_blockchain.from_dict(blockchain_data)
        
        print(f"\033[94mReceived blockchain with length: {len(new_blockchain.chain)}\033[0m")
        print(f"\033[94mCurrent blockchain length: {len(self.blockchain.chain)}\033[0m")
        
        if new_blockchain.is_valid_chain():
            if len(new_blockchain.chain) > len(self.blockchain.chain):
                self.blockchain = new_blockchain
                self.sync_chat_history()
                print("\033[92mBlockchain synchronized.\033[0m")
            else:
                print("\033[93mReceived blockchain is not longer than the current blockchain. No update performed.\033[0m")
        else:
            print("\033[91mReceived blockchain is invalid.\033[0m")

    def receive_block(self, block_data):
        new_block = Block.from_dict(block_data)
        print(f"\033[94mAttempting to add new block: {new_block.index}\033[0m")
        print(f"\033[94mNew block previous hash: {new_block.previous_hash}\033[0m")
        print(f"\033[94mCurrent blockchain last block hash: {self.blockchain.chain[-1].hash}\033[0m")
        
        if self.blockchain.add_block(new_block):
            self.sync_chat_history()  # Update chat history when a new block is added
            self.update_display()
            print(f"\033[92mNew block added: {new_block.index}\033[0m")
        else:
            print(f"\033[91mFailed to add new block: {new_block.index}\033[0m")
            self.request_full_blockchain()

    def sync_chat_history(self):
        self.chat_history = [block.data for block in self.blockchain.chain if isinstance(block.data, dict) and 'content' in block.data]
        self.update_display()

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

    def add_to_blockchain(self, data):
        new_block = Block(
            index=len(self.blockchain.chain),
            timestamp=time.time(),
            data=data,
            previous_hash=self.blockchain.get_latest_block().hash
        )
        if self.blockchain.add_block(new_block):
            self.sync_chat_history()
            self.update_display()
            self.broadcast_new_block(new_block)
            print(f"\033[92mNew block added: {new_block.index}\033[0m")
        else:
            print(f"\033[91mFailed to add new block: {new_block.index}\033[0m")

    def broadcast_new_block(self, block):
        message = {
            'type': 'new_block',
            'data': block.to_dict()
        }
        for peer_sock in self.peers.values():
            send_to_peer(peer_sock, message)

    def shutdown(self):
        print("\033[91mShutting down...\033[0m")
        self.running = False
        # Close the server socket to stop accepting new connections
        self.server_sock.close()
        # Close all peer connections
        for sock in list(self.peers.values()):
            try:
                sock.close()
            except Exception as e:
                print(f"\033[91mError closing socket: {e}\033[0m")
        # Wait for the server thread to finish
        self.server_thread.join()
        # Wait for all peer threads to finish
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
        display_chat_history(self.chat_history)  # Call the function from display module
        display_new_block(self.blockchain.get_latest_block())  # Call the function from display module

    def display_constitution(self):
        genesis_block = self.blockchain.chain[0]
        constitution = genesis_block.data
        display_constitution(constitution)

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5001
    username = input("Enter your username: ")
    node = Node('localhost', port, username)
    node.start()
