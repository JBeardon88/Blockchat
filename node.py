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
from encryption import encrypt_message, decrypt_message, generate_rsa_key_pair, encrypt_key_with_rsa, decrypt_key_with_rsa

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
        self.symmetric_key = None

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
        print(f"\033[92mInitiated handshake with {addr[0]}:{addr[1]}\033[0m")

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
                print(f"Handshake Debug - Symmetric Key: {self.symmetric_key}, Encrypted Symmetric Key: {encrypted_symmetric_key}")
                send_to_peer(sock, json.dumps({
                    'type': 'symmetric_key',
                    'data': encrypted_symmetric_key
                }))

                self.send_blockchain(sock)
                self.request_full_blockchain(sock)

    def handle_peer(self, sock, addr):
        print(f"\033[94mHandling peer {addr}\033[0m")
        while self.running:
            message = receive_from_peer(sock)
            if message is None:
                break
            self.process_message(message, sock)
        self.remove_peer(sock, addr)

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
        elif message_type == 'symmetric_key':
            self.handle_symmetric_key(message['data'])
        elif message_type == 'ping':
            print(f"\033[92mReceived ping from {get_peer_addr(self.peers, sock)}\033[0m")
        else:
            print(f"\033[91mUnknown message type: {message_type}\033[0m")

    def handle_symmetric_key(self, encrypted_key):
        self.symmetric_key = decrypt_key_with_rsa(self.private_key, encrypted_key)
        print(f"\033[92mSymmetric key received and decrypted: {self.symmetric_key}\033[0m")

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
            self.update_display()
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
        display_chat_history(self.chat_history)
        display_new_block(self.blockchain.get_latest_block(), self.symmetric_key)

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
    node.start()
