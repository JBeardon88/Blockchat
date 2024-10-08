import socket
import json
import struct

def send_to_peer(sock, message):
    try:
        msg = json.dumps(message).encode('utf-8')
        msg = struct.pack('>I', len(msg)) + msg
        sock.sendall(msg)
        # print(f"Sent message to peer: {message}")  # Removed
    except Exception as e:
        print(f"\033[91mError sending message to peer: {e}\033[0m")

def receive_from_peer(sock):
    try:
        raw_msglen = recvall(sock, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        message = recvall(sock, msglen).decode('utf-8')
        # print(f"Received message from peer: {message}")  # Removed
        return json.loads(message)
    except Exception as e:
        print(f"\033[91mError receiving message from peer: {e}\033[0m")
        return None

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF
    data = bytearray()  # Initialize the data variable
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

def get_peer_addr(peers, sock):
    for addr, peer_sock in peers.items():
        if peer_sock == sock:
            return addr
    return None