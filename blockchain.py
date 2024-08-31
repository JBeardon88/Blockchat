import hashlib
import time
import json

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'hash': self.hash
        }

    @classmethod
    def from_dict(cls, block_dict):
        block = cls(
            block_dict['index'],
            block_dict['timestamp'],
            block_dict['data'],
            block_dict['previous_hash']
        )
        block.hash = block_dict['hash']
        return block

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []

    def create_genesis_block(self):
        constitution = {
            "title": "B L O C K C H A T --- G A N G",
            "preamble": "A simple blockchain based chat application. Decentralized, communal, cool as fuck.",
            "articles": [
                "Origin Users: These are the original users of the blockchain. They are the first users to join the network.",
                "Rule 1: Example",
                "Rule 2: I'll think of it later.",
                "Rule 3: voting is the only way to mint new members."
            ]
        }
        return Block(0, time.time(), constitution, "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        if isinstance(data, Block):
            new_block = data
        else:
            previous_block = self.get_latest_block()
            new_block = Block(previous_block.index + 1, time.time(), data, previous_block.hash)
        
        if self.is_block_valid(new_block, self.get_latest_block()):
            self.chain.append(new_block)
            return new_block
        return None

    def is_block_valid(self, new_block, previous_block):
        if previous_block.index + 1 != new_block.index:
            return False
        if previous_block.hash != new_block.previous_hash:
            return False
        if new_block.calculate_hash() != new_block.hash:
            return False
        return True

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.previous_hash != previous_block.hash:
                return False
            if current_block.hash != current_block.calculate_hash():
                return False
        return True

    def resolve_conflicts(self, other_chain):
        if len(other_chain) > len(self.chain) and Blockchain.is_valid_chain(other_chain):
            self.chain = other_chain
            return True
        return False

    def is_valid_chain(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.previous_hash != previous_block.hash:
                return False
            if current_block.hash != current_block.calculate_hash():
                return False
        return True

    def to_dict(self):
        return {'chain': [block.to_dict() for block in self.chain]}

    def from_dict(self, blockchain_dict):
        self.chain = [Block.from_dict(block_dict) for block_dict in blockchain_dict['chain']]

    def resolve_fork(self, incoming_chain):
        if len(incoming_chain) > len(self.chain):
            self.chain = incoming_chain
            print("Blockchain updated with longer chain from peer.")
        else:
            print("Local blockchain is longer or same length. No update needed.")