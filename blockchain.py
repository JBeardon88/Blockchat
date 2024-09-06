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

    def create_genesis_block(self):
        genesis_block = Block(
            index=0,
            timestamp=0,
            data={
                'title': 'B L O C K C H A T --- G A N G',
                'preamble': 'Simple, decentralized, grassroots. New features are only addded when needed. Keep it simple, keep it safe, keep it secure.',
                'articles': [
                    'Origin Users: These are the original users of the blockchain. They are the first users to join the network.',
                    'Rule 1: Example',
                    'Rule 2: I\'ll think of it later.',
                    'Rule 3: voting is the only way to mint new members.'
                ]
            },
            previous_hash='0'
        )
        genesis_block.hash = genesis_block.calculate_hash()
        return genesis_block

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, block):
        print(f"\033[94mAdding block with index: {block.index}\033[0m")
        if self.is_valid_new_block(block, self.chain[-1]):
            self.chain.append(block)
            return True
        else:
            print(f"\033[91mBlock with index {block.index} is invalid\033[0m")
            return False

    def is_valid_new_block(self, new_block, previous_block):
        if previous_block.index + 1 != new_block.index:
            print(f"\033[91mInvalid index: {new_block.index}\033[0m")
            return False
        if previous_block.hash != new_block.previous_hash:
            print(f"\033[91mInvalid previous hash: {new_block.previous_hash}\033[0m")
            return False
        if not self.is_valid_hash(new_block):
            print(f"\033[91mInvalid hash: {new_block.hash}\033[0m")
            return False
        return True

    def is_valid_hash(self, block):
        # Implement your hash validation logic here
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
        return [block.to_dict() for block in self.chain]

    def from_dict(self, data):
        self.chain = [Block.from_dict(block_data) for block_data in data]

    def resolve_fork(self, incoming_chain):
        if len(incoming_chain) > len(self.chain):
            self.chain = incoming_chain
            print("Blockchain updated with longer chain from peer.")
        else:
            print("Local blockchain is longer or same length. No update needed.")