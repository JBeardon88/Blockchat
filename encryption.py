from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import json
import os


# Implement PKCS7 padding manually
def pad(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

# Generate RSA key pair
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt symmetric key with RSA public key
def encrypt_key_with_rsa(public_key, key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(key)
    return encrypted_key  # Return bytes directly

# Decrypt symmetric key with RSA private key
def decrypt_key_with_rsa(private_key, encrypted_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    key = cipher_rsa.decrypt(encrypted_key)
    return key


def encrypt_message(message, key):
    try:
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(message.encode('utf-8'), AES.block_size)
        encrypted_data = cipher.encrypt(padded_message)
        result = base64.b64encode(iv + encrypted_data).decode('utf-8')
        return result
    except Exception as e:
        print(f"Error encrypting message: {e}")
        return None

def decrypt_message(encrypted_message, key):
    try:
        if isinstance(encrypted_message, str):
            ciphertext = base64.b64decode(encrypted_message)
        else:
            ciphertext = encrypted_message

        iv = ciphertext[:16]

        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_padded = cipher.decrypt(ciphertext[16:])

        decrypted = unpad(decrypted_padded)

        result = decrypted.decode('utf-8')
        return result
    except Exception as e:
        print(f"Error in decrypt_message: {e}")
        raise

def encrypt_private_message(recipient_public_key, message, blockchain_symmetric_key):
    try:
        message_symmetric_key = get_random_bytes(32)
        encrypted_content = encrypt_message(message, message_symmetric_key)
        encrypted_symmetric_key = encrypt_key_with_rsa(recipient_public_key, message_symmetric_key)
        
        private_message = {
            "type": "private_message",
            "content": encrypted_content,
            "symmetric_key": encrypted_symmetric_key
        }
        
        json_data = json.dumps(private_message)
        return encrypt_message(json_data, blockchain_symmetric_key)
    except Exception as e:
        print(f"Error during private message encryption: {e}")
        raise

def decrypt_private_message(private_key, encrypted_message, blockchain_symmetric_key):
    try:
        decrypted_with_symmetric = decrypt_message(encrypted_message, blockchain_symmetric_key)
        if decrypted_with_symmetric is None:
            print(f"Error: Decryption with blockchain symmetric key failed")
            return None
        
        try:
            parsed_data = json.loads(decrypted_with_symmetric)
        except json.JSONDecodeError:
            print(f"Error: Decrypted data is not valid JSON")
            return None
        
        if parsed_data.get('type') != 'private_message':
            print(f"Error: Not a private message")
            return None
        
        rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        try:
            encrypted_symmetric_key = base64.b64decode(parsed_data['symmetric_key'])
            message_symmetric_key = cipher_rsa.decrypt(encrypted_symmetric_key)
        except ValueError as e:
            print(f"Error decrypting symmetric key: {e}")
            print(f"Private key used: {private_key}")
            return None
        
        try:
            decrypted_content = decrypt_message(parsed_data['content'], message_symmetric_key)
            return decrypted_content
        except Exception as e:
            print(f"Error decrypting content: {e}")
            return None
    except Exception as e:
        print(f"Error during private message decryption: {e}")
        import traceback
        traceback.print_exc()
        return None
