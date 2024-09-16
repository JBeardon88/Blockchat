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
        print(f"Encrypted message (first 50 chars): {result[:50]}...")
        return result
    except Exception as e:
        print(f"Error encrypting message: {e}")
        return None

def decrypt_message(encrypted_message, key):


    try:
        print(f"Attempting to decrypt message: {encrypted_message[:50]}...")
        print(f"Using key (hex): {key.hex()}")

        # Check if the input is already in bytes format
        if isinstance(encrypted_message, str):
            # If it's a string, assume it's base64 encoded and decode it
            ciphertext = base64.b64decode(encrypted_message)
        else:
            # If it's already bytes, use it directly
            ciphertext = encrypted_message

        print(f"Ciphertext (first 16 bytes): {ciphertext[:16].hex()}")

        # Extract the IV (first 16 bytes)
        iv = ciphertext[:16]
        print(f"IV: {iv.hex()}")

        # Create a new AES cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt the message
        decrypted_padded = cipher.decrypt(ciphertext[16:])
        print(f"Decrypted padded message (hex): {decrypted_padded.hex()}")

        # Remove padding
        decrypted = unpad(decrypted_padded)
        print(f"Decrypted unpadded message (hex): {decrypted.hex()}")

        # Decode the decrypted message from bytes to string
        result = decrypted.decode('utf-8')
        print(f"Decrypted message: {result}")
        return result
    except Exception as e:
        print(f"Error in decrypt_message: {e}")
        raise

def encrypt_private_message(recipient_public_key, message, blockchain_symmetric_key):
    try:
        message_symmetric_key = get_random_bytes(32)
        print(f"Generated symmetric key (hex): {message_symmetric_key.hex()}")
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
        # Decrypt with blockchain symmetric key
        decrypted_with_symmetric = decrypt_message(encrypted_message, blockchain_symmetric_key)
        if decrypted_with_symmetric is None:
            print(f"Error: Decryption with blockchain symmetric key failed")
            return None
        
        print(f"Decrypted with blockchain symmetric key: {decrypted_with_symmetric[:100]}...")
        
        try:
            parsed_data = json.loads(decrypted_with_symmetric)
            print(f"Successfully parsed JSON: {json.dumps(parsed_data, indent=2)}")
        except json.JSONDecodeError:
            print(f"Error: Decrypted data is not valid JSON")
            return None
        
        if parsed_data.get('type') != 'private_message':
            print(f"Error: Not a private message")
            return None
        
        # Decrypt the message-specific symmetric key
        rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        try:
            encrypted_symmetric_key = base64.b64decode(parsed_data['symmetric_key'])
            print(f"Encrypted symmetric key (base64): {parsed_data['symmetric_key']}")
            print(f"Encrypted symmetric key (bytes): {encrypted_symmetric_key}")
            message_symmetric_key = cipher_rsa.decrypt(encrypted_symmetric_key)
            print(f"Successfully decrypted message symmetric key (hex): {message_symmetric_key.hex()}")
        except ValueError as e:
            print(f"Error decrypting symmetric key: {e}")
            print(f"Private key used: {private_key}")
            return None
        
        # Decrypt the actual content
        try:
            decrypted_content = decrypt_message(parsed_data['content'], message_symmetric_key)
            print(f"Successfully decrypted content: {decrypted_content[:100]}...")
            return decrypted_content
        except Exception as e:
            print(f"Error decrypting content: {e}")
            return None
    except Exception as e:
        print(f"Error during private message decryption: {e}")
        import traceback
        traceback.print_exc()
        return None
