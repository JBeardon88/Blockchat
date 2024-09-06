from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import base64
import os

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
    return base64.b64encode(encrypted_key).decode('utf-8')

# Decrypt symmetric key with RSA private key
def decrypt_key_with_rsa(private_key, encrypted_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    key = cipher_rsa.decrypt(base64.b64decode(encrypted_key))
    return key

# Encrypt message with AES
def encrypt_message(message, key):
    try:
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        encrypted_message = iv + ct
        print(f"Encryption Debug - IV: {iv}, Ciphertext: {ct}")
        return encrypted_message
    except Exception as e:
        print(f"Error during encryption: {e}")
        raise


def decrypt_message(encrypted_message, key):
    try:
        if isinstance(encrypted_message, str):
            encrypted_message = encrypted_message.encode('utf-8')
        iv = base64.b64decode(encrypted_message[:24])
        ct = base64.b64decode(encrypted_message[24:])
        #print(f"Decryption Debug - Encrypted Message: {encrypted_message}, IV: {iv}, Ciphertext: {ct}")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ct)
        pt = unpad(decrypted, AES.block_size)
        #print(f"Decryption Debug - Plaintext: {pt.decode('utf-8')}")
        return pt.decode('utf-8')
    except Exception as e:
        print(f"Error during decryption: {e}")
        raise

