import base64
import time
import os
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

#Function creates a DES key based on a master key
def derive_keys(master_secret: bytes):
    # Derive encryption key
    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # 128 bits for AES (can be 24 or 32 for AES-192/256)
        salt=None,
        info=b"Encryption Key",
        backend=default_backend()
    ).derive(master_secret)

    # Derive MAC key
    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for HMAC-SHA256
        salt=None,
        info=b"MAC Key",
        backend=default_backend()
    ).derive(master_secret)

    return enc_key, mac_key

#Function for encrypting messages with a DES key
def DES_Encrypt(bytetext: bytes,DES_Key: bytes):
    nonce = os.urandom(8)
    timestamp = int(time.time()).to_bytes(4,"big")
    data_with_metadata = nonce + timestamp + bytetext
    cipher = DES.new(DES_Key,DES.MODE_ECB)
    padded_text = pad(data_with_metadata, DES.block_size)
    return nonce, cipher.encrypt(padded_text)

#Function for decrypting DES Messages
def des_decrypt(ciphertext: bytes, nonce: bytes, des_key: bytes):
    cipher = DES.new(des_key, DES.MODE_ECB)
    decrypted_padded_text = cipher.decrypt(ciphertext)
    decrypted_data = unpad(decrypted_padded_text, DES.block_size)
    received_nonce = decrypted_data[:8]
    received_timestamp = int.from_bytes(decrypted_data[8:12], "big")
    plaintext = decrypted_data[12:]

    #Verifying nonce
    if received_nonce != nonce:
        raise ValueError("Nonce mismatch! Possible replay attack.")

    #Verifying timestamp 60 seconds gap allowed
    current_time = int(time.time())
    if abs(current_time - received_timestamp) > 60:
        raise ValueError("Timestamp expired! Possible replay attack.")
    return plaintext

#Function encrypts a message using the clients AES key, the server will have access to this key so it can decrypt. It will recieve it via RSA messaging and encryption
def AESEncryption(key, message):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()   

#Function takes in the recieved servers AES key that was recieved via RSA messaging, and decrypts a message using it
def AESDecryption(key, encryptedmessage):
    encrypted_data = base64.b64decode(encryptedmessage)  # Decode Base64
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]  # Extract parts
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # Recreate cipher
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt & verify
    return decrypted_data.decode()

def generate_symmetric_key():
    return get_random_bytes(32)


