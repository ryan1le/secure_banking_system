import time
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

#Function creates a DES key based on a master key
def Generate_DES_Key(MasterKey: bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length = 8, #Restricting to 56-bit for DES
        salt = None, #Can be used to further make the encryption even more safe
        info = b"DES Encryption",
        backend=default_backend()
    )
    return hkdf.derive(MasterKey)

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

#Generating master key
master_key = b"s3"
des_key = Generate_DES_Key(master_key)
print(des_key)

#Encryoting message with master key
messagetosend = "Withdraw $500"
nonce, ciphertext = DES_Encrypt(messagetosend.encode('utf-8'), des_key)
print("Encrypted:", ciphertext.hex())

#Decrypting message using known master key
decrypted_text = des_decrypt(ciphertext, nonce, des_key)
print("Decrypted:", decrypted_text.decode())


