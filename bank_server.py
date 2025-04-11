import base64
import hashlib
import hmac
import socket
from threading import Thread, Lock
import json
import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from Crypto.Cipher import AES
from datetime import datetime
import sys
import os
from helpers import *
from authentication import UserAuthentication
from transaction_protocol import TransactionProtocol 

HOST = 'localhost'
PORT = 9999
PRE_SHARED_KEY = b'2ZOxp2vxL4fYd7e8NlqQZ7W9mF1J3K6gR0sT4V2CJ5M='
ADMIN_USERNAME = "admin"
cipher_suite = Fernet(PRE_SHARED_KEY)

XPRE_SHARED_KEY = base64.b64decode('2ZOxp2vxL4fYd7e8NlqQZ7W9mF1J3K6gR0sT4V2CJ5M=')

users = {}
clients = set()
clients_lock = Lock()
response_nonces = {}
server_nonces = set()

def generate_nonce():
    nonce = os.urandom(16).hex()
    while nonce in server_nonces:
        nonce = os.urandom(16).hex()

    server_nonces.add(nonce)
    return nonce

def handle_client(data, user, transaction_handler):
    try:
        # Handle registration
        if data.startswith('register:'):
            return user.register(data, transaction_handler)

        # Handle login
        elif data.startswith('login:'):
            return user.login(data, transaction_handler)

        # Handle admin commands
        elif data.startswith('admin:'):
            return user.adminCheck(data)  

        elif data.startswith('update:'):
            return transaction_handler.view_audit_log()  

        else:
            try:
                serialized_data = json.loads(data)
                print(serialized_data)
                return user.update_balance(serialized_data, transaction_handler)
            except:
                return None      

    except Exception as e:
        print(f"Server error: {e}")

def distribute_kms(client, addr):
    enc_initial_message = client.recv(1024).decode()
    print("Received initial message: ", enc_initial_message)
    dec_response = json.loads(AESDecryption(XPRE_SHARED_KEY , enc_initial_message))
    
    if addr not in response_nonces:
        response_nonces[addr] = []

    if (dec_response["client_n"] in response_nonces[addr] and time.time() - float(dec_response["timestamp"]) > 10):
        print("Message Replay Attack!")
        raise Exception("Message is tainted")
    response_nonces[addr].append(dec_response["client_n"])
    print(dec_response)

    N0 = generate_nonce()
    TS0 = str(time.time())
    auth_server_msg = json.dumps({"message": "Authenticate Server", "client_n": dec_response["client_n"], "server_n": N0, "timestamp": TS0})
    print("Auth Server Message to send:", auth_server_msg)

    enc_auth_server_msg = AESEncryption(XPRE_SHARED_KEY, auth_server_msg)
    print("Encrypted Auth Server Message:", enc_auth_server_msg)
    client.sendall(enc_auth_server_msg.encode())

    response = client.recv(4096).decode()
    print("Received response: ", response)
    dec_response = json.loads(AESDecryption(XPRE_SHARED_KEY ,response))
    if (dec_response["server_n"] != N0 or dec_response["client_n"] in response_nonces[addr] or time.time() - float(dec_response["timestamp"]) > 10):
        print("Message Replay Attack!")
        raise Exception("Message is tainted")
    response_nonces[addr].append(dec_response["client_n"])
    print(dec_response)

    master_secret = generate_symmetric_key()
    master_key, hmac_key = derive_keys(master_secret)
    print("\nGenerated Master_Secret: ")
    print(master_secret)

    N1 = generate_nonce()
    TS1 = str(time.time())
    send_ms_msg = json.dumps({"message": "Sent master_secret", "master_secret": master_secret.hex(), "client_n": dec_response["client_n"], "server_n": N1, "timestamp": TS1})
    print("MS Message to send:", send_ms_msg)

    enc_send_ms_msg = AESEncryption(XPRE_SHARED_KEY, send_ms_msg)
    print("Encrypted Auth Server Message:", enc_send_ms_msg)
    client.sendall(enc_send_ms_msg.encode())

    response = client.recv(4096).decode()
    print("Received response: ", response)
    dec_response = json.loads(AESDecryption(master_key ,response))
    if (dec_response["server_n"] != N1 or dec_response["client_n"] in response_nonces[addr] or time.time() - float(dec_response["timestamp"]) > 10):
        print("Message Replay Attack!")
        raise Exception("Message is tainted")
    response_nonces[addr].append(dec_response["client_n"])
    print(dec_response)

    N2 = generate_nonce()
    TS2 = str(time.time())
    final_msg = json.dumps({"message": "Final verification message", "client_n": dec_response["client_n"], "server_n": N2, "timestamp": TS2})
    print("Final verification to send:", final_msg)

    enc_final_msg = AESEncryption(master_key, final_msg)
    print("Encrypted Final verification Message:", enc_final_msg)
    client.sendall(enc_final_msg.encode())
    print("Sent final message")

    with clients_lock:
        clients.add(client)

    return master_key, hmac_key


def new_thread_client(client, addr, user):
    print ("Accepted connection from: ", addr)
    
    try:
        master_key, hmac_key = distribute_kms(client, addr)
        transaction = TransactionProtocol()
        while True:
            enc_message, hmac_message = client.recv(4096).split(b'||')
            verify_hmac = hmac.new(hmac_key, enc_message, hashlib.sha256).hexdigest().encode()

            print("Verifying response")
            if verify_hmac != hmac_message:
                raise RuntimeError("Mismatched HMAC in response message")
            
            response = json.loads(AESDecryption(master_key, enc_message.decode()))
            
            if response["nonce"] in response_nonces[addr]:
                raise RuntimeError("Replayed nonce detected!")
            response_nonces[addr].append(response["nonce"])
            
            if abs(time.time() - float(response["timestamp"])) > 10:
                raise RuntimeError("Replayed timestamp detected!")
            
            print(response)

            handle_message = handle_client(response["message"], user, transaction)

            if (handle_message is not None):
                N = generate_nonce()
                TS = str(time.time())
                response_msg = json.dumps({"message": handle_message, "nonce": N, "timestamp": TS})
                print("Server Response Message:", response_msg)

                enc_response_msg = AESEncryption(master_key, response_msg).encode()

                hmac_response_msg = hmac.new(hmac_key, enc_response_msg, hashlib.sha256).hexdigest().encode()
                print(f"HMAC: {hmac_response_msg}")

                final_enc_message = enc_response_msg + b"||" + hmac_response_msg

                print("Sending message")
                client.sendall(final_enc_message)
            
            else:
                print("Invalid Command")
                
    finally:
        with clients_lock:
            user.save_users()
            clients.remove(client)
        client.close()
        print(f"Connection closed: {addr}")
        

def start_server():
    user = UserAuthentication(
        pre_shared_key=PRE_SHARED_KEY,
        admin_username=ADMIN_USERNAME
    )
     
    user.load_users()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"Server running on {HOST}:{PORT}")
    
    try:
        while True:
            try:
                client, addr = server.accept()
                Thread(target=new_thread_client, args=(client, addr, user), daemon=True).start()
            except socket.timeout:      
                pass            # listening for shudown signal
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server.close()
        with clients_lock:
            for client in clients:
                client.close()
            clients.clear()
        print("Server shutdown.")

if __name__ == '__main__':
    start_server()