import socket
import threading
import json
import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime
import sys
import os

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, parent_dir)

from authentication import UserAuthentication 

HOST = 'localhost'
PORT = 9999
PRE_SHARED_KEY = b'2ZOxp2vxL4fYd7e8NlqQZ7W9mF1J3K6gR0sT4V2CJ5M='
ADMIN_USERNAME = "admin"
cipher_suite = Fernet(PRE_SHARED_KEY)
users = {}

def handle_client(client_socket, user):
    try:
        data = client_socket.recv(1024).decode()
        
        # Handle registration
        if data.startswith('register:'):
            user.register(data, client_socket)

        # Handle login
        elif data.startswith('login:'):
            user.login(data, client_socket)

        # Handle admin commands
        elif data.startswith('admin:'):
            user.adminCheck(data, client_socket)          

    except Exception as e:
        print(f"Server error: {e}")
    finally:
        client_socket.close()

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
    
    while True:
        client_sock, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_sock, user)).start()

if __name__ == '__main__':
    start_server()