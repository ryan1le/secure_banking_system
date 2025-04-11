import socket
import threading
import json
import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime

class UserAuthentication:
    def __init__(self, pre_shared_key, admin_username):
        #self.host = host
        #self.port = port
        self.pre_shared_key = pre_shared_key
        self.admin_username = admin_username
        self.cipher_suite = Fernet(pre_shared_key)
        self.users = {}
        self.server_socket = None
        #self.load_users()

    def load_users(self):
        """Load users from encrypted file with admin creation"""
        try:
            with open("users.enc", "rb") as f:
                encrypted_data = f.read()
                decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                self.users = json.loads(decrypted_data)
        except (FileNotFoundError, json.JSONDecodeError, InvalidToken):
            self.users = {}

        temp_pw = Fernet.generate_key().decode()[:12]
        hashed_pw = bcrypt.hashpw(temp_pw.encode(), bcrypt.gensalt()).decode()

        # Create admin if missing
        if self.admin_username not in self.users:
            self.users[self.admin_username] = {
                "password": hashed_pw,
                "is_admin": True,
                "created_at": datetime.now().isoformat()
            }
            self.save_users()
            print(f"\n⚠️ Admin created! Temporary password: {temp_pw}\n")
        else:
             self.users[self.admin_username] = {
                "password": hashed_pw,
                "is_admin": True,
                "created_at": datetime.now().isoformat() if self.admin_username not in self.users 
                            else self.users[self.admin_username].get('created_at', datetime.now().isoformat())
             }
             self.save_users()
             print(f"\n⚠️ Admin credentials updated! New temporary password: {temp_pw}\n")

    def save_users(self):
        """Save users to encrypted file"""
        encrypted_data = self.cipher_suite.encrypt(json.dumps(self.users).encode())
        with open("users.enc", "wb") as f:
            f.write(encrypted_data)

    def register(self, data, transaction_handler):
        _, username, password = data.split(':', 2)
        username = username.strip()
        
        if not username or not password:
            return 'EMPTY_FIELDS'
            
        if username in self.users:
            return 'USER_EXISTS'
            
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        self.users[username] = {
            "password": hashed_pw,
            "is_admin": False,
            "created_at": datetime.now().isoformat(),
            "balance": 0.00
        }
        self.save_users()
        transaction_handler._log_transaction({"customer_id": username, "action": "Register"})
        return 'REGISTER_SUCCESS'
    
    def update_balance(self, data, transaction_handler):
        username = data["username"]
        action = data["action"]
        amount = data["amount"]

        if not username:
            return 'EMPTY_FIELDS'
                
        if username not in self.users:
            return 'USER_DOESNT_EXISTS'
               
        client = self.users[username]
        
        current_balance = client["balance"]

        new_balance = current_balance + (amount if action == 'Deposit' else -amount)
        client["balance"] = new_balance

        transaction_handler._log_transaction({"customer_id": username, "action": action, "amount": amount})
        return json.dumps(client)

    def login(self, data, transaction_handler):
            _, username, password = data.split(':', 2)
            user_data = self.users.get(username.strip(), None)

            if (username.strip() == 'admin'):
                if user_data and bcrypt.checkpw(password.encode(), user_data['password'].encode()):
                    return 'Hello'
            
            if user_data and bcrypt.checkpw(password.encode(), user_data['password'].encode()):
                transaction_handler._log_transaction({"customer_id": username, "action": "Login"})
                transaction_handler._log_transaction({"customer_id": username, "action": "Balance", "amount": user_data["balance"]})
                return json.dumps(user_data)
            else:
                return 'LOGIN_FAILED'

    def adminCheck(self, data):
            try:
                # Split into 4 parts: 'admin', command_type, username, password
                _, cmd_type, username, password = data.split(':', 3)
                username = username.strip()
                password = password.strip()

                user_data = self.users.get(username, {})
                
                # Verify admin status and password
                if not user_data.get('is_admin', False):
                    return 'ADMIN_DENIED'
                    
                if not bcrypt.checkpw(password.encode(), user_data['password'].encode()):
                    return 'ADMIN_DENIED'
  
                if cmd_type == 'list_users':
                    user_list = [{
                        'username': uname,
                        'created_at': data['created_at']
                    } for uname, data in self.users.items()]
                    return (json.dumps(user_list))
                    
                else:
                    return 'INVALID_CMD'

            except ValueError:
                return 'INVALID_FORMAT'

    

    