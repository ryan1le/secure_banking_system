import base64
import hashlib
import os
import threading
import time
import PySimpleGUI as sg
import socket
import json
import hmac
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from datetime import datetime
from helpers import *

# Configuration
HOST = 'localhost'
PORT = 9999
PRE_SHARED_KEY = b'2ZOxp2vxL4fYd7e8NlqQZ7W9mF1J3K6gR0sT4V2CJ5M='
cipher_suite = Fernet(PRE_SHARED_KEY)

XPRE_SHARED_KEY = base64.b64decode('2ZOxp2vxL4fYd7e8NlqQZ7W9mF1J3K6gR0sT4V2CJ5M=')

# Theme and Colors
sg.theme('DarkBlue3')
HEADER_FONT = ('Helvetica', 20, 'bold')
BUTTON_FONT = ('Helvetica', 12)
TEXT_FONT = ('Helvetica', 12)
INPUT_SIZE = (25, 1)

class ConnectionManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.socket = None
        self.connected = False

    def get_connection(self):
        with self.lock:
            if not self.connected:
                try:
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.socket.connect((HOST, PORT))
                    self.connected = True
                    print("Established persistent connection")
                except Exception as e:
                    raise ConnectionError(f"Connection failed: {str(e)}")
            return self.socket

    def close(self):
        with self.lock:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.connected = False
                print("Closed persistent connection")

con_manager = ConnectionManager()
master_secret = None
master_key = None
hmac_key = None
past_nonces = set()

def generate_nonce():
    nonce = os.urandom(16).hex()
    while nonce in past_nonces:
        nonce = os.urandom(16).hex()

    past_nonces.add(nonce)
    return nonce

def exchange_keys():
    global master_key, hmac_key
    try:
        client = con_manager.get_connection()

        N0 = generate_nonce()
        TS0 = str(time.time())
        initial_message = json.dumps({"message": "Initial Message", "client_n": N0, "timestamp": TS0})
        print("Initial Message to send:", initial_message)
        
        enc_initial_message = AESEncryption(XPRE_SHARED_KEY, initial_message)
        print("Encrypted initial message:", enc_initial_message)
        client.sendall(enc_initial_message.encode())

        response = client.recv(4096).decode()
        print("Received response: ", response)
        dec_response = json.loads(AESDecryption(XPRE_SHARED_KEY ,response))
        if (dec_response["client_n"] != N0 or dec_response["server_n"] in past_nonces or time.time() - float(dec_response["timestamp"]) > 10):
            print("Message Replay Attack!")
            raise Exception("Message is tainted")
        past_nonces.add(dec_response["server_n"])
        print(dec_response)

        N1 = generate_nonce()
        TS1 = str(time.time())
        auth_client_msg = json.dumps({"message": "Authenticate Client", "client_n": N1, "server_n": dec_response["server_n"], "timestamp": TS1})
        print("Auth Client Message to send:", auth_client_msg)

        enc_auth_client_msg = AESEncryption(XPRE_SHARED_KEY, auth_client_msg)
        print("Encrypted Auth Client Message:", enc_auth_client_msg)
        client.sendall(enc_auth_client_msg.encode())

        response = client.recv(4096).decode()
        print("Received response: ", response)
        dec_response = json.loads(AESDecryption(XPRE_SHARED_KEY ,response))
        if (dec_response["client_n"] != N1 or dec_response["server_n"] in past_nonces or time.time() - float(dec_response["timestamp"]) > 10):
            print("Message Replay Attack!")
            raise Exception("Message is tainted")
        past_nonces.add(dec_response["server_n"])
        print(dec_response)

        master_secret = bytes.fromhex(dec_response["master_secret"])
        print("\nCreating MASTER and MAC keys")
        master_key, hmac_key = derive_keys(master_secret)

        N2 = generate_nonce()
        TS2 = str(time.time())
        verify_client_msg = json.dumps({"message": "Verify Master Key Client", "client_n": N2, "server_n": dec_response["server_n"], "timestamp": TS2})
        print("Verify Master Key Client Message to send:", verify_client_msg)

        enc_verify_client_msg = AESEncryption(master_key, verify_client_msg)
        print("Encrypted Verify Master Key Client Message:", enc_verify_client_msg)
        client.sendall(enc_verify_client_msg.encode())

        final_response = client.recv(4096).decode()
        print("Received final verification response: ", final_response)
        dec_final_response = json.loads(AESDecryption(master_key ,final_response))
        if (dec_final_response["client_n"] != N2 or dec_final_response["server_n"] in past_nonces or time.time() - float(dec_final_response["timestamp"]) > 10):
            print("Message Replay Attack!")
            raise Exception("Message is tainted")
        past_nonces.add(dec_final_response["server_n"])
        print(dec_final_response)

        print("Initial exchange complete!")
    except Exception as e:
        print(e)
        raise e

def send_to_server(message):
    """Handle server communication"""
    global master_key, hmac_key
    try:
        client = con_manager.get_connection()
        
        sent_nonce = generate_nonce()
        send_ts = str(time.time())
        build_message = json.dumps({"message": message, "nonce": sent_nonce, "timestamp": send_ts})
        print("Message to send", build_message)
        enc_build_message =  AESEncryption(master_key, build_message).encode()

        hmac_build_message = hmac.new(hmac_key, enc_build_message, hashlib.sha256).hexdigest().encode()
        print(f"HMAC: {hmac_build_message}")

        final_enc_message = enc_build_message + b"||" + hmac_build_message

        print("Sending message")
        client.sendall(final_enc_message)

        print("Waiting for response")
        response_enc, response_hmac = client.recv(4096).split(b"||")
        response_verify_hmac = hmac.new(hmac_key, response_enc, hashlib.sha256).hexdigest().encode()

        print("Verifying response")
        if response_verify_hmac != response_hmac:
            raise RuntimeError("Mismatched HMAC in response message")
        
        response = json.loads(AESDecryption(master_key, response_enc.decode()))
        
        if response["nonce"] in past_nonces:
            raise RuntimeError("Replayed nonce detected!")
        past_nonces.add(response["nonce"])
        
        if abs(float(response["timestamp"]) - float(send_ts)) > 10:
            raise RuntimeError("Replayed timestamp detected!")

        return response["message"]

    except ConnectionRefusedError:
        sg.popup_error("Server offline!\nStart the server first.")
    except Exception as e:
        sg.popup_error(f"Connection error: {str(e)}")
    return None

def admin_panel(username, audit_logs):
    """Admin Dashboard"""
    menu_def = [['Tools', ['User Management', 'Audit Logs']],
                ['Help', ['About']]]

    user_list_column = [
        [sg.Text("USER MANAGEMENT", font=('Helvetica', 14))],
        [sg.Table(values=[], 
                 headings=['Username', 'Account Created'],
                 key='-USER-TABLE-',
                 col_widths=[20, 25],
                 auto_size_columns=False,
                 justification='left',
                 expand_x=True,
                 expand_y=True,
                 enable_click_events=True)],
        [sg.Button('Refresh'), sg.Button('Logout')]
    ]

    audit_log_column = [
        [sg.Text("AUDIT LOGS", font=('Helvetica', 14))],
        [sg.Multiline(default_text=audit_logs, size=(60, 15), autoscroll=True, disabled=True, key='-LOGS-')],
        [sg.Button('Refresh_Logs'), sg.Button('Logout')]
    ]

    layout = [
        [sg.Menu(menu_def)],
        [sg.Text(f"ADMIN DASHBOARD", font=HEADER_FONT, pad=((0,0),(20,20)))],
        [sg.TabGroup([[sg.Tab('User Management', user_list_column),
                      sg.Tab('Audit Logs', audit_log_column)]])],
        [sg.StatusBar("Ready", key='-STATUS-', size=(50, 1))]
    ]

    window = sg.Window("Bank Admin Portal", layout, finalize=True, resizable=True)

    def refresh_users():
        admin_password = sg.popup_get_text("Enter Admin Password:", password_char='*')
        if not admin_password:
            return
        
        response = send_to_server(f'admin:list_users:{username}:{admin_password}').encode()
        if response == b'ADMIN_DENIED':
            window['-STATUS-'].update("Authorization failed!")
        elif response:
            try:
                users = json.loads(response.decode())
                user_data = [[user['username'], 
                            datetime.fromisoformat(user['created_at']).strftime('%Y-%m-%d %H:%M:%S')]
                            for user in users]
                
                window['-USER-TABLE-'].update(values=user_data)
                window['-STATUS-'].update(f"Loaded {len(users)} users")
            except Exception as e:
                window['-STATUS-'].update(f"Error: {str(e)}")
    
    def refresh_logs():
        try:
            response = send_to_server('update:logs')
            test = '\n'.join(json.dumps(x) for x in response)
            window['-LOGS-'].update(test)

        except Exception as e:
            sg.popup_error(f"Connection error: {str(e)}")


    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, 'Logout'):
            break

        if event == 'User Management':
            refresh_users()
        elif event == 'Refresh':
            refresh_users()
        elif event == 'Refresh_Logs':
            refresh_logs()
        elif event == '-USER-TABLE-':  
            col_clicked = values[event][1]
            user_data = window['-USER-TABLE-'].get()
            # Sort by clicked column (0: username, 1: creation date)
            user_data.sort(key=lambda x: x[col_clicked], reverse=True)
            window['-USER-TABLE-'].update(values=user_data)

    window.close()
    main_window()

def main_window():
    """Banking Interface"""
    login_layout = [
        [sg.Image('bank_logo.png', size=(100, 100), pad=((0,0),(0,20)))], 
        [sg.Text("Secure Banking Portal", font=HEADER_FONT, justification='center')],
        [sg.HorizontalSeparator()],
        [sg.Text('Username', font=TEXT_FONT, size=(10,1)), 
         sg.Input(key='-USER-', font=TEXT_FONT, size=INPUT_SIZE)],
        [sg.Text('Password', font=TEXT_FONT, size=(10,1)), 
         sg.Input(key='-PASS-', password_char='*', font=TEXT_FONT, size=INPUT_SIZE)],
        [sg.HorizontalSeparator()],
        [sg.Button('Login', button_color=('white', '#0078D4'), font=BUTTON_FONT, size=(10,1)),
         sg.Button('Register', button_color=('white', '#2C3E50'), font=BUTTON_FONT, size=(10,1))],
        [sg.Text("", key='-STATUS-', text_color='red', font=('Helvetica', 10))]
    ]

    window = sg.Window("Secure Banking System", 
                      login_layout, 
                      element_justification='center',
                      margins=(20, 20))

    while True:
        event, values = window.read()
        
        if event in (sg.WIN_CLOSED, 'Exit'):
            break
            
        username = values['-USER-'].strip()
        password = values['-PASS-'].strip()
        
        if not username or not password:
            window['-STATUS-'].update("All fields are required!")
            continue
            
        if event == 'Register':
            window['-STATUS-'].update("Processing registration...")
            response = send_to_server(f'register:{username}:{password}').encode()
            if response == b'REGISTER_SUCCESS':
                sg.popup_ok("Account Created!\nYou can now login.", title="Success")
                window['-STATUS-'].update("")
            elif response == b'USER_EXISTS':
                window['-STATUS-'].update("Username already exists!")
            else:
                window['-STATUS-'].update("Registration failed!")
                
        elif event == 'Login':
            window['-STATUS-'].update("Authenticating...")
            response = send_to_server(f'login:{username}:{password}').encode()
            if response == b'LOGIN_FAILED':
                window['-STATUS-'].update("Invalid credentials!")
            elif response:
                try:
                    window.close()
                    if username == "admin":
                        admin_panel(username, '')
                    else:
                        response = json.loads(response.decode())
                        user_dashboard(username, response, [])
                except:
                    window['-STATUS-'].update("Authentication failed!")

    window.close()

def user_dashboard(username, user_data, log_entry):
    """User Dashboard"""
    account_summary = [
        [sg.Text("Account Summary", font=HEADER_FONT)],
        [sg.HorizontalSeparator()],
        [sg.Text("Current Balance:", font=TEXT_FONT), 
         sg.Text(user_data["balance"], font=('Helvetica', 18), key='-BALANCE-')]
    ]

    transaction_history = [
        [sg.Table(values=log_entry, headings=['Date', 'Type', 'Amount'], 
        key='-TRANSACTIONS-',
        auto_size_columns=False,
        col_widths=[12, 12, 12],
        justification='left',
        expand_x=True)]
    ]

    layout = [
        [sg.Text(f"Welcome, {username}", font=HEADER_FONT)],
        [sg.Column(account_summary, pad=((0,0),(0,20)))],
        [sg.Text("Recent Transactions", font=('Helvetica', 14))],
        [sg.Column(transaction_history, expand_x=True, expand_y=True)],
        [sg.HorizontalSeparator()],
        [sg.Text("Amount:", font=TEXT_FONT), 
         sg.Input(size=(15,1), 
         key='-AMOUNT-', 
         tooltip="Enter transaction amount")],
        [sg.Button('Deposit', button_color=('white', '#2ECC71')),
         sg.Button('Withdraw', button_color=('white', '#E74C3C'))],
        [sg.Button('Logout', expand_x=True)]
    ]

    window = sg.Window("Banking Dashboard", 
                      layout, 
                      resizable=True, 
                      finalize=True,
                      margins=(20, 20))

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, 'Logout'):
            break

        # Handle transactions
        if event in ('Deposit', 'Withdraw'):
            amount_str = values['-AMOUNT-'].strip()
            
            if not amount_str:
                sg.popup_error("Please enter an amount!")
                continue
                
            try:
                amount = float(amount_str)
                if amount <= 0:
                    raise ValueError
            except ValueError:
                sg.popup_error("Invalid amount!\nPlease enter a positive number.")
                continue

            # Here you would typically send to server
            transaction_type = "Deposit" if event == 'Deposit' else "Withdrawal"
            sg.popup_quick(f"Processing {transaction_type} of ${amount:.2f}")
            
            response = json.loads(send_to_server(json.dumps({"username": username, "action": transaction_type, "amount": amount})))
            new_balance = response["balance"]
            window['-BALANCE-'].update(f"${new_balance:,.2f}")

            log_entry.append([datetime.now().strftime('%Y-%m-%d %H:%M:%S'), transaction_type, amount])
            window['-TRANSACTIONS-'].update(log_entry)

            # Clear input field after transaction
            window['-AMOUNT-'].update('')

    window.close()
    main_window()

if __name__ == '__main__':
    exchange_keys()
    main_window()