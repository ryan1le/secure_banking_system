import PySimpleGUI as sg
import socket
import json
from cryptography.fernet import Fernet
from datetime import datetime

# Configuration
HOST = 'localhost'
PORT = 9999
PRE_SHARED_KEY = b'2ZOxp2vxL4fYd7e8NlqQZ7W9mF1J3K6gR0sT4V2CJ5M='
cipher_suite = Fernet(PRE_SHARED_KEY)

# Theme and Colors
sg.theme('DarkBlue3')
HEADER_FONT = ('Helvetica', 20, 'bold')
BUTTON_FONT = ('Helvetica', 12)
TEXT_FONT = ('Helvetica', 12)
INPUT_SIZE = (25, 1)

def send_to_server(message):
    """Handle server communication"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((HOST, PORT))
            s.send(message.encode())
            return s.recv(1024)
    except ConnectionRefusedError:
        sg.popup_error("Server offline!\nStart the server first.")
    except Exception as e:
        sg.popup_error(f"Connection error: {str(e)}")
    return None

def admin_panel(username):
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
        [sg.Multiline(default_text='', size=(60, 15), autoscroll=True, disabled=True)]
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
        
        response = send_to_server(f'admin:list_users:{username}:{admin_password}')
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

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, 'Logout'):
            break

        if event == 'User Management':
            refresh_users()
        elif event == 'Refresh':
            refresh_users()
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
            response = send_to_server(f'register:{username}:{password}')
            if response == b'REGISTER_SUCCESS':
                sg.popup_ok("Account Created!\nYou can now login.", title="Success")
                window['-STATUS-'].update("")
            elif response == b'USER_EXISTS':
                window['-STATUS-'].update("Username already exists!")
            else:
                window['-STATUS-'].update("Registration failed!")
                
        elif event == 'Login':
            window['-STATUS-'].update("Authenticating...")
            response = send_to_server(f'login:{username}:{password}')
            if response == b'LOGIN_FAILED':
                window['-STATUS-'].update("Invalid credentials!")
            elif response:
                try:
                    cipher_suite.decrypt(response)
                    window.close()
                    if username == "admin":
                        admin_panel(username)
                    else:
                        user_dashboard(username)
                except:
                    window['-STATUS-'].update("Authentication failed!")

    window.close()

def user_dashboard(username):
    """User Dashboard"""
    account_summary = [
        [sg.Text("Account Summary", font=HEADER_FONT)],
        [sg.HorizontalSeparator()],
        [sg.Text("Current Balance:", font=TEXT_FONT), 
         sg.Text("$12,345.67", font=('Helvetica', 18), key='-BALANCE-')]
    ]

    transaction_history = [
        [sg.Table(values=[
            ["2023-01-01", "Deposit", "$1,000.00"],
            ["2023-01-02", "Withdrawal", "$200.00"]
        ], headings=['Date', 'Type', 'Amount'], 
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
         sg.Button('Withdraw', button_color=('white', '#E74C3C')),
         sg.Button('Balance', button_color=('white', '#3498DB'))],
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

            # Update balance (simulated - replace with actual server communication)
            current_balance = float(window['-BALANCE-'].get().replace('$','').replace(',',''))
            new_balance = current_balance + (amount if event == 'Deposit' else -amount)
            window['-BALANCE-'].update(f"${new_balance:,.2f}")

            # Clear input field after transaction
            window['-AMOUNT-'].update('')

    window.close()
    main_window()

if __name__ == '__main__':
    main_window()