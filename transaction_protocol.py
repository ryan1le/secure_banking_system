import hashlib
import os
import json
import hmac
import time
import struct
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

class TransactionProtocol:
    def __init__(self):
        self.des_key = b'\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81'  # 8-byte DES key
        self.nonce_cache = set()
        self.log_file = "audit.log"

    # Encryption function using DES
    def _encrypt(self, plaintext):
        cipher = DES.new(self.des_key, DES.MODE_ECB)
        return cipher.encrypt(pad(plaintext.encode(), DES.block_size))

    # Decryption function use DES
    def _decrypt(self, ciphertext):
        cipher = DES.new(self.des_key, DES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), DES.block_size).decode()

    # Logging Transaction into encrpyted audit file
    def _log_transaction(self, transaction):
        log_entry = {
            "customer_id": transaction["customer_id"],
            "action": transaction["action"],
            "timestamp": datetime.now().isoformat()
        }
        if transaction["action"] in ('Deposit', 'Withdrawal', 'Balance'):
            log_entry["amount"] = transaction["amount"]

        encrypted_log = self._encrypt(json.dumps(log_entry))
        with open(self.log_file, "ab") as f:
            f.write(struct.pack("I", len(encrypted_log)) + encrypted_log)

    # Reading and Decrypting audit log file to view 
    def view_audit_log(self):
        if not os.path.exists(self.log_file):
            return print("No audit log found")
        
        logs = []

        with open(self.log_file, "rb") as f:
            while length_data := f.read(4):
                entry_length = struct.unpack("I", length_data)[0]
                encrypted_entry = f.read(entry_length)
                try:
                    logs.append(self._decrypt(encrypted_entry))
                except:
                    print("Invalid log entry (skipping)")
        
        return logs