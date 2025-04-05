import os
import json
import hmac
import time
import struct
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

class TransactionProtocol:
    def __init__(self, des_key, mac_key):
        self.des_key = des_key  # 8-byte DES key
        self.mac_key = mac_key[:8]  # Ensure 8-byte MAC key
        self.nonce_cache = set()
        self.log_file = "audit.log"
        if os.path.exists(self.log_file):
            os.remove(self.log_file)

    # Encryption function using DES
    def _encrypt(self, plaintext):
        cipher = DES.new(self.des_key, DES.MODE_ECB)
        return cipher.encrypt(pad(plaintext.encode(), DES.block_size))

    # Decryption function use DES
    def _decrypt(self, ciphertext):
        cipher = DES.new(self.des_key, DES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), DES.block_size).decode()

    # Generate Mac key
    def _generate_mac(self, data):
        return hmac.new(self.mac_key, data, 'sha256').digest()[:8]

    # Creating Secure transaction with DES-Encryption and MAC
    def create_transaction(self, customer_id, action, amount=None):
        transaction = {
            "customer_id": customer_id,
            "action": action,
            "amount": amount,
            "timestamp": int(time.time()),
            "nonce": os.urandom(8).hex()
        }
        encrypted = self._encrypt(json.dumps(transaction))
        return encrypted + self._generate_mac(encrypted)

    # Verify Mac, Decrypt and Process the transaction
    def process_transaction(self, secure_payload):
        encrypted, received_mac = secure_payload[:-8], secure_payload[-8:]
        
        # Verify HMAC - For Data Integrity
        if not hmac.compare_digest(self._generate_mac(encrypted), received_mac):
            return None, "Integrity check failed"

         # Decrypt and validate transaction
        transaction = json.loads(self._decrypt(encrypted))
        
        # Checking for Replay attack using nonce
        if transaction["nonce"] in self.nonce_cache:
            return None, "Replay attack detected"
        self.nonce_cache.add(transaction["nonce"])

        self._log_transaction(transaction)
        return {"status": "success", **transaction}, None

    # Logging Transaction into encrpyted audit file
    def _log_transaction(self, transaction):
        log_entry = {
            "customer_id": transaction["customer_id"],
            "action": transaction["action"],
            "timestamp": datetime.fromtimestamp(transaction["timestamp"]).isoformat()
        }
        if transaction["action"] in ('deposit', 'withdrawal'):
            log_entry["amount"] = transaction["amount"]

        encrypted_log = self._encrypt(json.dumps(log_entry))
        with open(self.log_file, "ab") as f:
            f.write(struct.pack("I", len(encrypted_log)) + encrypted_log)

    # Reading and Decrypting audit log file to view 
    def view_audit_log(self):
        if not os.path.exists(self.log_file):
            return print("No audit log found")

        with open(self.log_file, "rb") as f:
            while length_data := f.read(4):
                entry_length = struct.unpack("I", length_data)[0]
                encrypted_entry = f.read(entry_length)
                try:
                    print(json.loads(self._decrypt(encrypted_entry)))
                except:
                    print("Invalid log entry (skipping)")