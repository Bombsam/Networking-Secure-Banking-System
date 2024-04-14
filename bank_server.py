import json, secrets, hmac, socket, threading

from hashlib import sha256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Global variables
REGISTERED_CLIENTS = {
    "user1_pass1": 500,
    "user2_pass2": 400,
    "user3_pass3": 600,
}
AUDIT_LOG_FILE = "audit_log.bin"
SHARED_KEY = b"network security"  # Shared key constant


# Bank Server class
class BankServer:
    def __init__(self, host, port):  # constructor
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))

    def handle_client(self, client_socket, client_address):
        try:
            while True:
                accountKey = (
                    client_socket.recv(480).decode().strip()
                )  # <username>_<password>

                if (
                    accountKey in REGISTERED_CLIENTS.keys()
                ):  # indicates that user submitted valid login information
                    client_socket.sendall(self.pad(b"Login successful"))
                    # Generate a nonce for authentication
                    server_nonce = secrets.token_bytes(16)
                    client_socket.sendall(self.encrypt_data(server_nonce, SHARED_KEY))

                    # Receive nonce from client
                    client_nonce = client_socket.recv(16)

                    # Authenticate client using nonces and shared key
                    if server_nonce == self.decrypt_data(client_nonce, SHARED_KEY):
                        client_socket.sendall(
                            self.pad(b"Client is successfully authenticated.")
                        )

                        # Now, server is authenticated by client
                        client_socket.sendall(
                            self.encrypt_data(
                                self.decrypt_data(client_socket.recv(16), SHARED_KEY),
                                SHARED_KEY,
                            )
                        )
                        # Run authenticated key distribution protocol
                        master_secret = (
                            self.run_authenticated_key_distribution_protocol(
                                client_socket
                            )
                        )

                        # Derive encryption key and MAC key from master secret
                        encryption_key, mac_key = self.derive_keys_from_master_secret(
                            master_secret
                        )
                        client_socket.sendall(encryption_key)
                        client_socket.sendall(mac_key)

                        while True:
                            # Receive encrypted transaction data from client
                            encrypted_transaction_data = client_socket.recv(480)

                            # Receive MAC from client
                            received_mac = client_socket.recv(32)

                            # Verify MAC
                            calculated_mac = hmac.new(
                                mac_key, encrypted_transaction_data, sha256
                            ).digest()

                            if hmac.compare_digest(received_mac, calculated_mac):
                                print("The mac generated by the client is valid")
                                # Decrypt transaction data
                                transaction_data = self.decrypt_data(
                                    encrypted_transaction_data, encryption_key
                                )

                                # Process transaction

                                transaction = transaction_data.decode().split(
                                    "/"
                                )  # <action>/<amount>
                                action = transaction[0].strip()
                                amount = int(transaction[1])
                                if action == "deposit":
                                    print("entered deposit")
                                    REGISTERED_CLIENTS[accountKey] += amount
                                elif action == "withdraw":
                                    if amount <= REGISTERED_CLIENTS[accountKey]:
                                        REGISTERED_CLIENTS[accountKey] -= amount
                                    else:
                                        client_socket.sendall(
                                            (
                                                self.encrypt_data(
                                                    self.pad(
                                                        b"Withdrawal cannot be processed due to INSUFFICIENT BALANCE"
                                                    ),
                                                    encryption_key,
                                                )
                                            )
                                        )
                                # no change is made for account inquiry
                                # Log transaction
                                log_data = {
                                    "username": accountKey.split("_")[0],
                                    "action": action,
                                    "time": transaction[2].strip(),
                                }

                                self.encrypt_and_write_to_log(
                                    log_data, encryption_key, AUDIT_LOG_FILE
                                )  # data must be encrypted prior to writing ot the log file

                                message = (
                                    "Transaction is successful. Your current balance is: "
                                    + str(REGISTERED_CLIENTS[accountKey])
                                    + " dollars."
                                ).encode()
                                # Encrypt data prior to sending it to client
                                encrypted_message = self.encrypt_data(
                                    self.pad(message), encryption_key
                                )
                                client_socket.sendall(encrypted_message)
                                client_socket.sendall(
                                    hmac.new(
                                        mac_key, encrypted_message, sha256
                                    ).digest()
                                )

                            else:  # hmac values do not match
                                message = b"Transaction failed due to data tampering. HMAC values do not match."  # converted to bytes
                                encrypted_message = self.encrypt_data(
                                    self.pad(message), encryption_key
                                )
                                client_socket.sendall(
                                    self.encrypt_data(self.pad(message), encryption_key)
                                )
                    else:
                        print("Authentication failed. Nonces do not match.")
                        message = b"Authentication failed. Nonces do not match."
                        client_socket.sendall(self.pad(message))
                else:
                    message = b"Authentication error. User logged in with invalid credentials."
                    client_socket.sendall(self.pad(message))

        except Exception as e:
            print(f"Client {client_address}: {str(e)} focibly closed connection")
        finally:
            client_socket.close()

    def run_authenticated_key_distribution_protocol(self, client_socket):
        # Generate Master Secret
        master_secret = secrets.token_bytes(32)
        # Send Master Secret to client
        # client_socket.sendall(master_secret) #no need to encode, as message is already in bytes
        return master_secret

    def pad(self, message):
        return message.ljust(480)

    def derive_keys_from_master_secret(self, master_secret):
        # Derive encryption key and MAC key
        encryption_key = master_secret[
            :16
        ]  # Use the first 16 bytes of the master secret as the encryption key
        mac_key = master_secret[
            16:
        ]  # Use the remaining bytes of the master secret as the MAC key
        return encryption_key, mac_key

    def encrypt_data(self, encrypted_data, encryption_key):
        # Encrypt transaction data
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CBC(b"\x00" * 16),
            backend=default_backend(),
        )
        encryptor_block = cipher.encryptor()
        encrypted_data = (
            encryptor_block.update(encrypted_data) + encryptor_block.finalize()
        )
        return encrypted_data.rstrip(b"\x00")

    def decrypt_data(self, encrypted_data, encryption_key):
        # Decrypt transaction data
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CBC(b"\x00" * 16),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted_data.rstrip(b"\x00")

    def encrypt_and_write_to_log(self, data, encryption_key, log_file):
        # Encrypt log data
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CBC(b"\x00" * 16),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        encrypted_data = (
            encryptor.update(self.pad(json.dumps(data).encode())) + encryptor.finalize()
        )

        # Write encrypted data to log file
        with open(log_file, "ab") as f:
            f.write(encrypted_data)

        print("audit log successful")
        decryptor = cipher.decryptor()
        print("Transaction information: " + decryptor.update(encrypted_data).decode())

    # authentication protocol
    def authenticate_client(self, client_nonce, server_nonce):
        # Authenticate client using nonces and shared key
        expected_hmac = hmac.HMAC(
            SHARED_KEY, hashes.SHA256(), backend=default_backend()
        )
        expected_hmac.update(server_nonce)
        expected_mac = expected_hmac.finalize()
        client_mac = hmac.HMAC(SHARED_KEY, hashes.SHA256(), backend=default_backend())
        client_mac.update(client_nonce)
        return hmac.compare_digest(expected_mac, client_mac.finalize())

    def start(self):
        self.server_socket.listen(5)
        print(f"Bank server listening on {self.host}:{self.port}...")
        while True:
            client_socket, client_address = (
                self.server_socket.accept()
            )  # accept new connection
            print(f"New connection from {client_address}")
            client_thread = threading.Thread(
                target=self.handle_client, args=(client_socket, client_address)
            )
            client_thread.start()


# Main function
if __name__ == "__main__":
    bank_server = BankServer("localhost", 50000)
    bank_server.start()