import socket
import json
import secrets
import hmac

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hashlib import sha256
from datetime import datetime

SHARED_KEY = b"network security"  # Shared key constant


# Bank client class
class BankClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))

    def login_and_authenticate(self, username, password):
        # send username and password
        print(username)
        print(password)
        encoded_login = self.pad((username + "_" + password).encode())
        self.client_socket.sendall(encoded_login)

        login_confirm = (
            self.client_socket.recv(480).decode().strip()
        )  # receive login confirmation message
        print(login_confirm)

        if login_confirm != "Login successful":
            return False

        server_nonce = self.client_socket.recv(16)  # receive encrypted nonce
        # decrypt encryted nonce using shared key, and send to server for authentication
        self.client_socket.send(
            self.encrypt_data(self.decrypt_data(server_nonce, SHARED_KEY), SHARED_KEY)
        )

        # receive authentication confirmation
        auth_confirm = self.client_socket.recv(480).decode().strip()
        print(auth_confirm)

        if auth_confirm != "Client is successfully authenticated.":
            return False

        # Now, client authenticates server
        nonce = secrets.token_bytes(16)
        self.client_socket.sendall(self.encrypt_data(nonce, SHARED_KEY))

        # Receive nonce from server
        server_nonce = self.client_socket.recv(16)
        if nonce == self.decrypt_data(server_nonce, SHARED_KEY):
            print("Client successfully authenticated server")
            return True

    def pad(self, message):
        return message.ljust(480)

    def encrypt_data(self, original_data, encryption_key):
        # Encrypt transaction data
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CBC(b"\x00" * 16),
            backend=default_backend(),
        )
        encryptor_block = cipher.encryptor()
        original_data = (
            encryptor_block.update(original_data) + encryptor_block.finalize()
        )
        return original_data.rstrip(b"\x00")

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


# Main function
if __name__ == "__main__":
    # Initialize client
    bank_client = BankClient("localhost", 50000)  # call the constructor

    try:
        isActive = True
        username = input("Please enter your username: ")
        password = input("Please enter your password: ")
        continueSession = ""
        while isActive:
            if continueSession == "y" or bank_client.login_and_authenticate(
                username, password
            ):
                if continueSession != "y":
                    # recieve encryption and mac keys from the server
                    encryption_key = bank_client.client_socket.recv(16)
                    mac_key = bank_client.client_socket.recv(16)

                else:
                    print("Re-entering while loop to perform another transaction")

                action = input(
                    "Please enter the type of transaction you wish to complete: "
                )

                while action not in ["deposit", "withdraw", "banking inquiry"]:
                    action = input("Invalid action. Please choose another action: ")

                amount = ""
                if action != "inquiry":
                    amount = input(
                        "Please enter the amount you wish to deposit/withdraw (Enter 0 for banking inquiry): "
                    )

                # Generate current timestamp
                timestamp = datetime.now()

                # Format timestamp as string
                timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                transaction_message = bank_client.encrypt_data(
                    bank_client.pad(
                        (action + "/" + amount + "/" + timestamp_str).encode()
                    ),
                    encryption_key,
                )
                bank_client.client_socket.send(transaction_message)
                bank_client.client_socket.send(
                    hmac.new(mac_key, transaction_message, sha256).digest()
                )
                transaction_response = bank_client.client_socket.recv(480)
                server_mac = bank_client.client_socket.recv(32)
                expected_mac = hmac.new(mac_key, transaction_response, sha256).digest()

                if hmac.compare_digest(server_mac, expected_mac):
                    print("MAC sent by server is valid, checked by client")
                    print(
                        "Response: "
                        + bank_client.decrypt_data(
                            transaction_response, encryption_key
                        ).decode()
                    )
                else:
                    print("MAC sent by server is not valid.")

                continueSession = input(
                    "Do you wish to perform any other banking action (y/n)? "
                )

                if continueSession == "n":
                    isActive = False

            else:  # login/authentication unsuccessful
                print(
                    "Login and/or nonce authentication unsuccessful. Please try again."
                )
                username = input("Please re-enter your username: ")
                password = input("Please re-enter your password: ")
                continueSession = "retry"

    finally:
        print("Exited while loop, bank client closing connection.")
        """encrypted_message = bank_client.encrypt_data(bank_client.pad(b"Client socket is closing connection"), encryption_key)
        bank_client.client_socket.send(encrypted_message)
        bank_client.client_socket.send(hmac.new(mac_key, encrypted_message, sha256).digest())"""
        # Close connection
        bank_client.client_socket.close()
