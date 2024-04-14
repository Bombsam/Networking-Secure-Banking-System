import tkinter as tk
from tkinter import messagebox
import socket
import secrets
import hmac
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hashlib import sha256


class BankClientGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Bank ATM Client")

        # Network setup
        self.host = "localhost"
        self.port = 50000
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Attempt to connect to server
        try:
            self.client_socket.connect((self.host, self.port))
        except ConnectionRefusedError:
            messagebox.showerror("Connection Error", "Unable to connect to the server")
            self.master.destroy()
            return

        # User interface setup
        self.setup_gui()

    def setup_gui(self):
        # Login Interface
        self.login_frame = tk.Frame(self.master)
        self.login_frame.pack(padx=10, pady=10)

        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1)

        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1)

        self.login_button = tk.Button(
            self.login_frame, text="Login", command=self.login
        )
        self.login_button.grid(row=2, columnspan=2)

        # Transaction Interface
        self.transaction_frame = tk.Frame(self.master)

        self.action_var = tk.StringVar(self.transaction_frame)
        self.action_var.set("deposit")  # default action

        tk.OptionMenu(
            self.transaction_frame, self.action_var, "deposit", "withdraw", "inquiry"
        ).grid(row=0, column=0)
        self.amount_entry = tk.Entry(self.transaction_frame)
        self.amount_entry.grid(row=0, column=1)

        self.submit_button = tk.Button(
            self.transaction_frame, text="Submit", command=self.submit_transaction
        )
        self.submit_button.grid(row=1, columnspan=2)

        # Status Display
        self.status_label = tk.Label(self.master, text="", relief="sunken")
        self.status_label.pack(fill=tk.X, padx=10, pady=10)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if self.login_and_authenticate(username, password):
            self.login_frame.pack_forget()
            self.transaction_frame.pack(padx=10, pady=10)
        else:
            messagebox.showerror(
                "Login Failed",
                "Authentication failed, please check your username and password.",
            )

    def login_and_authenticate(self, username, password):
        try:
            # Send username and password
            self.send_message(username + "_" + password)
            # Check login response
            if self.receive_message() != "Login successful":
                return False

            # Continue with authentication process
            server_nonce = self.receive_message()  # Receive encrypted nonce
            self.send_message(
                server_nonce
            )  # Echo back the nonce for server authentication

            # Check authentication confirmation
            if self.receive_message() != "Client is successfully authenticated.":
                return False

            # Receive encryption and MAC keys from the server
            self.encryption_key = self.client_socket.recv(16)
            self.mac_key = self.client_socket.recv(16)

            return True
        except Exception as e:
            messagebox.showerror("Network Error", str(e))
            return False

    def submit_transaction(self):
        action = self.action_var.get()
        amount = self.amount_entry.get()
        if action != "inquiry" and not amount.isdigit():
            messagebox.showerror("Error", "Please enter a valid amount")
            return

        # Prepare and send transaction
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        transaction_data = f"{action}/{amount}/{timestamp}"
        self.send_transaction(transaction_data)

        # Receive and verify the response
        transaction_response = self.receive_message()
        self.status_label.config(text=f"Response: {transaction_response}")

    def send_transaction(self, data):
        encrypted_data = self.encrypt_data(data.encode(), self.encryption_key)
        self.client_socket.send(encrypted_data)
        self.client_socket.send(hmac.new(self.mac_key, encrypted_data, sha256).digest())

    def receive_message(self):
        data = self.client_socket.recv(480)
        return self.decrypt_data(data, self.encryption_key).decode().strip()

    def encrypt_data(self, data, key):
        cipher = Cipher(
            algorithms.AES(key), modes.CBC(b"\x00" * 16), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(self.pad(data)) + encryptor.finalize()

    def decrypt_data(self, data, key):
        cipher = Cipher(
            algorithms.AES(key), modes.CBC(b"\x00" * 16), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def pad(self, data):
        return data.ljust(480, b"\x00")

    def on_closing(self):
        self.client_socket.close()
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = BankClientGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
