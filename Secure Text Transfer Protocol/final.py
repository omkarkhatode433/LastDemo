from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad
import hashlib
import random
import os
import tkinter as tk
from tkinter import filedialog

class DiffieHellman:
    def __init__(self):
        self.p = 23  # Prime number
        self.g = 5   # Primitive root modulo of p
        self.private_key = random.randint(1, self.p - 1)
        self.public_key = pow(self.g, self.private_key, self.p)
        self.secret_key = None

    def generate_secret_key(self, other_public_key):
        self.secret_key = pow(other_public_key, self.private_key, self.p)

class StandaloneApplication:
    def __init__(self):
        self.dh = DiffieHellman()
        self.secret_key = None

    def generate_dh_keys(self):
        return self.dh.public_key

    def generate_secret_key(self, other_public_key):
        self.dh.generate_secret_key(other_public_key)
        self.secret_key = hashlib.sha256(str(self.dh.secret_key).encode()).digest()

    def encrypt_file(self):
        if not self.secret_key:
            raise ValueError("Secret key not generated.")
        
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")

        with open(file_path, 'rb') as file:
            plaintext = file.read()

        cipher = AES.new(self.secret_key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        output_file_path = filedialog.asksaveasfilename(title="Save Encrypted File As", defaultextension=".enc")
        with open(output_file_path, 'wb') as file:
            file.write(cipher.iv + ciphertext)

    def decrypt_file(self):
        if not self.secret_key:
            raise ValueError("Secret key not generated.")
        
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(title="Select File to Decrypt")

        with open(file_path, 'rb') as file:
            iv = file.read(16)
            ciphertext = file.read()

        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv=iv)
        try:
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except ValueError:
            print("Padding is incorrect. File may be corrupted or not encrypted properly.")
            return

        output_file_path = filedialog.asksaveasfilename(title="Save Decrypted File As")
        with open(output_file_path, 'wb') as file:
            file.write(plaintext)

if __name__ == "__main__":
    app = StandaloneApplication()

    # Step 1: Generate Diffie-Hellman keys
    print("Generate Diffie-Hellman keys...")
    my_public_key = app.generate_dh_keys()
    print("My public key:", my_public_key)


    # Step 2: Exchange public keys and generate secret key
    other_public_key = int(input("Enter other user's public key: "))
    app.generate_secret_key(other_public_key)

    # Step 3: Encrypt file
    print("Encrypting file...")
    app.encrypt_file()
    print("File encrypted successfully.")

    # Step 4: Decrypt file
    print("Decrypting file...")
    app.decrypt_file()
    print("File decrypted successfully.")
