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
    def __init__(self, master):
        self.master = master
        master.title("Secure Text Transfer")

        # Encryption Section
        self.label_file_enc = tk.Label(master, text="Select File:")
        self.label_file_enc.grid(row=0, column=0, sticky='E', padx=5, pady=2)

        self.file_path_entry_enc = tk.Entry(master)
        self.file_path_entry_enc.grid(row=0, column=1, columnspan=7, sticky="WE", pady=3)

        self.browse_button_enc = tk.Button(master, text="Browse ...", command=self.select_file_enc)
        self.browse_button_enc.grid(row=0, column=8, sticky='W', padx=5, pady=2)

        self.label_destination_enc = tk.Label(master, text="Destination Folder:")
        self.label_destination_enc.grid(row=1, column=0, sticky='E', padx=5, pady=2)

        self.destination_entry_enc = tk.Entry(master)
        self.destination_entry_enc.grid(row=1, column=1, columnspan=7, sticky="WE", pady=2)

        self.destination_button_enc = tk.Button(master, text="Browse ...", command=self.select_destination_enc)
        self.destination_button_enc.grid(row=1, column=8, sticky='W', padx=5, pady=2)

        self.label_public_key_receiver = tk.Label(master, text="Public Key of Receiver:")
        self.label_public_key_receiver.grid(row=2, column=0, sticky='E', padx=5, pady=2)

        self.public_key_receiver_entry = tk.Entry(master)
        self.public_key_receiver_entry.grid(row=2, column=1, sticky='WE', pady=2)

        self.label_private_key_sender = tk.Label(master, text="Private Key of Sender:")
        self.label_private_key_sender.grid(row=2, column=5, padx=5, pady=2)

        self.private_key_sender_entry = tk.Entry(master)
        self.private_key_sender_entry.grid(row=2, column=7, pady=2)

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.grid(row=2, column=8, sticky='W', padx=5, pady=2)

        # Decryption Section
        self.label_file_dec = tk.Label(master, text="Select File:")
        self.label_file_dec.grid(row=3, column=0, sticky='E', padx=5, pady=2)

        self.file_path_entry_dec = tk.Entry(master)
        self.file_path_entry_dec.grid(row=3, column=1, columnspan=7, sticky="WE", pady=3)

        self.browse_button_dec = tk.Button(master, text="Browse ...", command=self.select_file_dec)
        self.browse_button_dec.grid(row=3, column=8, sticky='W', padx=5, pady=2)

        self.label_destination_dec = tk.Label(master, text="Destination Folder:")
        self.label_destination_dec.grid(row=4, column=0, sticky='E', padx=5, pady=2)

        self.destination_entry_dec = tk.Entry(master)
        self.destination_entry_dec.grid(row=4, column=1, columnspan=7, sticky="WE", pady=2)

        self.destination_button_dec = tk.Button(master, text="Browse ...", command=self.select_destination_dec)
        self.destination_button_dec.grid(row=4, column=8, sticky='W', padx=5, pady=2)

        self.label_public_key_sender = tk.Label(master, text="Public Key of Sender:")
        self.label_public_key_sender.grid(row=5, column=0, sticky='E', padx=5, pady=2)

        self.public_key_sender_entry = tk.Entry(master)
        self.public_key_sender_entry.grid(row=5, column=1, sticky='WE', pady=2)

        self.label_private_key_receiver = tk.Label(master, text="Private Key of Receiver:")
        self.label_private_key_receiver.grid(row=5, column=5, padx=5, pady=2)

        self.private_key_receiver_entry = tk.Entry(master)
        self.private_key_receiver_entry.grid(row=5, column=7, pady=2)

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.grid(row=5, column=8, sticky='W', padx=5, pady=2)

        self.dh = DiffieHellman()
        self.secret_key = None

    def select_file_enc(self):
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        self.file_path_entry_enc.delete(0, tk.END)
        self.file_path_entry_enc.insert(tk.END, file_path)

    def select_destination_enc(self):
        destination_path = filedialog.askdirectory(title="Select Destination Folder")
        self.destination_entry_enc.delete(0, tk.END)
        self.destination_entry_enc.insert(tk.END, destination_path)

    def select_file_dec(self):
        file_path = filedialog.askopenfilename(title="Select File to Decrypt")
        self.file_path_entry_dec.delete(0, tk.END)
        self.file_path_entry_dec.insert(tk.END, file_path)

    def select_destination_dec(self):
        destination_path = filedialog.askdirectory(title="Select Destination Folder")
        self.destination_entry_dec.delete(0, tk.END)
        self.destination_entry_dec.insert(tk.END, destination_path)

    def generate_secret_key(self, other_public_key):
        self.dh.generate_secret_key(other_public_key)
        self.secret_key = hashlib.sha256(str(self.dh.secret_key).encode()).digest()

    def encrypt_file(self):
        sender_private_key = int(self.private_key_sender_entry.get())
        receiver_public_key = int(self.public_key_receiver_entry.get())

        self.generate_secret_key(receiver_public_key)

        if not self.secret_key:
            raise ValueError("Secret key not generated.")

        file_path = self.file_path_entry_enc.get()
        destination_path = self.destination_entry_enc.get()

        with open(file_path, 'rb') as file:
            plaintext = file.read()

        cipher = AES.new(self.secret_key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        output_file_path = os.path.join(destination_path, "encrypted_file.enc")
        with open(output_file_path, 'wb') as file:
            file.write(cipher.iv + ciphertext)

    def decrypt_file(self):
        receiver_private_key = int(self.private_key_receiver_entry.get())
        sender_public_key = int(self.public_key_sender_entry.get())

        self.generate_secret_key(sender_public_key)

        if not self.secret_key:
            raise ValueError("Secret key not generated.")

        file_path = self.file_path_entry_dec.get()
        destination_path = self.destination_entry_dec.get()

        with open(file_path, 'rb') as file:
            iv = file.read(16)
            ciphertext = file.read()

        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv=iv)
        try:
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except ValueError:
            print("Padding is incorrect. File may be corrupted or not encrypted properly.")
            return

        output_file_path = os.path.join(destination_path, "decrypted_file.txt")
        with open(output_file_path, 'wb') as file:
            file.write(plaintext)

if __name__ == "__main__":
    root = tk.Tk()
    app = StandaloneApplication(root)
    root.mainloop()
