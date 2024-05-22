import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import END
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from dh import generate_private_key, generate_public_key, generate_secret
import hashlib

class SecureTextTransferApp:
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

    def select_file_enc(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_entry_enc.delete(0, END)
            self.file_path_entry_enc.insert(0, file_path)

    def select_destination_enc(self):
        destination_folder = filedialog.askdirectory()
        if destination_folder:
            self.destination_entry_enc.delete(0, END)
            self.destination_entry_enc.insert(0, destination_folder)

    def select_file_dec(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_entry_dec.delete(0, END)
            self.file_path_entry_dec.insert(0, file_path)

    def select_destination_dec(self):
        destination_folder = filedialog.askdirectory()
        if destination_folder:
            self.destination_entry_dec.delete(0, END)
            self.destination_entry_dec.insert(0, destination_folder)

    def encrypt_file(self):
        file_path = self.file_path_entry_enc.get()
        destination_folder = self.destination_entry_enc.get()
        public_key = self.public_key_receiver_entry.get()
        private_key = self.private_key_sender_entry.get()

        if not file_path or not destination_folder or not public_key or not private_key:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        # Generate private and public keys using DH.py functions
        private_key_int = generate_private_key(int(private_key))
        public_key_int = generate_public_key(private_key_int)

        # Generate shared secret key using DH.py function
        shared_key_hex = generate_secret(private_key_int, int(public_key))

        # Convert hexadecimal shared key to bytes
        shared_key_bytes = bytes.fromhex(shared_key_hex)

        # Convert the shared key to a proper AES key by hashing it
        aes_key = hashlib.sha256(shared_key_bytes).digest()

        # Encrypt file using AES
        try:
            cipher = AES.new(aes_key, AES.MODE_CBC)
            with open(file_path, 'rb') as file:
                plaintext = file.read()
                ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

            # Save encrypted file
            save_path = f"{destination_folder}/encrypted_file.txt"
            with open(save_path, 'wb') as file:
                file.write(ciphertext)
            messagebox.showinfo("Success", "File successfully encrypted and saved as 'encrypted_file.txt'.")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_file(self):
        file_path = self.file_path_entry_dec.get()
        destination_folder = self.destination_entry_dec.get()
        public_key = self.public_key_sender_entry.get()
        private_key = self.private_key_receiver_entry.get()

        if not file_path or not destination_folder or not public_key or not private_key:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        # Generate private and public keys using DH.py functions
        private_key_int = generate_private_key(int(private_key))
        public_key_int = generate_public_key(private_key_int)

        # Generate shared secret key using DH.py function
        shared_key_hex = generate_secret(private_key_int, int(public_key))

        # Convert hexadecimal shared key to bytes
        shared_key_bytes = bytes.fromhex(shared_key_hex)

        # Convert the shared key to a proper AES key by hashing it
        aes_key = hashlib.sha256(shared_key_bytes).digest()

        try:
            # Decrypt file using AES
            with open(file_path, 'rb') as file:
                ciphertext = file.read()
            cipher = AES.new(aes_key, AES.MODE_CBC)
            decrypted_data_padded = cipher.decrypt(ciphertext)

            # Remove padding manually
            padding_value = decrypted_data_padded[-1]  # Get the last byte as padding value
            decrypted_data = decrypted_data_padded[:-padding_value]  # Remove padding

            # Show decrypted data in a message box
            decrypted_text = decrypted_data.decode('utf-8')
            if decrypted_text:
                messagebox.showinfo("Decrypted Data", decrypted_text)
            else:
                messagebox.showwarning("Empty", "Decrypted data is empty.")

            # Save decrypted file
            save_path = f"{destination_folder}/decrypted_file.txt"
            with open(save_path, 'wb') as file:
                file.write(decrypted_data)
            messagebox.showinfo("Success", "File successfully decrypted and saved as 'decrypted_file.txt'.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureTextTransferApp(root)
    root.mainloop()
