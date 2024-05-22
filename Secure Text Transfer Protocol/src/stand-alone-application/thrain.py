import binascii
import os
import ENCDEC  # Assuming this is your encryption/decryption module
import DH  # Assuming this is your Diffie-Hellman module

def encrypt(filename, directory, public_key, private_key):
    key = DH.generate_secret(int(private_key), int(public_key))
    hex_key = binascii.hexlify(key.encode()).decode()[:32]

    with open(filename, "r") as file_obj:
        plaintext = file_obj.read()

    encrypted_msg = ENCDEC.AESCipher(hex_key).encrypt(plaintext)

    output_filename = os.path.join(directory, hex_key[16:] + ".txt")
    with open(output_filename, 'w') as file_obj:
        file_obj.write(encrypted_msg)

    os.remove(filename)
    os.system("xdg-open " + directory)

def decrypt(filename, directory, public_key, private_key):
    key = DH.generate_secret(int(private_key), int(public_key))
    hex_key = binascii.hexlify(key.encode()).decode()[:32]

    with open(filename, "r") as file_obj:
        msg = file_obj.read()

    text = ENCDEC.AESCipher(hex_key).decrypt(msg)

    output_filename = os.path.join(directory, "DecodedFile.txt")
    with open(output_filename, "w") as file_obj:
        file_obj.write(text)

    os.remove(filename)
    os.system("xdg-open " + directory)
