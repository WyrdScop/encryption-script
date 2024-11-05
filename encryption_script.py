import argparse
from cryptography.fernet import Fernet
import os

# Function to generate a key and save it to a file
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Function to load the key from a file
def load_key():
    return open("secret.key", "rb").read()

# Function to encrypt a file
def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_path, "wb") as file:
        file.write(encrypted_data)

# Function to decrypt a file
def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_path, "wb") as file:
        file.write(decrypted_data)

# Function to encrypt all files in a folder
def encrypt_folder(folder_path, key):
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, key)

# Function to decrypt all files in a folder
def decrypt_folder(folder_path, key):
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file(file_path, key)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files and folders.")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Action to perform: encrypt or decrypt")
    parser.add_argument("path", help="Path to the file or folder")
    args = parser.parse_args()

    key = load_key()

    if args.action == "encrypt":
        if os.path.isfile(args.path):
            encrypt_file(args.path, key)
        elif os.path.isdir(args.path):
            encrypt_folder(args.path, key)
    elif args.action == "decrypt":
        if os.path.isfile(args.path):
            decrypt_file(args.path, key)
        elif os.path.isdir(args.path):
            decrypt_folder(args.path, key)
        