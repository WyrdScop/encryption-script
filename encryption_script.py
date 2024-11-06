import argparse
from cryptography.fernet import Fernet
import os
import sys

# Function to generate a key and save it to a file
def generate_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        print("Key generated and saved to secret.key")
    else:
        print("Key already exists. Skipping key generation.")

# Function to load the key from a file
def load_key():
    if not os.path.exists("secret.key"):
        print("Key file not found. Please generate a key first.")
        sys.exit(1)
    return open("secret.key", "rb").read()

# Function to encrypt a file
def encrypt_file(file_path, key):
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)
        with open(file_path, "wb") as file:
            file.write(encrypted_data)
        print(f"File {file_path} encrypted successfully.")
    except Exception as e:
        print(f"Error encrypting file {file_path}: {e}")

# Function to decrypt a file
def decrypt_file(file_path, key):
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(file_path, "wb") as file:
            file.write(decrypted_data)
        print(f"File {file_path} decrypted successfully.")
    except Exception as e:
        print(f"Error decrypting file {file_path}: {e}")

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
    parser.add_argument("action", choices=["generate_key", "encrypt", "decrypt"], help="Action to perform: generate_key, encrypt or decrypt")
    parser.add_argument("path", nargs='?', help="Path to the file or folder (not needed for generate_key)")
    args = parser.parse_args()

    if args.action == "generate_key":
        generate_key()
    else:
        key = load_key()
        if args.action == "encrypt":
            if os.path.isfile(args.path):
                encrypt_file(args.path, key)
            elif os.path.isdir(args.path):
                encrypt_folder(args.path, key)
            else:
                print(f"Path {args.path} does not exist.")
        elif args.action == "decrypt":
            if os.path.isfile(args.path):
                decrypt_file(args.path, key)
            elif os.path.isdir(args.path):
                decrypt_folder(args.path, key)
            else:
                print(f"Path {args.path} does not exist.")