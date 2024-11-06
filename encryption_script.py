import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64
import sys

# Constants
KEY_FILE = "secret.key"
SALT = b'\x00'*16  # Use a secure random salt in production
ITERATIONS = 100000

# Function to generate a key and save it to a file
def generate_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved to secret.key")

# Function to load the key from a file
def load_key(password):
    if not os.path.exists(KEY_FILE):
        print("Key file not found. Please generate a key first.")
        sys.exit(1)
    with open(KEY_FILE, "rb") as key_file:
        key = key_file.read()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Function to encrypt a file
def encrypt_file(file_path, key):
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()

        with open(file_path, "wb") as file:
            file.write(encrypted_data)
        print(f"File {file_path} encrypted successfully.")
    except Exception as e:
        print(f"Error encrypting file {file_path}: {e}")

# Function to decrypt a file
def decrypt_file(file_path, key):
    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        
        iv = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        file_data = unpadder.update(padded_data) + unpadder.finalize()

        with open(file_path, "wb") as file:
            file.write(file_data)
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
    parser.add_argument("--password", required=True, help="Password for key derivation")
    args = parser.parse_args()

    if args.action == "generate_key":
        generate_key(args.password)
    else:
        key = load_key(args.password)
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