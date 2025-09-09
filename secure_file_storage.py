import os
import hashlib
import base64
import json
from cryptography.fernet import Fernet
from datetime import datetime

# --- Constants ---
METADATA_FILE = "file_metadata.json"
KEY_FILE = "secret.key"

# --- Helper Functions ---

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    print("[+] Encryption key generated and saved.")
    return key

def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

def sha256_hash(filepath):
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            sha.update(chunk)
    return sha.hexdigest()

def save_metadata(filename, hash_value):
    data = {
        "original_filename": filename,
        "timestamp": datetime.now().isoformat(),
        "sha256": hash_value
    }
    with open(METADATA_FILE, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Metadata saved to {METADATA_FILE}")

def load_metadata():
    if not os.path.exists(METADATA_FILE):
        print("[!] Metadata file not found.")
        return None
    with open(METADATA_FILE, "r") as f:
        return json.load(f)

# --- Core Functions ---

def encrypt_file(filepath):
    key = load_key()
    fernet = Fernet(key)

    with open(filepath, "rb") as file:
        original = file.read()

    encrypted = fernet.encrypt(original)

    encrypted_filename = filepath + ".enc"
    with open(encrypted_filename, "wb") as enc_file:
        enc_file.write(encrypted)

    file_hash = sha256_hash(filepath)
    save_metadata(filepath, file_hash)

    print(f"[✓] File encrypted: {encrypted_filename}")

def decrypt_file(encrypted_filepath):
    key = load_key()
    fernet = Fernet(key)

    with open(encrypted_filepath, "rb") as enc_file:
        encrypted = enc_file.read()

    decrypted = fernet.decrypt(encrypted)

    original_filename = encrypted_filepath.replace(".enc", "_decrypted")

    with open(original_filename, "wb") as dec_file:
        dec_file.write(decrypted)

    file_hash = sha256_hash(original_filename)
    metadata = load_metadata()

    if metadata:
        if file_hash == metadata["sha256"]:
            print(f"[✓] Decryption successful and hash verified.")
        else:
            print("[!] WARNING: File was decrypted, but integrity check FAILED!")
    else:
        print("[!] Metadata not available for verification.")

    print(f"[✓] File decrypted: {original_filename}")

# --- CLI Interface ---
if __name__ == "__main__":
    print("=== Secure File Storage System (AES-256) ===")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Enter choice (1 or 2): ")

    if choice == "1":
        path = input("Enter path to file to encrypt: ").strip()
        if os.path.exists(path):
            encrypt_file(path)
        else:
            print("[!] File not found.")
    elif choice == "2":
        path = input("Enter path to .enc file to decrypt: ").strip()
        if os.path.exists(path) and path.endswith(".enc"):
            decrypt_file(path)
        else:
            print("[!] Encrypted file not found or invalid format.")
    else:
        print("[!] Invalid choice.")
