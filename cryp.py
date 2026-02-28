import os
from cryptography.fernet import Fernet
import json
import sys
from tqdm import tqdm
import getpass




class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


# 1. Generate and save a key (Do this only once!)
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("[+] Key generated and saved as 'secret.key'. Keep it safe!")

# 2. Load the existing key
def load_key():
    return open("secret.key", "rb").read()

# 3. Encrypt a file
def encrypt_file(file_path):
    key = load_key()
    if not key: return
    f = Fernet(key)
  
    file_size = os.path.getsize(file_path)
    
    # Fernet لا يدعم التشفير على أجزاء (Streaming) بشكل مباشر بسهولة، 
    # لذا سنستخدم tqdm لإظهار حالة القراءة والمعالجة
    with tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Encrypting {os.path.basename(file_path)}") as pbar:
        with open(file_path, "rb") as file:
            file_data = file.read()
            pbar.update(file_size) # تحديث الشريط بعد القراءة
    
    encrypted_data = f.encrypt(file_data)
    
    with open(file_path, "wb") as file:
        file.write(encrypted_data)
    print(f"\n{Colors.GREEN}[✔] File {file_path} has been ENCRYPTED.{Colors.END}")
# 4. Decrypt a file
def decrypt_file(file_path):
    secret_key_check=getpass.getpass(f"{Colors.YELLOW}Enter the secret key to decrypt the file: {Colors.END}").strip().encode('utf-8')
  
    

    key = secret_key_check
   
    f = Fernet(key)
    
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    
    try:
        decrypted_data = f.decrypt(encrypted_data)
        with open(file_path, "wb") as file:
            file.write(decrypted_data)
        print(f"[!] File {file_path} has been DECRYPTED.")
    except Exception:
        print("[X] Invalid Key or file is not encrypted.")