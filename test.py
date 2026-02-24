# #!/usr/bin/env python3
# import hashlib
# import os
# import json

# secret_key = "adel"

# def Hashing_engine(file_path):
#     sha256_hash = hashlib.sha256()
#     try:
#         with open(file_path, 'rb') as f:
#             for bite_block in iter(lambda: f.read(4096), b""):
#                 print(f"I am hashing this data: {bite_block.strip()}")#if had any problem remove the strip
#                 # إذا أردت الحماية الحقيقية، لا تستخدم .strip() 
#                 # لأن تغيير السطر الجديد يعتبر "تعديلاً" في الملف
#                 sha256_hash.update(bite_block)
#         # incorporate the secret key into the final hash
#         #sha256_hash.update(secret_key.encode())
#         return sha256_hash.hexdigest()
#     except Exception as e:
#         print(f"Error hashing file {file_path}: {e}")
#         return None

# def main_hash():
#     target_path = input("Enter path: ").strip()
#     if not os.path.exists(target_path):
#         print("Path does not exist")
#         exit(-1)
        
#     db_json = "hash_db.json"
#     re_init = input("re-initialize? (yay/nay): ").strip().lower()
    
#     if re_init == "yay":
#         hashes = {}
#         if os.path.isdir(target_path):
#             # الترتيب الصحيح: root ثم dirs ثم files
#             for root, dirs, files in os.walk(target_path):
#                 for file in files:
#                     full_path = os.path.join(root, file)
#                     hashes[full_path] = Hashing_engine(full_path)
#         else:
#             hashes[target_path] = Hashing_engine(target_path)

#         with open(db_json, 'w') as f:
#             json.dump(hashes, f, indent=4)
#         print("Database updated!")

#     else:
#         if not os.path.exists(db_json):
#             print("No DB found")
#             exit(-1)
#         with open(db_json, 'r') as f:
#             stored = json.load(f)
        
#         for f_path, old_h in stored.items(): # استخدمنا .items() هنا
#             curr_h = Hashing_engine(f_path)
#             if curr_h != old_h:
#                 print(f"!!! MODIFIED: {f_path}")
#             else:
#                 print(f"OK: {f_path}")

# if __name__ == "__main__":
#     main_hash()




#!/usr/bin/env python3
import hashlib
import os
import json
import sys
from tqdm import tqdm
from cryptography.fernet import Fernet
from cryp import generate_key, load_key, encrypt_file, decrypt_file


secret_salt = "adel"


class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    """Displays a cool ASCII banner at startup."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃      FILE INTEGRITY CHECKER & BUILDER          ┃
    ┃            Version 2.0 | By Adel               ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
{Colors.END}"""
    print(banner)




def Hashing_engine(file_path,algorithm):
    """
    Computes the hash of a file using the specified algorithm.
    Supported: 'md5', 'sha1', 'sha256', 'sha512', etc.
    """
    #sha256_hash = hashlib.sha256()
    hash_algorithm = hashlib.new(algorithm)
    try:
        with open(file_path, 'rb') as f:
            file_size = os.path.getsize(file_path)
            for bite_block in iter(lambda: f.read(4096), b""):
                with tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Hashing {os.path.basename(file_path)[:20]}", leave=False) as pbar:
               # print(f"I am hashing this data: {bite_block.strip()}")#if had any problem remove the strip
                  hash_algorithm.update(bite_block)
                  pbar.update(len(bite_block))
        # incorporate the secret key into the final hash
        hash_algorithm.update(secret_salt.encode())
        return hash_algorithm.hexdigest()
    except Exception as e:
        print(f"Error hashing file {file_path}: {e}")
        return None

def main_hash():

    target_path = input(f"{Colors.YELLOW}Enter path:{Colors.END}").strip()
    if not os.path.exists(target_path):
        print(f"{Colors.RED}[!]Path does not exist{Colors.END}")
        exit(-1)
    hash_ask=input("Which hashing algorithm do you want to use? (e.g., md5, sha1, sha256, sha512): ").strip().lower()
    if not hasattr(hashlib, hash_ask):
        print(f"Unsupported hashing algorithm: {hash_ask}")
        exit(-1)
    
        
    db_json = "hash_db.json"

    crypt_choice = input(f"{Colors.YELLOW}Do you want to encrypt the files after hashing? (yay/nay):{Colors.END} ").strip().lower()

    print(f"\n{Colors.MAGENTA}--- SETTINGS ---{Colors.END}")

    re_init = input("re-initialize? (yay/nay): ").strip().lower()
    
    if re_init == "yay":
        hashes = {}
        if os.path.isdir(target_path):
            
            for root, dirs, files in os.walk(target_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    hashes[full_path] = Hashing_engine(full_path, hash_ask)
        else:
            hashes[target_path] = Hashing_engine(target_path, hash_ask)

        with open(db_json, 'w') as f:
            json.dump(hashes, f, indent=4)
        print(f"{Colors.GREEN}[✔]Database updated!{Colors.END}")


    else:
        if not os.path.exists(db_json):
            print(f"{Colors.RED}[!] No DB found{Colors.END}")
            exit(-1)
        with open(db_json, 'r') as f:
            stored = json.load(f)
        
        alg_used = stored.get("algorithm", hash_ask) # in case we want to store the algorithm in the future
        print(f"\n{Colors.CYAN}[*] Checking integrity using {alg_used.upper()}...{Colors.END}\n")
        
        for f_path, old_h in stored.items(): # استخدمنا .items() هنا
            curr_h = Hashing_engine(f_path,algorithm=hash_ask)
            if curr_h != old_h:
                print(f"{Colors.RED}[MODIFIED]: {Colors.END}{f_path}")
            else:
                print(f"{Colors.GREEN}[SAVE]: {Colors.END}{f_path}")



def main_menu():
    print_banner()
    print(f"{Colors.MAGENTA}--- CONTROL PANEL ---{Colors.END}")
    print("1. file Integrity checker (checker/verify) - file Integrity builder (builder/init)")
    print("2. Encrypt a File")
    print("3. Decrypt a File")
    print("4. Generate New Key (Careful!)")

    choice = input(f"\n{Colors.YELLOW}Select an option (1-4): {Colors.END}").strip()

    if choice == "1":
        main_hash()
    elif choice == "2":
        file_to_encrypt = input(f"{Colors.YELLOW}Enter the path of the file to encrypt: {Colors.END}").strip()
        if os.path.exists(file_to_encrypt):
            encrypt_file(file_to_encrypt)
        else:
            print(f"{Colors.RED}[!] File does not exist{Colors.END}")
    elif choice == "3": 
        file_to_decrypt = input(f"{Colors.YELLOW}Enter the path of the file to decrypt: {Colors.END}").strip()
        if os.path.exists(file_to_decrypt):
            decrypt_file(file_to_decrypt)
        else:
            print(f"{Colors.RED}[!] File does not exist{Colors.END}")
    elif choice == "4":
        confirm = input(f"{Colors.RED}This will overwrite your existing key and you may lose access to encrypted files. Are you sure? (yes/no): {Colors.END}").strip().lower()
        if confirm == "yes":
            generate_key()
        else:
            print(f"{Colors.GREEN}[✔] Key generation cancelled.{Colors.END}")
    else:
        print(f"{Colors.RED}[!] Invalid option. Exiting.{Colors.END}")
        exit(-1)

if __name__ == "__main__":
    main_menu()

















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
    f = Fernet(key)
    
    with open(file_path, "rb") as file:
        file_data = file.read()
    
    encrypted_data = f.encrypt(file_data)
    
    with open(file_path, "wb") as file:
        file.write(encrypted_data)
    print(f"[!] File {file_path} has been ENCRYPTED.")

# 4. Decrypt a file
def decrypt_file(file_path):
    secret_key_check=input(f"{Colors.YELLOW}Enter the secret key to decrypt the file: {Colors.END}").strip().encode('utf-8')

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