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

    crypt_choice = input(f"{Colors.YELLOW}Do you want to encrypt the files after hashing? (yay/nay):{Colors.END} ").strip().lower()################

    if crypt_choice=="yay":
        encrypt_file(target_path)
    


    print(f"\n{Colors.MAGENTA}--- SETTINGS ---{Colors.END}")

    re_init = input("re-initialize? (yay/nay): ").strip().lower()
    
    if re_init == "yay":
        # hashes = {}
        db_data={
            "metadata":{
                "algorithm": hash_ask,
                "version": "2.0",
            },
            "files": {}
        }
        if os.path.isdir(target_path):
            
            for root, dirs, files in os.walk(target_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    db_data["files"][full_path]= Hashing_engine(full_path, hash_ask)
                    # hashes[full_path] = Hashing_engine(full_path, hash_ask)
        else:
            # hashes[target_path] = Hashing_engine(target_path, hash_ask)
            db_data["files"][target_path]= Hashing_engine(target_path, hash_ask)

        with open(db_json, 'w') as f:
            json.dump(db_data, f, indent=4)
        print(f"{Colors.GREEN}[✔]Database updated!{Colors.END}")


    else:
        if not os.path.exists(db_json):
            print(f"{Colors.RED}[!] No DB found{Colors.END}")
            exit(-1)
        with open(db_json, 'r') as f:
            stored = json.load(f)
        
        alg_used = stored.get("metadata", {}).get("algorithm", hash_ask) # in case we want to store the algorithm in the future
        print(f"\n{Colors.CYAN}[*] Checking integrity using {alg_used.upper()}...{Colors.END}\n")
        
        for f_path, old_h in stored["files"].items(): 
            curr_h = Hashing_engine(f_path,algorithm=alg_used)
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
