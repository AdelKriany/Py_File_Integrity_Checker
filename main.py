import os
import hashlib
import json
import re

def Hashing_engine(file_path):
    """Compute the SHA-256 hash of the given file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:#r for read ,b for binary
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
            
    return sha256_hash.hexdigest()



def main():
    target_path=input("Enter the path of the LOG FILE or DIRECTORY TO SCAN: ").strip()
    if not os.path.exists(target_path):
        print("File size checking not supported on this system.")
        exit(1)

    DB_PATH="hash_database.json"

    re_init=input("Do you want to re-initialize the log file? (yes/no): ").strip().lower()
    if re_init =='yes':
        hashes={}
        if os.path.isdir(target_path):
            for root, dirs, files in os.walk(target_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_hash = Hashing_engine(file_path)
                    hashes[file_path] = file_hash
        else:
            hashes[target_path]=Hashing_engine(target_path)

        with open(DB_PATH, 'w') as f:
            json.dump(hashes, f)
        print("Log file re-initialized.")
        exit(0)

    else:
        if  not os.path.exists(DB_PATH):
            print("No existing log file found. Please re-initialize first.")
            exit(1)
        with open(DB_PATH, 'r') as f:
            storedHashes = json.load(f)
        print("\n--- Checking Integrity ---")
        for file_path, old_hash in storedHashes.items():
            if not os.path.exists(file_path):
                print(f"File missing: {file_path}")
                continue
            current_hash = Hashing_engine(file_path)
            if current_hash != old_hash:
                print(f"File modified: {file_path}")
            else:
                print(f"File unchanged: {file_path}")
    


# main
if __name__=="__main__":
   main()