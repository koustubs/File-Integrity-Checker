import hashlib
import os
import json
import argparse

HASH_FILE = "file_hashes.json"

def calculate_hash(file_path, algo="sha256"):
    """Calculates the hash of a file using the specified algorithm."""
    hash_func = hashlib.new(algo)
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return None

def generate_baseline(directory):
    """Scans the directory and stores initial file hashes."""
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hashes[file_path] = calculate_hash(file_path)
    with open(HASH_FILE, "w") as f:
        json.dump(file_hashes, f, indent=4)
    print(f"✅ Baseline hashes stored in {HASH_FILE}")

def verify_integrity(directory):
    """Compares current file hashes with stored hashes to detect changes."""
    try:
        with open(HASH_FILE, "r") as f:
            stored_hashes = json.load(f)
    except FileNotFoundError:
        print("[ERROR] Baseline hash file not found. Run --generate first.")
        return
    
    modified_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            current_hash = calculate_hash(file_path)
            if file_path in stored_hashes:
                if stored_hashes[file_path] != current_hash:
                    modified_files.append(file_path)
            else:
                print(f"⚠️ New file detected: {file_path}")
    
    if modified_files:
        print("⚠️ WARNING: Modified files detected:")
        for file in modified_files:
            print(f" - {file}")
    else:
        print("✅ No modifications detected.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File Integrity Checker")
    parser.add_argument("--generate", help="Generate file hashes", action="store_true")
    parser.add_argument("--verify", help="Verify file integrity", action="store_true")
    parser.add_argument("directory", help="Directory to scan")
    
    args = parser.parse_args()
    if args.generate:
        generate_baseline(args.directory)
    elif args.verify:
        verify_integrity(args.directory)
    else:
        print("Use --generate or --verify with a directory path")
