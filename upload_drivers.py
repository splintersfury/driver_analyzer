#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
import tempfile
import requests
import concurrent.futures
import time
from pathlib import Path

# Configuration
# Using localhost because this script runs on the host
MWDB_API_URL = "http://localhost:8080/api/" 
MWDB_API_KEY = os.environ.get("MWDB_API_KEY")
if not MWDB_API_KEY:
    print("Please set MWDB_API_KEY environment variable")
    exit(1)
SOURCE_DIR = "/home/splintersfury/Documents/drivers/ALL_DRIVERS"
MAX_WORKERS = 10  # Parallel uploads

def upload_file(file_path):
    """Uploads a single file to MWDB."""
    try:
        file_name = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            files = {"file": (file_name, f)}
            # Try to upload
            headers = {"Authorization": f"Bearer {MWDB_API_KEY}"}
            response = requests.post(f"{MWDB_API_URL}file", headers=headers, files=files, timeout=30)
            
            if response.status_code == 200:
                print(f"[+] Uploaded: {file_name}")
                return True
            elif response.status_code == 409: # Conflict usually means already exists, check MWDB API docs
                print(f"[.] Exists: {file_name}")
                return True
            else:
                print(f"[-] Failed {file_name}: {response.status_code} - {response.text[:100]}")
                return False
    except Exception as e:
        print(f"[!] Error uploading {file_path}: {e}")
        return False

def process_archive(archive_path):
    """Extracts an archive and uploads contained .sys files."""
    archive_name = os.path.basename(archive_path)
    print(f"\nExample: Processing archive: {archive_name}")
    print(f"Size: {os.path.getsize(archive_path) / (1024*1024):.2f} MB")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"Extracting to {temp_dir}...")
        try:
            # 7z x archive.7z -o{temp_dir} -y
            cmd = ["7z", "x", archive_path, f"-o{temp_dir}", "-y"]
            # Suppress output to avoid clutter
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
             print(f"[!] Failed to extract {archive_name}: {e}")
             return

        # Find all .sys files
        sys_files = []
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.lower().endswith(".sys"):
                    sys_files.append(os.path.join(root, file))
        
        print(f"Found {len(sys_files)} drivers in {archive_name}")
        
        if not sys_files:
            return

        # Upload in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(upload_file, f) for f in sys_files]
            
            # Wait for all to complete
            done_count = 0
            for future in concurrent.futures.as_completed(futures):
                done_count += 1
                if done_count % 50 == 0:
                    print(f"Progress: {done_count}/{len(sys_files)}...")

def main():
    if not os.path.exists(SOURCE_DIR):
        print(f"Source directory not found: {SOURCE_DIR}")
        return

    # Get all .7z files
    archives = [os.path.join(SOURCE_DIR, f) for f in os.listdir(SOURCE_DIR) if f.endswith(".7z")]
    archives.sort() # Process in order
    
    print(f"Found {len(archives)} archives to process.")
    
    for i, archive in enumerate(archives, 1):
        print(f"\n[{i}/{len(archives)}] Starting {os.path.basename(archive)}")
        start_time = time.time()
        process_archive(archive)
        duration = time.time() - start_time
        print(f"Finished {os.path.basename(archive)} in {duration:.1f}s")

if __name__ == "__main__":
    main()
