#!/usr/bin/env python3
"""
Script to delete all samples from MWDB.
Use with caution - this will remove all files!
"""
import os
from mwdblib import MWDB

def clear_all_samples():
    # Connect to MWDB
    mwdb = MWDB(
        api_url=os.environ.get("MWDB_API_URL", "http://localhost:8080/api/"),
        api_key=os.environ.get("MWDB_API_KEY")
    )
    
    print("Connecting to MWDB...")
    
    # Get all files
    print("Fetching all files...")
    files = list(mwdb.search_files())
    
    print(f"Found {len(files)} files to delete.")
    
    if len(files) == 0:
        print("No files to delete.")
        return
    
    # Ask for confirmation
    response = input(f"Are you sure you want to delete {len(files)} files? (yes/no): ")
    if response.lower() != "yes":
        print("Aborted.")
        return
    
    # Delete each file
    deleted_count = 0
    failed_count = 0
    
    for i, file_obj in enumerate(files, 1):
        try:
            print(f"[{i}/{len(files)}] Deleting {file_obj.sha256}...")
            file_obj.remove()
            deleted_count += 1
        except Exception as e:
            print(f"  ERROR: Failed to delete {file_obj.sha256}: {e}")
            failed_count += 1
    
    print(f"\nDone! Deleted {deleted_count} files, {failed_count} failed.")

if __name__ == "__main__":
    clear_all_samples()
