#!/usr/bin/env python3
"""
Simple script to delete all files from MWDB using mwdblib.
"""
from mwdblib import MWDB

# Use the admin API key
api_key = os.environ.get("MWDB_API_KEY")
if not api_key:
    # Look for it in the .env file possibly or error out
    print("Error: MWDB_API_KEY environment variable not set.")
    exit(1)

mwdb = MWDB(api_url="http://mwdb-core:8080/api/", api_key=api_key)

print("Fetching all files...")
files = list(mwdb.search_files(""))  # Empty query gets all files

print(f"Found {len(files)} files to delete.")

if len(files) == 0:
    print("No files to delete.")
    exit(0)

deleted = 0
failed = 0

for i, f in enumerate(files, 1):
    try:
        print(f"[{i}/{len(files)}] Deleting {f.sha256}...")
        f.remove()
        deleted += 1
    except Exception as e:
        print(f"  ERROR: {e}")
        failed += 1

print(f"\nDeleted {deleted} files, {failed} failed.")
