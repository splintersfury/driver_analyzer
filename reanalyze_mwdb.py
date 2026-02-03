
import os
import argparse
import tempfile
import hashlib
from mwdblib import MWDB
from karton.core import Karton, Task, Resource, Config

class Reanalyzer(Karton):
    identity = "karton.reanalyzer"
    
    def process(self, task):
        pass

    def reanalyze_sha(self, sha256, content):
        print(f"Sending reanalysis task for {sha256}...")
        
        # Determine kind based on file? For now assume driver:windows for patch diff
        # Actually patch_differ listens for 'driver' kind AND 'analysis' kind with correct header?
        # patch_differ.py binds to:
        # { type: driver, kind: driver:windows }
        # { type: analysis, kind: patch_differ }
        
        # We can send it specifically to patch_differ to avoid triggering everything else
        task = Task(
            headers={
                "type": "analysis",
                "kind": "patch_differ"
            },
            payload={
                "sample": Resource("sample", content=content)
            }
        )
        self.send_task(task)
        print(f"Task sent for {sha256}!")

def main():
    api_url = os.environ.get("MWDB_API_URL", "http://mwdb-core:8080/api/")
    api_key = os.environ.get("MWDB_API_KEY")
    
    if not api_key:
        print("MWDB_API_KEY not set!")
        return

    mwdb = MWDB(api_url=api_url, api_key=api_key)
    # Use env vars by default if no config file
    karton = Reanalyzer(config=Config())
    
    # Identify recent files or FortiClient ones
    # We can search by filename pattern or tag
    print("Searching for Fortinet samples...")
    # Attempt to find by name
    samples = mwdb.search_files('name:"*forti*"')
    
    count = 0
    for sample in samples:
        try:
            print(f"Processing {sample.sha256} ({sample.file_name})")
            content = sample.download()
            karton.reanalyze_sha(sample.sha256, content)
            count += 1
        except Exception as e:
            print(f"Failed to process {sample.sha256}: {e}")
            
    print(f"Re-submitted {count} samples.")

if __name__ == "__main__":
    main()
