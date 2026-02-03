
import argparse
import sys
import hashlib
from karton.core import Karton, Task, Resource

class ManualTrigger(Karton):
    identity = "karton.manual_trigger"
    
    def process(self, task):
        pass

    def produce(self, file_path):
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            sha256 = hashlib.sha256(content).hexdigest()
            print(f"Loaded {file_path}")
            print(f"SHA256: {sha256}")
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)

        print("Sending manual patch diff task...")
        task = Task(
            headers={
                "type": "analysis",
                "kind": "patch_differ"
            },
            payload={
                "sample": Resource("sample", path=file_path)
            }
        )
        self.send_task(task)
        print("Task sent successfully! Check logs for 'patch-differ-manual' container.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Force a Patch Diff analysis for a local file.")
    parser.add_argument("file", help="Path to the driver file (sys)")
    args = parser.parse_args()
    
    ManualTrigger().produce(args.file)
