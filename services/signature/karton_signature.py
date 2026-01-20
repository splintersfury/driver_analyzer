import logging

# Set up logging early
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

from karton.core import Karton, Task, Resource
import os
import subprocess
import csv
import io
import logging
import shutil

class SignatureKarton(Karton):
    """
    Karton service that checks digital signatures of Windows drivers using Sigcheck.
    """
    identity = "karton.driver.signature"
    filters = [
        {
            "type": "driver",
            "kind": "driver:windows"
        }
    ]

    def process(self, task: Task) -> None:
        print(f"DEBUG: Processing task {task.uid}", flush=True)
        sample = task.get_resource("sample")
        
        temp_dir = f"/tmp/sig_{task.uid}"
        os.makedirs(temp_dir, exist_ok=True)
        sample_path = os.path.join(temp_dir, sample.name)
        
        try:
            with open(sample_path, "wb") as f:
                f.write(sample.content)
            
            logging.info(f"Running Sigcheck on {sample.name}")
            
            # Run Sigcheck
            # Prefix with Z: for Wine compatibility and use - style flags
            win_sample_path = "Z:" + sample_path
            cmd = ["wine", "/opt/sysinternals/sigcheck64.exe", "-accepteula", "-a", "-h", "-c", "-nobanner", win_sample_path]
            
            # Wine produces validation messages on stderr sometimes, ignore them
            env = os.environ.copy()
            env["WINEDEBUG"] = "-all"
            
            result = subprocess.run(cmd, capture_output=True, env=env, timeout=120)
            
            # Decode with latin-1 to handle non-UTF8 Wine output
            output = result.stdout.decode('latin-1', errors='replace')
            print(f"DEBUG: Sigcheck Raw Output Length: {len(output)}", flush=True)
            if len(output) < 500:
                print(f"DEBUG: Sigcheck Raw Output: {output}", flush=True)
            
            # Parse CSV
            sig_data = {}
            if output:
                try:
                    # CSV format: "Path","Verified","Date","Publisher","Company","Description",etc.
                    f = io.StringIO(output)
                    reader = csv.DictReader(f)
                    for row in reader:
                        # Convert to plain dict with string values (handle None)
                        sig_data = {k: (v if v is not None else "") for k, v in row.items()}
                        break # Only one file
                except Exception as e:
                    logging.warning(f"Failed to parse CSV: {e}")

            # Send results (Always send so reporter knows we finished)
            clean_sig_data = {str(k): str(v) for k, v in sig_data.items() if k is not None}
            
            new_task = Task(
                headers={
                    "type": "signature-report",
                    "source": "sigcheck"
                },
                payload={
                    "sample": sample,
                    "sigcheck_data": clean_sig_data,
                    "raw_output": output[:5000]
                }
            )
            self.send_task(new_task)
            logging.info(f"Sigcheck finished. Verified: {clean_sig_data.get('Verified', 'Unknown')}")

            if not sig_data:
                stderr_output = result.stderr.decode('latin-1', errors='replace') if result.stderr else ""
                logging.warning("Sigcheck produced no usable output.")
                logging.warning(f"Stderr: {stderr_output[:1000]}")

        except Exception as e:
            logging.error(f"Sigcheck failed: {e}")
            import traceback
            traceback.print_exc()
        finally:
            shutil.rmtree(temp_dir)

if __name__ == "__main__":
    service = SignatureKarton()
    service.loop()
