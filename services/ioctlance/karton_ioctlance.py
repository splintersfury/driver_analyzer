import logging

# Set up logging early
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

from karton.core import Karton, Task, Resource
import os
import subprocess
import json
import logging
import shutil

class IOCTLanceKarton(Karton):
    """
    Karton service that runs IOCTLance on Windows drivers.
    """
    identity = "karton.driver.ioctlance"
    filters = [
        {
            "type": "driver",
            "kind": "driver:windows"
        }
    ]

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        
        # Create a temporary directory for analysis
        temp_dir = f"/tmp/analysis_{task.uid}"
        os.makedirs(temp_dir, exist_ok=True)
        
        sample_path = os.path.join(temp_dir, sample.name)
        with open(sample_path, "wb") as f:
            f.write(sample.content)
            
        logging.info(f"Running IOCTLance on {sample.name}")
        
        # IOCTLance command
        # python3 analysis/ioctlance.py <path>
        cmd = ["python3", "/home/ioctlance/analysis/ioctlance.py", sample_path]
        
        try:
            # IOCTLance writes output to <path>.json if it finds something? 
            # Or does it output to stdout?
            # README says: "-o, --overwrite overwrite x.sys.json if x.sys has been analyzed"
            # It implies it creates a JSON file next to the binary.
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200) # 20 mins timeout
            
            logging.info(f"IOCTLance stdout: {result.stdout}")
            logging.info(f"IOCTLance stderr: {result.stderr}")
            
            # Check for JSON output
            json_path = sample_path + ".json"
            ioctl_data = {}
            if os.path.exists(json_path):
                with open(json_path, "r") as f:
                    ioctl_data = json.load(f)
            else:
                 logging.warning(f"No JSON output found from IOCTLance at {json_path}")
            
            # Create a report or pass data
            # We can upload the raw JSON as an artifact
            # Send report (Always so reporter knows we finished)
            new_task = Task(
                headers={
                    "type": "analysis-report",
                    "source": "ioctlance"
                },
                payload={
                    "sample": sample,
                    "ioctlance_report": ioctl_data,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
            )
            if ioctl_data:
                json_res = Resource(name=f"{sample.name}_ioctlance.json", content=json.dumps(ioctl_data, indent=2).encode('utf-8'))
                new_task.add_resource("ioctlance_json", json_res)
            
            self.send_task(new_task)
            logging.info("Sent IOCTLance results to reporter.")

        except subprocess.TimeoutExpired:
            logging.error("IOCTLance timed out.")
        except Exception as e:
            logging.error(f"IOCTLance failed: {e}")
            import traceback
            traceback.print_exc()
        finally:
            shutil.rmtree(temp_dir)

if __name__ == "__main__":
    service = IOCTLanceKarton()
    service.loop()
