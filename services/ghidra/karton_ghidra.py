import logging
import os
import shutil
import subprocess
from karton.core import Karton, Task, Resource
from mwdblib import MWDB

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("karton.driver.ghidra")

class GhidraDecompilerKarton(Karton):
    """
    Karton service that decompiles Windows drivers using Ghidra and uploads source to MWDB.
    """
    identity = "karton.driver.ghidra"
    filters = [
        {
            "type": "driver",
            "kind": "driver:windows"
        }
    ]

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        logger.info(f"Starting Ghidra decompilation for {sample.name}")

        import uuid
        run_id = str(uuid.uuid4())
        temp_dir = f"/tmp/ghidra_work_{run_id}"
        os.makedirs(temp_dir, exist_ok=True)
        
        try:
            # 1. Save sample to disk
            sample_path = os.path.join(temp_dir, sample.name)
            with open(sample_path, "wb") as f:
                f.write(sample.content)

            # 2. Prepare output directory
            output_dir = os.path.join(temp_dir, "output")
            os.makedirs(output_dir, exist_ok=True)

            # 3. Construct Ghidra Headless command
            ghidra_home = os.environ.get("GHIDRA_HOME", "/app/ghidra")
            headless_script = os.path.join(ghidra_home, "support", "analyzeHeadless")
            
            project_dir = os.path.join(temp_dir, "project")
            os.makedirs(project_dir, exist_ok=True)

            cmd = [
                headless_script,
                project_dir,
                f"temp_project_{run_id}",
                "-import", sample_path,
                "-scriptPath", "/app",
                "-postScript", "ExportDecompiled.py", output_dir,
                "-deleteProject"
            ]

            logger.info("Running Ghidra Headless...")
            # Run Ghidra (this takes time)
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                timeout=3000 # 50 mins, Ghidra can be slow
            )

            if result.returncode != 0:
                logger.error(f"Ghidra failed with code {result.returncode}")
                logger.error(f"Stdout: {result.stdout}")
                logger.error(f"Stderr: {result.stderr}")
                return # Don't retry endlessly?

            # 4. Find output file
            # ExportDecompiled.py writes to output_dir/<filename>.c
            # (or check the log/logic) where filename matches input filename usually
            expected_output = os.path.join(output_dir, sample.name + ".c")
            
            if not os.path.exists(expected_output):
                # Fallback: check any .c file in output_dir
                files = [f for f in os.listdir(output_dir) if f.endswith(".c")]
                if files:
                    expected_output = os.path.join(output_dir, files[0])
                else:
                    logger.error("No decompiled .c file found in output directory.")
                    logger.info(f"Stdout: {result.stdout}")
                    return

            # 5. Upload to MWDB
            logger.info(f"Uploading {expected_output} to MWDB...")
            
            mwdb_url = os.environ.get("MWDB_API_URL")
            mwdb_key = os.environ.get("MWDB_API_KEY")

            if mwdb_url and mwdb_key:
                mwdb = MWDB(api_url=mwdb_url, api_key=mwdb_key)
                
                # Get parent object
                # Upload as child
                with open(expected_output, "rb") as f:
                    content = f.read()

                mwdb.upload_file(
                    name=f"{sample.name}.c",
                    content=content,
                    parent=sample.sha256,
                    tags=["ghidra_decompiled", "source_c"]
                )
                logger.info("Upload successful.")

            else:
                logger.warning("MWDB_API_URL or MWDB_API_KEY not set. Skipping upload.")

        except Exception as e:
            logger.error(f"Exception during processing: {e}")
            import traceback
            traceback.print_exc()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    service = GhidraDecompilerKarton()
    service.loop()
