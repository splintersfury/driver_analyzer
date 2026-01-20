import logging

# Set up logging early
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

from karton.core import Karton, Task, Resource
from karton.core.config import Config
import pefile
import logging

class DriverClassifier(Karton):
    """
    Karton service that checks if a PE file is a Windows Driver.
    """
    identity = "karton.driver.classifier"
    filters = [
        {
            "type": "sample",
            "kind": "runnable",
            "platform": "win32"
        },
        {
            "type": "sample",
            "kind": "runnable",
            "platform": "win64"
        }
    ]

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        
        # Download sample to temporary file (RemoteResource doesn't have .path)
        with sample.download_temporary_file() as temp_path:
            logging.info(f"Processing sample: {sample.name}")
            
            try:
                pe = pefile.PE(temp_path.name, fast_load=True)
                is_driver = False
                confidence = 0
                
                # Check 1: Subsystem NATIVE (1)
                # 1 = IMAGE_SUBSYSTEM_NATIVE (Driver/Kernel)
                if pe.OPTIONAL_HEADER.Subsystem == 1:
                    is_driver = True
                    confidence += 50
                    logging.info("Found NATIVE subsystem.")

                # Check 2: Imports (ntoskrnl.exe, hal.dll)
                # fast_load=True doesn't load imports, need to parse them data directories
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                
                kernel_imports = {'ntoskrnl.exe', 'hal.dll', 'fltmgr.sys', 'win32k.sys'}
                found_imports = set()
                
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                        if dll_name in kernel_imports:
                            found_imports.add(dll_name)
                
                if found_imports:
                    is_driver = True
                    confidence += 30
                    logging.info(f"Found kernel imports: {found_imports}")
                
                # Check 3: Sections (INIT, PAGE) - common in drivers
                for section in pe.sections:
                    sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    if sec_name in ['.sys', 'INIT', 'PAGE']:
                        confidence += 10

                if is_driver:
                    logging.info(f"Detected potential driver (Confidence: {confidence})")
                    
                    # Trigger detailed analysis
                    new_task = Task(
                        headers={
                            "type": "driver",
                            "kind": "driver:windows",
                        },
                        payload={
                            "sample": sample,
                            "driver_confidence": confidence,
                        }
                    )
                    self.send_task(new_task)
                else:
                    logging.info(f"Not a driver: {sample.name}")

            except Exception as e:
                logging.error(f"Error processing PE: {e}")

if __name__ == "__main__":
    classifier = DriverClassifier()
    classifier.loop()
