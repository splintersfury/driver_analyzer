import logging

# Set up logging early
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

from karton.core import Karton, Task, Resource
from mwdblib import MWDB
import os
import logging
import json

class ReporterKarton(Karton):
    """
    Karton service that reports findings to MWDB.
    """
    identity = "karton.driver.reporter"
    filters = [
        {"type": "signature-report"},
        {"type": "analysis-report"}
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mwdb = MWDB(
            api_url=os.environ.get("MWDB_API_URL", "http://mwdb-core:8080/api/"),
            api_key=os.environ.get("MWDB_API_KEY")
        )

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        sha256 = sample.sha256
        
        logging.info(f"Reporting for sample {sha256}")
        
        # Determine report type
        if task.headers["type"] == "signature-report":
            self.report_signature(task, sha256)
        elif task.headers["type"] == "analysis-report":
            self.report_analysis(task, sha256)

    def report_signature(self, task: Task, sha256: str):
        sig_data = task.payload.get("sigcheck_data", {})
        logging.info(f"Sigcheck data received for {sha256}: {sig_data}")

        try:
            obj = self.mwdb.query_file(sha256)
            if not obj:
                logging.warning(f"Sample {sha256} not found in MWDB.")
                return

            # Add attributes (including file description)
            for k, v in sig_data.items():
                if v and v != "n/a":
                    try:
                        # MWDB keys: max 32 chars, letters, digits, underscores, dashes. No colons.
                        clean_k = k.lower().replace(' ', '_').replace('-', '_')
                        attr_name = f"sig_{clean_k}"[:32].strip("_")
                        obj.add_attribute(attr_name, v)
                    except Exception as e:
                        # Skip attributes that aren't defined in MWDB schema
                        logging.debug(f"Skipping attribute {k}: {e}")
            

            # Add status tag
            verified = sig_data.get("Verified", "Unknown")
            if verified == "Signed":
                obj.add_tag("signed")
            elif verified == "Unsigned":
                obj.add_tag("unsigned")
            
            # Add product tag if available
            product = sig_data.get("Product", "") or sig_data.get("Description", "") or sig_data.get("File description", "")
            if product and product != "n/a":
                # Clean product name for tag: allow alphanumeric, underscore, dash, dot
                import re
                product_tag = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', product).strip("_")
                product_tag = product_tag[:50].strip("_")
                
                if product_tag:
                    logging.info(f"Adding product tag: product:{product_tag} for {sha256}")
                    obj.add_tag(f"product:{product_tag}")
                else:
                    logging.warning(f"Product tag became empty after cleaning: original='{product}'")

            # Post concise comment
            verdict = "✅ Signed" if verified == "Signed" else "⚠️ Unsigned"
            publisher = sig_data.get("Publisher", "Unknown")
            
            comment = f"### 🔐 Signature Analysis\n\n"
            comment += f"**Verdict**: {verdict}\n"
            if publisher and publisher != "n/a":
                comment += f"**Publisher**: {publisher}\n"
            comment += "\n*Detailed metadata available in attributes sidebar.*"
            
            obj.add_comment(comment)
            logging.info(f"Reported signature attributes and comment for {sha256}")
            
        except Exception as e:
            logging.error(f"Failed to report signature to MWDB: {e}")

    def report_analysis(self, task: Task, sha256: str):
         data = task.payload.get("ioctlance_report", {})
         
         try:
            obj = self.mwdb.query_file(sha256)
            if not obj:
                return

            # IOCTLance outputs: {"basic": {...}, "vuln": [...], "error": [...]}
            # Extract the vulnerabilities list from the 'vuln' key
            if isinstance(data, dict):
                vulnerabilities = data.get("vuln", [])
            elif isinstance(data, list):
                vulnerabilities = data
            else:
                vulnerabilities = []
            
            count = len(vulnerabilities)
            
            # Add attributes
            obj.add_attribute("ioctl_vuln_count", str(count))
            verdict = "VULNERABLE" if count > 0 else "CLEAN"
            obj.add_attribute("ioctl_verdict", verdict)

            # Add tags
            if count > 0:
                obj.add_tag("vulnerable")
                # Add vulnerability count tag
                obj.add_tag(f"{count}_Vuln_Ioctlance")

            # Upload the full JSON report as a child artifact if available
            try:
                json_resource = task.get_resource("ioctlance_json")
                if json_resource:
                    # Try to get the original filename from sigcheck metadata first
                    try:
                        mwdb_obj = self.mwdb.query_file(sha256)
                        original_name = None
                        # Check if we have the original filename from sigcheck
                        for attr in mwdb_obj.attributes:
                            if attr.key == "original_filename":
                                original_name = attr.value
                                break
                    except:
                        original_name = None
                    
                    # Fall back to sample name if sigcheck didn't provide original name
                    if not original_name:
                        sample = task.get_payload("sample")
                        original_name = sample.name if sample else "unknown"
                    
                    # Create better artifact name: IOCTLANCE_Report_<original_filename>
                    artifact_name = f"IOCTLANCE_Report_{original_name}"
                    
                    json_obj = self.mwdb.upload_file(
                        name=artifact_name,
                        content=json_resource.content,
                        parent=sha256
                    )
                    logging.info(f"Uploaded IOCTLance JSON artifact: {artifact_name}")
            except Exception as e:
                logging.debug(f"No JSON resource to upload: {e}")

            # Post concise comment with full details
            markdown = "### 🛡️ IOCTLance Vulnerability Scan\n\n"
            if count > 0:
                markdown += f"**Verdict**: ⚠️ Found {count} potential vulnerabilities.\n\n"
                
                # Add summary of vulnerability types
                vuln_types = {}
                for vuln in vulnerabilities:
                    title = vuln.get("title", "Unknown")
                    vuln_types[title] = vuln_types.get(title, 0) + 1
                
                markdown += "**Vulnerability Summary:**\n"
                for vtype, vcount in vuln_types.items():
                    markdown += f"- {vtype}: {vcount}\n"
                
                # Add full details in collapsible section
                markdown += "\n<details>\n<summary><b>📋 Click to view full vulnerability details</b></summary>\n\n```json\n"
                import json
                markdown += json.dumps(vulnerabilities, indent=2)
                markdown += "\n```\n</details>\n"
            else:
                markdown += "**Verdict**: ✅ No obvious vulnerabilities detected.\n"

            obj.add_comment(markdown)
            logging.info(f"Reported IOCTLance attributes for {sha256}")
         except Exception as e:
            logging.error(f"Failed to report analysis to MWDB: {e}")

    def _post_comment(self, sha256: str, body: str):
        try:
            obj = self.mwdb.query_file(sha256)
            if obj:
                obj.add_comment(body)
                logging.info(f"Posted comment to {sha256}")
            else:
                logging.warning(f"Sample {sha256} not found in MWDB to comment on.")
        except Exception as e:
            logging.error(f"Failed to post comment to MWDB: {e}")

if __name__ == "__main__":
    service = ReporterKarton()
    service.loop()
