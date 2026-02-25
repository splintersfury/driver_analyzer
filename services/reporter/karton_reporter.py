import logging

# Set up logging early
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

from karton.core import Karton, Task, Resource
from mwdblib import MWDB
import os
import logging
import json
import redis
import requests

# Telegram notification config
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
REDIS_HOST = os.environ.get("KARTON_REDIS_HOST", "karton-redis")
WATCH_KEY = "telegram:watch"

# Compact exploit primitive mapping for IOCTLance titles.
# Full mapping lives in AutoPiff/rules/exploit_map.yaml; this is the
# notification-friendly subset.
EXPLOIT_MAP = {
    "read/write controllable address": {
        "class": "Arbitrary R/W",
        "primitives": "Direct IOCTL R/W",
        "chain": "Token Swap / PTE Manipulation",
    },
    "map physical memory": {
        "class": "Arbitrary R/W",
        "primitives": "Physical Memory Mapping",
        "chain": "Token Swap / PTE Manipulation",
    },
    "buffer overflow": {
        "class": "Buffer Overflow",
        "primitives": "Pool Corruption",
        "chain": "Named Pipe Spray → I/O Ring R/W (22H2+)",
    },
    "dest or src controllable": {
        "class": "Buffer Overflow",
        "primitives": "Pool Corruption",
        "chain": "Named Pipe Spray → I/O Ring R/W (22H2+)",
    },
    "arbitrary shellcode execution": {
        "class": "Code Execution",
        "primitives": "Direct Call Hijack",
        "chain": "Direct (no chain needed)",
    },
    "arbitrary wrmsr": {
        "class": "HW Access",
        "primitives": "MSR Write",
        "chain": "Token Swap via LSTAR / PTE Manipulation",
    },
    "arbitrary out": {
        "class": "HW Access",
        "primitives": "I/O Port Access",
        "chain": "DMA → Physical Memory R/W",
    },
    "controllable process handle": {
        "class": "Privilege Escalation",
        "primitives": "Process Handle Leak",
        "chain": "Token Manipulation",
    },
    "arbitrary process termination": {
        "class": "Privilege Escalation",
        "primitives": "Process Kill",
        "chain": "DoS / Defense Evasion",
    },
    "null pointer dereference - input buffer": {
        "class": "Null Deref",
        "primitives": "Limited",
        "chain": "DoS (BSoD)",
    },
    "null pointer dereference - allocated memory": {
        "class": "Null Deref",
        "primitives": "Limited",
        "chain": "DoS (BSoD)",
    },
    "ObjectName in ObjectAttributes controllable": {
        "class": "File/Registry Access",
        "primitives": "Arbitrary Path Access",
        "chain": "Privilege Escalation via file/registry overwrite",
    },
}


def send_telegram_notification(sha256: str, verdict: str, vuln_count: int = 0,
                               context: dict = None):
    """Send enriched Telegram notification to all users watching this driver."""
    if not TELEGRAM_BOT_TOKEN:
        return

    try:
        r = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)
        chat_ids = r.smembers(f"{WATCH_KEY}:{sha256}")

        if not chat_ids:
            logging.debug(f"No watchers for {sha256}")
            return

        ctx = context or {}

        # --- Build enriched message ---
        if verdict == "VULNERABLE":
            msg = f"⚠️ *VULNERABLE* — {vuln_count} issue{'s' if vuln_count != 1 else ''}\n\n"
        else:
            msg = "✅ *CLEAN*\n\n"

        # Driver identity: description or product, plus version
        description = ctx.get("description", "")
        version = ctx.get("version", "")
        label = description or f"`{sha256[:16]}…`"
        if version:
            label += f" v{version}"
        msg += f"📄 {label}\n"

        # Publisher
        publisher = ctx.get("publisher", "")
        if publisher:
            msg += f"🏢 {publisher}\n"

        # Signing status
        signing = ctx.get("signing", "")
        if signing:
            icon = "🔐" if signing == "Signed" else "🔓"
            msg += f"{icon} {signing}\n"

        # Vulnerability type breakdown with exploit primitives
        vuln_types = ctx.get("vuln_types", {})
        if vuln_types:
            msg += "\n🐛 *Vulnerabilities:*\n"
            for vtype, vcount in vuln_types.items():
                exploit = EXPLOIT_MAP.get(vtype)
                if exploit:
                    msg += f"  • {vtype} ({vcount})\n"
                    msg += f"    ↳ {exploit['primitives']} → {exploit['chain']}\n"
                else:
                    msg += f"  • {vtype} ({vcount})\n"
        elif verdict == "CLEAN":
            msg += "\nNo vulnerabilities detected.\n"

        msg += f"\n`{sha256[:24]}…`\n"
        msg += f"[View in MWDB](http://localhost:8082/file/{sha256})"

        # Send to all watchers
        for chat_id in chat_ids:
            try:
                requests.post(
                    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                    json={
                        "chat_id": chat_id,
                        "text": msg,
                        "parse_mode": "Markdown"
                    },
                    timeout=10
                )
                logging.info(f"Sent Telegram notification to chat {chat_id} for {sha256[:12]}")
            except Exception as e:
                logging.error(f"Failed to send Telegram notification: {e}")
    except Exception as e:
        logging.error(f"Error checking watchers: {e}")

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
            
            # Build enrichment context from MWDB attributes for notification
            notify_ctx = {}
            try:
                a = obj.attributes  # dict: {key: [val, ...], ...}

                def _first(key: str, default: str = "") -> str:
                    vals = a.get(key, [])
                    return vals[0] if vals else default

                notify_ctx["description"] = (
                    _first("sig_file_description")
                    or _first("sig_description")
                    or _first("sig_product")
                    or ""
                )
                notify_ctx["publisher"] = _first("sig_publisher")
                notify_ctx["version"] = _first("sig_file_version")

                # Signing status from tags
                tags = set(obj.tags) if hasattr(obj, "tags") else set()
                if "signed" in tags:
                    notify_ctx["signing"] = "Signed"
                elif "unsigned" in tags:
                    notify_ctx["signing"] = "Unsigned"

                # Vulnerability type breakdown
                vuln_types = {}
                for vuln in vulnerabilities:
                    title = vuln.get("title", "Unknown")
                    vuln_types[title] = vuln_types.get(title, 0) + 1
                if vuln_types:
                    notify_ctx["vuln_types"] = vuln_types

            except Exception as e:
                logging.debug(f"Could not enrich notification context: {e}")

            # Send Telegram notification to watchers
            try:
                send_telegram_notification(sha256, verdict, count, context=notify_ctx)
            except Exception as e:
                logging.debug(f"Telegram notification skipped: {e}")
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
