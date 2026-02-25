import os
import re
import json
import time
import threading
import requests as http_requests
import markdown as md
from markupsafe import Markup
from collections import Counter
from flask import Flask, render_template, request, jsonify, abort

app = Flask(__name__)


@app.template_filter("markdown")
def markdown_filter(text):
    """Convert markdown text to safe HTML."""
    if not text:
        return ""
    html = md.markdown(text, extensions=["extra"])
    return Markup(html)

API_URL = os.environ.get("MWDB_API_URL", "http://mwdb-core:8080/api/")
API_KEY = os.environ.get("MWDB_API_KEY", "")


# ---------------------------------------------------------------------------
# MWDB API helpers
# ---------------------------------------------------------------------------

def api_get(endpoint, params=None):
    url = API_URL.rstrip("/") + "/" + endpoint.lstrip("/")
    headers = {"Authorization": f"Bearer {API_KEY}"}
    r = http_requests.get(url, headers=headers, params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def api_download(sha256):
    url = API_URL.rstrip("/") + f"/file/{sha256}/download"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    r = http_requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    return r.content


def count_files(query):
    count = 0
    older_than = None
    while True:
        params = {"query": query, "count": 1000}
        if older_than:
            params["older_than"] = older_than
        data = api_get("file", params)
        files = data.get("files", [])
        if not files:
            break
        count += len(files)
        older_than = files[-1]["id"]
        if len(files) < 1000:
            break
    return count


def search_files(query, limit=100):
    results = []
    older_than = None
    while len(results) < limit:
        params = {"query": query, "count": min(limit - len(results), 1000)}
        if older_than:
            params["older_than"] = older_than
        data = api_get("file", params)
        files = data.get("files", [])
        if not files:
            break
        results.extend(files)
        older_than = files[-1]["id"]
        if len(files) < 1000:
            break
    return results[:limit]


def tag_names(tags):
    return [t["tag"] if isinstance(t, dict) else t for t in tags]


def extract_tag(tags, prefix):
    for t in tags:
        tag = t["tag"] if isinstance(t, dict) else t
        if tag.startswith(prefix):
            return tag[len(prefix):]
    return None


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

_data = {}
_data_ready = threading.Event()
_data_lock = threading.Lock()
CACHE_TTL = 300


def _collect_data():
    """Collect all actionable data from MWDB."""
    global _data

    result = {}

    # --- Quick counts ---
    counts = {}
    for tag in ["driver", "vulnerable", "ghidra_decompiled",
                 "autopiff_reported", "driveratlas_triaged",
                 "signed", "unsigned", "oem_driver", "windows_inbox"]:
        counts[tag] = count_files(f"tag:{tag}")
    result["counts"] = counts

    # --- All autopiff report JSONs (the real findings) ---
    report_files = search_files("tag:autopiff_reported", limit=200)
    all_findings = []
    reports_by_driver = {}

    for rf in report_files:
        # For each autopiff-reported driver, find its child report JSONs
        sha = rf["id"]
        driver_name = rf["file_name"]
        driver_tags = tag_names(rf.get("tags", []))
        product = extract_tag(rf.get("tags", []), "product:") or driver_name

        try:
            detail = api_get(f"file/{sha}")
            children = detail.get("children", [])
        except Exception:
            children = []

        report_json = None
        for ch in children:
            ch_sha = ch["id"]
            # Parent child list lacks file_name — try downloading JSON children
            ch_tags = tag_names(ch.get("tags", []))
            if "misc:json" in ch_tags and "autopiff" not in ch_tags and "semantic_deltas" not in ch_tags:
                try:
                    raw = api_download(ch_sha)
                    candidate = json.loads(raw)
                    if candidate.get("autopiff_stage") == "report":
                        report_json = candidate
                        break
                except Exception:
                    continue

        if not report_json:
            continue

        # Extract version info
        drv_info = report_json.get("driver", {})
        old_ver = drv_info.get("old", {}).get("version", "?")
        new_ver = drv_info.get("new", {}).get("version", "?")

        report_entry = {
            "driver_name": driver_name,
            "driver_sha": sha,
            "product": product,
            "old_version": old_ver,
            "new_version": new_ver,
            "total_findings": report_json.get("summary", {}).get("total_findings", 0),
            "reachable_findings": report_json.get("summary", {}).get("reachable_findings", 0),
            "top_categories": report_json.get("summary", {}).get("top_categories", []),
            "findings": [],
        }

        for f in report_json.get("findings", []):
            finding = {
                "driver_name": driver_name,
                "driver_sha": sha,
                "product": product,
                "function": f.get("function", "?"),
                "score": f.get("score", 0),
                "confidence": f.get("confidence", 0),
                "category": f.get("category", "unknown"),
                "rule_ids": f.get("rule_ids", []),
                "reachability": f.get("reachability", {}).get("class", "unknown"),
                "sinks": f.get("sinks", []),
                "why": f.get("why", ""),
                "added_checks": f.get("added_checks", []),
            }
            all_findings.append(finding)
            report_entry["findings"].append(finding)

        reports_by_driver[sha] = report_entry

    # Sort findings by score descending
    all_findings.sort(key=lambda x: x["score"], reverse=True)
    result["findings"] = all_findings
    result["reports"] = reports_by_driver

    # --- Category stats from findings ---
    cat_counts = Counter(f["category"] for f in all_findings)
    result["category_counts"] = dict(cat_counts.most_common())

    rule_counts = Counter()
    for f in all_findings:
        for r in f["rule_ids"]:
            rule_counts[r] += 1
    result["rule_counts"] = dict(rule_counts.most_common())

    # --- IOCTLance vulnerable drivers with parsed vulns ---
    vuln_files = search_files("tag:vulnerable", limit=100)
    vuln_drivers = []

    for vf in vuln_files:
        sha = vf["id"]
        tags = tag_names(vf.get("tags", []))
        vuln_count = 0
        for t in tags:
            m = re.match(r"(\d+)_vuln_ioctlance", t)
            if m:
                vuln_count = int(m.group(1))

        product = extract_tag(vf.get("tags", []), "product:") or vf["file_name"]
        attack_score = extract_tag(vf.get("tags", []), "attack_surface_score:")
        risk = extract_tag(vf.get("tags", []), "risk:")
        framework = extract_tag(vf.get("tags", []), "framework:")

        # Parse IOCTLance comment for exploit primitives
        primitives = []
        ioctl_codes = []
        try:
            comments = api_get(f"file/{sha}/comment")
            for c in comments:
                text = c.get("comment", "")
                if "IOCTLance" not in text:
                    continue

                # Extract summary lines (before <details> block)
                summary_section = text.split("<details>")[0]
                for line in summary_section.split("\n"):
                    line = line.strip().lstrip("- ")
                    if ":" in line and any(kw in line.lower() for kw in
                        ["controllable", "overflow", "arbitrary", "oob",
                         "double free", "uninitialized", "null pointer",
                         "dereference"]):
                        primitives.append(line)

                # Extract IOCTL codes from JSON block
                json_match = re.search(r"```json\s*(\[.+?\])\s*```", text, re.DOTALL)
                if json_match:
                    try:
                        vuln_details = json.loads(json_match.group(1))
                        for vd in vuln_details:
                            code = vd.get("eval", {}).get("IoControlCode", "")
                            title = vd.get("title", "")
                            desc = vd.get("description", "")
                            if code:
                                ioctl_codes.append({
                                    "code": code,
                                    "title": title,
                                    "description": desc,
                                })
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass

        # Deduplicate primitives from ioctl_codes if summary parsing missed them
        if not primitives and ioctl_codes:
            prim_counter = Counter(ic["title"] for ic in ioctl_codes)
            primitives = [f"{title}: {count}" for title, count in prim_counter.items()]

        vuln_drivers.append({
            "name": vf["file_name"],
            "sha256": sha,
            "product": product,
            "vuln_count": vuln_count,
            "signed": "signed" in tags,
            "attack_score": attack_score,
            "risk": risk,
            "framework": framework,
            "primitives": primitives,
            "ioctl_codes": ioctl_codes,
            "tags": tags,
        })

    vuln_drivers.sort(key=lambda x: x["vuln_count"], reverse=True)
    result["vuln_drivers"] = vuln_drivers

    # Primitive summary across all drivers
    prim_counts = Counter()
    for vd in vuln_drivers:
        for ic in vd["ioctl_codes"]:
            prim_counts[ic["title"]] += 1
    result["primitive_counts"] = dict(prim_counts.most_common())

    result["_ts"] = time.time()

    with _data_lock:
        _data = result
    _data_ready.set()


def _refresh():
    try:
        _collect_data()
    except Exception as e:
        print(f"Data collection error: {e}", flush=True)
        import traceback
        traceback.print_exc()
        _data_ready.set()


def get_data():
    with _data_lock:
        ts = _data.get("_ts", 0)
    if time.time() - ts > CACHE_TTL:
        threading.Thread(target=_refresh, daemon=True).start()
        if not _data:
            _data_ready.wait(timeout=120)
    with _data_lock:
        return dict(_data)


threading.Thread(target=_refresh, daemon=True).start()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    data = get_data()
    if not data or "_ts" not in data:
        return render_template("loading.html")
    return render_template("dashboard.html", data=data)


@app.route("/driver/<sha256>")
def driver_detail(sha256):
    data = get_data()

    # Check if we have autopiff report for this driver
    report = data.get("reports", {}).get(sha256)

    # Get MWDB file info
    try:
        f = api_get(f"file/{sha256}")
    except Exception:
        abort(404)

    tags = tag_names(f.get("tags", []))
    product = extract_tag(f.get("tags", []), "product:") or f.get("file_name", sha256)
    comments = []
    try:
        comments = api_get(f"file/{sha256}/comment")
    except Exception:
        pass

    # Find in vuln_drivers
    vuln_info = None
    for vd in data.get("vuln_drivers", []):
        if vd["sha256"] == sha256:
            vuln_info = vd
            break

    driver = {
        "name": f.get("file_name", sha256),
        "sha256": sha256,
        "product": product,
        "tags": tags,
        "comments": comments,
        "report": report,
        "vuln_info": vuln_info,
        "children": f.get("children", []),
        "attributes": {a["key"]: a["value"] for a in f.get("attributes", [])},
    }
    return render_template("driver_detail.html", driver=driver)


@app.route("/vulnerable")
def vulnerable():
    data = get_data()
    if not data or "_ts" not in data:
        return render_template("loading.html")
    return render_template("vulnerable.html", drivers=data.get("vuln_drivers", []))


@app.route("/api/stats")
def api_stats():
    data = get_data()
    return jsonify({
        "counts": data.get("counts", {}),
        "total_findings": len(data.get("findings", [])),
        "category_counts": data.get("category_counts", {}),
        "rule_counts": data.get("rule_counts", {}),
        "primitive_counts": data.get("primitive_counts", {}),
        "vuln_drivers": len(data.get("vuln_drivers", [])),
        "cache_age": int(time.time() - data.get("_ts", 0)),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
