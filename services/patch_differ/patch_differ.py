
import logging
import os
import shutil
import subprocess
import tempfile
import difflib
import re
import uuid
import datetime
import json
from typing import Optional, Tuple, List, Dict, Set

from karton.core import Karton, Task, Resource
from mwdblib import MWDB, MWDBFile

import pefile

# Import AutoPiff semantic rule engine
try:
    from rule_engine import SemanticRuleEngine
    RULE_ENGINE_AVAILABLE = True
except ImportError:
    RULE_ENGINE_AVAILABLE = False

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("karton.driver.patch_differ")

def normalize_decompiled_code(code: str) -> str:
    """
    Normalize Ghidra decompiled code to remove address-specific patterns.
    This prevents false positives from code relocation between versions.

    Normalizes:
    - DAT_14006xxxx -> GLOBAL (data references)
    - FUN_14000xxxx -> FUNC (function calls)
    - PTR_xxx_140xxxxx -> PTR (pointer tables)
    - LAB_14000xxxx -> LABEL (jump labels)
    - Hex addresses like 0x14004fxxx -> ADDR (string/data addresses)
    - _DAT_14006xxxx -> _GLOBAL (underscore prefixed globals)
    - _UNK_14006xxxx -> _UNK (unknown data)
    - uRam addresses -> RAM_VAR (direct memory references)
    """
    normalized = code

    # Order matters - do more specific patterns first

    # PTR tables: PTR_FUN_140066c80 or PTR__guard_dispatch_icall_1400664d0
    normalized = re.sub(r'PTR_[A-Za-z_]*_14[0-9a-fA-F]{7,8}', 'PTR_NORMALIZED', normalized)

    # Function references: FUN_140001234
    normalized = re.sub(r'FUN_14[0-9a-fA-F]{7,8}', 'FUNC', normalized)

    # Data references with underscore prefix: _DAT_14006e968, _UNK_14006xxxx
    normalized = re.sub(r'_DAT_14[0-9a-fA-F]{7,8}', '_GLOBAL', normalized)
    normalized = re.sub(r'_UNK_14[0-9a-fA-F]{7,8}', '_UNK', normalized)

    # Data references: DAT_14006c968
    normalized = re.sub(r'DAT_14[0-9a-fA-F]{7,8}', 'GLOBAL', normalized)

    # Jump labels: LAB_140001234
    normalized = re.sub(r'LAB_14[0-9a-fA-F]{7,8}', 'LABEL', normalized)

    # Hex address constants: 0x14004f210 (string addresses, etc)
    normalized = re.sub(r'0x14[0-9a-fA-F]{7,8}', 'ADDR', normalized)

    # Direct RAM references: uRam000000014006c981
    normalized = re.sub(r'[iu]Ram[0-9a-fA-F]{16}', 'RAM_VAR', normalized)

    # Stack cookie references that change between versions
    normalized = re.sub(r'auStack[A-Za-z]*_[0-9a-fA-F]+', 'STACK_VAR', normalized)
    normalized = re.sub(r'local_[0-9a-fA-F]+', 'LOCAL_VAR', normalized)
    normalized = re.sub(r'local_res[0-9a-fA-F]+', 'LOCAL_RES', normalized)

    # Parameter variables with hex suffixes: param_1, puVar2, etc stay as-is (they're semantic)
    # But large hex offsets in struct access can vary: + 0x168 vs + 0x170
    # We keep these as they may indicate actual structural changes

    return normalized


class DetailedDiff:
    def __init__(self, old_functions: Dict[str, str], new_functions: Dict[str, str], normalize: bool = True):
        self.old_funcs = old_functions
        self.new_funcs = new_functions
        self.normalize = normalize
        self.matched_funcs = set(old_functions.keys()) & set(new_functions.keys())
        self.added_funcs = set(new_functions.keys()) - set(old_functions.keys())
        self.removed_funcs = set(old_functions.keys()) - set(new_functions.keys())

        self.diffs = {} # func_name -> list of diff lines
        self.delta_scores = {} # func_name -> int score
        self.changed_funcs = set()

        self._calculate_diffs()

    def _calculate_diffs(self):
        for func in self.matched_funcs:
            old_code = self.old_funcs[func]
            new_code = self.new_funcs[func]

            # Normalize code to remove address-specific patterns
            if self.normalize:
                old_code = normalize_decompiled_code(old_code)
                new_code = normalize_decompiled_code(new_code)

            old_lines = old_code.splitlines()
            new_lines = new_code.splitlines()

            diff = list(difflib.unified_diff(
                old_lines, new_lines, n=3, lineterm=''
            ))

            if diff:
                self.diffs[func] = diff
                self.changed_funcs.add(func)
                # Calculate simple delta score: added + removed lines (excluding header)
                score = 0
                for line in diff:
                     if line.startswith('+') and not line.startswith('+++'): score += 1
                     elif line.startswith('-') and not line.startswith('---'): score += 1
                self.delta_scores[func] = score

class PatchDiffKarton(Karton):
    """
    Karton service that performs patch diffing between a new driver sample
    and the closest previous version found in the corpus.
    """
    identity = "karton.driver.patch_differ"
    filters = [
        {
            "type": "driver",
            "kind": "driver:windows"
        },
        {
            "type": "analysis",
            "kind": "patch_differ"
        }
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mwdb = MWDB(
            api_url=os.environ.get("MWDB_API_URL", "http://mwdb-core:8080/api/"),
            api_key=os.environ.get("MWDB_API_KEY")
        )

        # Initialize AutoPiff semantic rule engine
        self.rule_engine = None
        if RULE_ENGINE_AVAILABLE:
            rules_dir = os.environ.get("AUTOPIFF_RULES_DIR", "/app/rules")
            rules_path = os.path.join(rules_dir, "semantic_rules.yaml")
            sinks_path = os.path.join(rules_dir, "sinks.yaml")
            if os.path.exists(rules_path) and os.path.exists(sinks_path):
                try:
                    self.rule_engine = SemanticRuleEngine(rules_path, sinks_path)
                    logger.info(f"AutoPiff rule engine loaded: {len(self.rule_engine.rules)} rules, {len(self.rule_engine.sink_lookup)} sinks")
                except Exception as e:
                    logger.warning(f"Failed to load rule engine: {e}")
            else:
                logger.info("AutoPiff rules not found, using basic pattern detection")

    def _get_version_info(self, file_path: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Extracts Product Name, File Version, and Architecture from PE.
        Returns: (product_name, file_version, arch_str)
        """
        try:
            pe = pefile.PE(file_path, fast_load=True)
            
            # Architecture
            arch = "Unknown"
            if pe.FILE_HEADER.Machine == 0x8664: arch = "x64"
            elif pe.FILE_HEADER.Machine == 0x014c: arch = "x86"
            elif pe.FILE_HEADER.Machine == 0xAA64: arch = "ARM64"

            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            
            product_name = None
            file_version = None

            if hasattr(pe, 'FileInfo'):
                for entry in pe.FileInfo:
                    for child in entry:
                        if hasattr(child, 'StringTable'):
                            for st in child.StringTable:
                                for key, val in st.entries.items():
                                    k = key.decode('utf-8', errors='ignore')
                                    v = val.decode('utf-8', errors='ignore')
                                    if k == 'ProductName': product_name = v
                                    elif k == 'FileVersion': file_version = v
            
            if not product_name and hasattr(pe, 'VS_VERSIONINFO'):
                for fileinfo in pe.VS_VERSIONINFO:
                     if hasattr(fileinfo, 'StringTable'):
                        for st in fileinfo.StringTable:
                            for key, val in st.entries.items():
                                k = key.decode('utf-8', errors='ignore')
                                v = val.decode('utf-8', errors='ignore')
                                if k == 'ProductName': product_name = v
                                elif k == 'FileVersion': file_version = v
            
            return product_name, file_version, arch
        except Exception as e:
            logger.warning(f"Failed to extract info from {file_path}: {e}")
            return None, None, None

    def _parse_version(self, version_str: str) -> List[int]:
        if not version_str: return []
        clean_ver = re.sub(r'[^0-9\.]', '', version_str)
        try:
            return [int(x) for x in clean_ver.split('.') if x]
        except:
            return []

    def _find_closest_prior_version(self, product_name: str, target_version: str, current_sha: str, current_arch: str) -> Optional[MWDBFile]:
        if not product_name or not target_version: return None

        product_tag_safe = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', product_name).strip("_")
        product_tag_safe = product_tag_safe[:50].strip("_")
        query = f'tag:"product:{product_tag_safe.lower()}"'
        
        target_ver_tuple = self._parse_version(target_version)
        if not target_ver_tuple: return None

        candidates = []
        import itertools
        for sample in itertools.islice(self.mwdb.search_files(query), 50): 
            version_attr = None
            for key, values in sample.attributes.items():
                if key in ['sig_file_version', 'file_version']:
                    if values:
                        version_attr = values[0]
                        break
            
            # Architecture check
            # We look for "arch:x64" etc tags
            sample_arch_tag = next((t for t in sample.tags if t.startswith("arch:")), None)
            
            # Policy: 
            # 1. If sample has conflicting arch tag -> Reject
            # 2. If sample has NO arch tag -> Accept (legacy/unknown)
            # 3. If sample has matching arch tag -> Accept
            
            normalized_current_arch = f"arch:{current_arch.lower()}"
            if sample_arch_tag and sample_arch_tag != normalized_current_arch:
                 # Mismatch, skip
                 continue

            if version_attr:
                cand_ver_tuple = self._parse_version(version_attr)
                # Allow strictly older, OR same version but different SHA
                if cand_ver_tuple and (cand_ver_tuple < target_ver_tuple or (cand_ver_tuple == target_ver_tuple and sample.sha256 != current_sha)):
                    candidates.append((cand_ver_tuple, sample))
        
        if not candidates: return None
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    def _run_ghidra_decompile(self, file_path: str, temp_dir: str) -> Optional[str]:
        filename = os.path.basename(file_path)
        output_dir = os.path.join(temp_dir, f"ghidra_out_{filename}")
        os.makedirs(output_dir, exist_ok=True)
        
        ghidra_home = os.environ.get("GHIDRA_HOME", "/app/ghidra")
        headless_script = os.path.join(ghidra_home, "support", "analyzeHeadless")
        project_dir = os.path.join(temp_dir, f"ghidra_proj_{filename}")
        os.makedirs(project_dir, exist_ok=True)
        
        cmd = [
            headless_script, project_dir, "temp_project",
            "-import", file_path, "-scriptPath", "/app",
            "-postScript", "ExportDecompiled.py", output_dir,
            "-deleteProject"
        ]
        
        logger.info(f"Decompiling {filename}...")
        try:
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2400) # 40 mins
        except subprocess.TimeoutExpired:
            logger.error(f"Ghidra timed out for {filename}")
            return None

        expected_output = os.path.join(output_dir, filename + ".c")
        if os.path.exists(expected_output): return expected_output
        files = [f for f in os.listdir(output_dir) if f.endswith(".c")]
        if files: return os.path.join(output_dir, files[0])
        return None

    def _get_decompiled_source(self, sample_obj: MWDBFile, temp_dir: str) -> Optional[str]:
        for child in sample_obj.children:
            if child.name.endswith(".c") and ("source_c" in child.tags or "ghidra_decompiled" in child.tags):
                out_path = os.path.join(temp_dir, f"{sample_obj.sha256}.c")
                logger.info(f"Found existing source for {sample_obj.sha256}, downloading...")
                content = child.download()
                
                if b"// FUNCTION_START:" not in content:
                    logger.info(f"Legacy source found for {sample_obj.sha256} (no delimiters). Re-decompiling.")
                    continue

                with open(out_path, "wb") as f: f.write(content)
                return out_path
        
        sample_path = os.path.join(temp_dir, sample_obj.sha256)
        logger.info(f"Downloading sample {sample_obj.sha256} for decompilation...")
        content = sample_obj.download()
        with open(sample_path, "wb") as f: f.write(content)
        return self._run_ghidra_decompile(sample_path, temp_dir)

    def _parse_ghidra_output_list(self, file_path: str) -> List[Tuple[str, str]]:
        """Parses the delimited Ghidra output into a list of (function_name, code) tuples"""
        funcs = []
        current_func = None
        current_code = []
        parse_order = 0
        
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                if line.startswith("// FUNCTION_START:"):
                    parts = line.strip().split(":", 1)
                    if len(parts) > 1:
                        meta = parts[1].strip().split("@")
                        raw_name = meta[0].strip()
                        
                        # Normalization: If generic name (FUN_, sub_, undefined), use index
                        if raw_name.startswith("FUN_") or raw_name.startswith("sub_") or raw_name.startswith("undefined"):
                             func_name = f"sub_{parse_order:04d}" 
                        else:
                             func_name = raw_name
                             
                        current_func = func_name
                        current_code = []
                        parse_order += 1
                elif line.startswith("// FUNCTION_END"):
                    if current_func:
                        funcs.append((current_func, "".join(current_code).strip()))
                        current_func = None
                else:
                    if current_func:
                        current_code.append(line)
        return funcs

    def _align_functions(self, old_funcs: List[Tuple[str, str]], new_funcs: List[Tuple[str, str]]) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        Aligns functions based on content similarity using Longest Common Subsequence (LCS).
        Returns (old_dict, new_dict) where matched functions share the same key.
        """
        import hashlib
        import difflib
        import uuid
        
        # 1. Create content hashes
        def get_hash(code):
            return hashlib.md5(code.encode('utf-8')).hexdigest()
            
        old_hashes = [get_hash(f[1]) for f in old_funcs]
        new_hashes = [get_hash(f[1]) for f in new_funcs]
        
        # 2. Use SequenceMatcher to find longest common subsequence of HASHES
        matcher = difflib.SequenceMatcher(None, old_hashes, new_hashes)
        
        old_dict = {}
        new_dict = {}
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                for k in range(i2 - i1):
                    old_idx = i1 + k
                    new_idx = j1 + k
                    key = new_funcs[new_idx][0] 
                    old_dict[key] = old_funcs[old_idx][1]
                    new_dict[key] = new_funcs[new_idx][1]
                    
            elif tag == 'replace':
                count = min(i2-i1, j2-j1)
                for k in range(count):
                    old_idx = i1 + k
                    new_idx = j1 + k
                    key = new_funcs[new_idx][0]
                    old_dict[key] = old_funcs[old_idx][1]
                    new_dict[key] = new_funcs[new_idx][1]
                
                if (i2-i1) > (j2-j1): # Removed
                    for k in range(count, i2-i1):
                        old_idx = i1 + k
                        key = f"{old_funcs[old_idx][0]}_REMOVED_{uuid.uuid4().hex[:4]}"
                        old_dict[key] = old_funcs[old_idx][1]
                elif (j2-j1) > (i2-i1): # Added
                    for k in range(count, j2-j1):
                        new_idx = j1 + k
                        key = new_funcs[new_idx][0]
                        new_dict[key] = new_funcs[new_idx][1]

            elif tag == 'delete':
                for k in range(i2 - i1):
                    old_idx = i1 + k
                    key = f"{old_funcs[old_idx][0]}_REMOVED_{uuid.uuid4().hex[:4]}"
                    old_dict[key] = old_funcs[old_idx][1]
            
            elif tag == 'insert':
                for k in range(j2 - j1):
                    new_idx = j1 + k
                    key = new_funcs[new_idx][0]
                    new_dict[key] = new_funcs[new_idx][1]

        return old_dict, new_dict

    def _classify_surface(self, code: str) -> List[str]:
        surfaces = []
        if "IRP_MJ_DEVICE_CONTROL" in code or "IoControlCode" in code or "SystemBuffer" in code or "Type3InputBuffer" in code:
            surfaces.append("IOCTL / IRP Control Plane")
        if "MiniportOidRequest" in code or "FilterOidRequest" in code or "Ndis" in code:
            surfaces.append("NDIS / Network")
        if "StorPort" in code or "Srb" in code or "SCSI" in code:
            surfaces.append("Storage (Storport/SCSI)")
        if "Flt" in code or "FSCTL" in code:
            surfaces.append("File System / Filter")
        return list(set(surfaces))

    def _detect_fix_patterns(self, diff: List[str]) -> List[Dict]:
        patterns = []
        if any(("InputBufferLength" in l or "OutputBufferLength" in l or "InformationBufferLength" in l) and (">" in l or "<" in l) for l in diff if l.startswith('+')):
            patterns.append({"type": "Input Length Validation", "confidence": "High", "desc": "Added buffer length comparisons."})

        added_cmd_checks = [l for l in diff if l.startswith('+') and "cmd" in l.lower() and (">" in l or "<" in l or "==" in l or "switch" in l)]
        if added_cmd_checks:
            patterns.append({"type": "Opcode/Command Allowlist", "confidence": "Medium", "desc": "Added opcode range checks or switch cases."})

        if any("ProbeFor" in l for l in diff if l.startswith('+')):
            patterns.append({"type": "Probe Added", "confidence": "High", "desc": "Added ProbeForRead/Write call."})

        if any(("Rtl" in l and "Mult" in l) or "Overflow" in l for l in diff if l.startswith('+')):
            patterns.append({"type": "Integer Overflow Fix", "confidence": "High", "desc": "Added safe integer math function."})

        return patterns

    def _run_semantic_analysis(self, diff_obj: DetailedDiff, old_funcs: Dict[str, str], new_funcs: Dict[str, str]) -> List[Dict]:
        """Run AutoPiff semantic rule engine on changed functions.

        Uses normalized code to avoid false positives from address relocations.
        """
        if not self.rule_engine:
            return []

        all_hits = []
        for func_name in diff_obj.changed_funcs:
            old_code = old_funcs.get(func_name, "")
            new_code = new_funcs.get(func_name, "")
            diff_lines = diff_obj.diffs.get(func_name, [])

            # Normalize code to remove address-specific patterns
            # This ensures the semantic rules match on actual logic changes, not relocations
            old_code_normalized = normalize_decompiled_code(old_code)
            new_code_normalized = normalize_decompiled_code(new_code)

            try:
                hits = self.rule_engine.evaluate(func_name, old_code_normalized, new_code_normalized, diff_lines)
                for hit in hits:
                    all_hits.append({
                        'function': func_name,
                        'rule_id': hit.rule_id,
                        'category': hit.category,
                        'confidence': hit.confidence,
                        'sinks': hit.sinks,
                        'indicators': hit.indicators,
                        'why_matters': hit.why_matters,
                        'delta_score': diff_obj.delta_scores.get(func_name, 0)
                    })
            except Exception as e:
                logger.warning(f"Rule engine error on {func_name}: {e}")

        # Sort by confidence
        all_hits.sort(key=lambda x: x['confidence'], reverse=True)
        return all_hits

    def _generate_semantic_report_section(self, semantic_hits: List[Dict]) -> str:
        """Generate markdown section for semantic analysis findings."""
        if not semantic_hits:
            return ""

        report = "\n## 6) Semantic Rule Analysis (AutoPiff)\n\n"
        report += f"**{len(semantic_hits)} security-relevant patterns detected**\n\n"

        # Group by category
        by_category = {}
        for hit in semantic_hits:
            cat = hit['category']
            by_category[cat] = by_category.get(cat, 0) + 1

        report += "### By Category\n"
        for cat, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
            report += f"- **{cat}**: {count} findings\n"
        report += "\n"

        report += "### Top Findings\n"
        report += "| # | Category | Function | Confidence | Rule |\n"
        report += "|---|----------|----------|------------|------|\n"

        for i, hit in enumerate(semantic_hits[:15], 1):
            conf_pct = f"{hit['confidence']*100:.0f}%"
            report += f"| {i} | {hit['category']} | `{hit['function'][:20]}` | {conf_pct} | {hit['rule_id']} |\n"
        report += "\n"

        # Detailed findings for top 5
        report += "### Detailed Analysis\n\n"
        for i, hit in enumerate(semantic_hits[:5], 1):
            report += f"#### {i}. {hit['function']}\n"
            report += f"- **Rule:** {hit['rule_id']}\n"
            report += f"- **Category:** {hit['category']}\n"
            report += f"- **Confidence:** {hit['confidence']*100:.0f}%\n"
            report += f"- **Why it matters:** {hit['why_matters']}\n"
            if hit['sinks']:
                report += f"- **Sinks involved:** {', '.join(hit['sinks'][:5])}\n"
            if hit['indicators']:
                report += f"- **Indicators:** {', '.join(hit['indicators'][:5])}\n"
            report += "\n"

        return report

    def process(self, task: Task) -> None:
        sample_resource = task.get_resource("sample")
        if not sample_resource: return
        sha256 = sample_resource.sha256
        logger.info(f"Starting patch diff check for {sha256}")

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # 1. Download and Identify
                current_path = os.path.join(temp_dir, "current_sample.sys")
                with open(current_path, "wb") as f: f.write(sample_resource.content)
                
                product, version, arch = self._get_version_info(current_path)
                if not product or not version:
                    logger.info("Skipping: No Product/Version info.")
                    return
                
                # Tag current sample with architecture for future reference
                if arch != "Unknown":
                    try: self.mwdb.file(sha256).add_tag(f"arch:{arch.lower()}")
                    except: pass
                
                product_tag = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', product).strip("_")[:50]
                logger.info(f"Identified: {product} v{version} ({arch})")

                # 2. Find Prior (with Arch check)
                prior = self._find_closest_prior_version(product, version, sha256, arch)
                if not prior:
                    logger.info(f"No compatible prior version found (Arch: {arch}).")
                    return
                
                # 3. Source extraction
                new_src_path = self._run_ghidra_decompile(current_path, temp_dir)
                old_src_path = self._get_decompiled_source(prior, temp_dir)
                if not new_src_path or not old_src_path:
                    logger.error("Decompilation failed.")
                    return

                # 5. Diff Analysis
                # Parse to lists
                new_funcs_list = self._parse_ghidra_output_list(new_src_path)
                old_funcs_list = self._parse_ghidra_output_list(old_src_path)
                
                logger.info(f"Parsing functions... (New: {len(new_funcs_list)}, Old: {len(old_funcs_list)})")
                
                # Check Arch Mismatch
                old_arch_tag = next((t for t in prior.tags if t.startswith("arch:")), "arch:unknown")
                arch_mismatch = False
                if arch.lower() not in old_arch_tag and "unknown" not in old_arch_tag:
                     arch_mismatch = True
                     logger.warning(f"Architecture mismatch detected: New={arch}, Old={old_arch_tag}")

                # Align functions (Smart Matching)
                old_funcs_dict, new_funcs_dict = self._align_functions(old_funcs_list, new_funcs_list)
                
                logger.info("Analyzing diffs...")
                diff_obj = DetailedDiff(old_funcs_dict, new_funcs_dict)
                # Generate Metadata
                old_ver = prior.attributes.get('file_version', ['Unknown'])[0] if isinstance(prior.attributes.get('file_version'), list) else prior.attributes.get('file_version', 'Unknown')

                report = "# 🛡️ Patch Diff Report (Generic)\n\n"
                
                if arch_mismatch:
                    report += "> [!WARNING]\n"
                    report += f"> **Architecture Mismatch Detected**: New is {arch}, Old is {old_arch_tag}. Diffs may be noisy due to compiler/arch differences.\n\n"
                    
                report += "## 1) Executive Summary\n\n"
                report += f"**Product / Family:** {product} (tag: {product_tag})\n\n"
                report += "**Binary Pair:**\n"
                report += f"- **New:** {sha256} | Version {version} | Arch {arch}\n"
                report += f"- **Old:** {prior.sha256} | Version {old_ver} | {old_arch_tag}\n\n"
                
                # Stats calculation (Total comes from aligned dicts now)
                diff_matched = len(diff_obj.matched_funcs)
                diff_total = len(new_funcs_dict) # This is effectively new_funcs_list length
                pct = (diff_matched / diff_total * 100) if diff_total > 0 else 0
                report += f"**Function match coverage:** {diff_matched}/{diff_total} ({pct:.1f}%)\n\n"

                # Match Rate Categorization
                mwdb_tags = []
                if pct > 85:
                    match_cat = "high"
                elif pct >= 70:
                    match_cat = "medium"
                else:
                    match_cat = "low"
                mwdb_tags.append(f"diff_match:{match_cat}")
                
                report += "### Key Findings (Automated)\n"
                # Heuristics on top changed functions
                top_changed = sorted(diff_obj.changed_funcs, key=lambda f: diff_obj.delta_scores.get(f, 0), reverse=True)
                
                detections = []
                surfaces = set()
                
                for mysql_func in top_changed[:10]:
                    # Surface detection
                    s = self._classify_surface(new_funcs_dict[mysql_func])
                    surfaces.update(s)
                    
                    # Fix detection
                    d = self._detect_fix_patterns(diff_obj.diffs[mysql_func])
                    for item in d:
                        item['func'] = mysql_func
                        detections.append(item)
                
                if detections:
                    for det in detections[:5]:
                        report += f"- ✅ **{det['type']}** detected in `{det['func']}` ({det['desc']})\n"
                else:
                    report += "- ℹ️ No specific security fix patterns detected automatically.\n"
                
                if surfaces:
                    report += f"- **Surface Areas:** {', '.join(surfaces)}\n"

                report += "\n## 2) Diff Stats\n"
                report += f"- **Total functions:** New: {len(new_funcs_list)} | Old: {len(old_funcs_list)}\n"
                report += f"- **Matched:** {len(diff_obj.matched_funcs)} | **Changed:** {len(diff_obj.changed_funcs)}\n"
                report += f"- **New-only:** {len(diff_obj.added_funcs)} | **Old-only:** {len(diff_obj.removed_funcs)}\n\n"
                
                report += "### Change Heatmap (Top 10 by Delta Score)\n"
                report += "| Rank | Function | Delta Score | Potential Reason |\n"
                report += "|---|---|---|---|\n"
                for i, func in enumerate(top_changed[:10]):
                    score = diff_obj.delta_scores[func]
                    reasons = [d['type'] for d in detections if d.get('func') == func]
                    reason_str = ", ".join(reasons) if reasons else "Logic Change"
                    report += f"| {i+1} | `{func}` | {score} | {reason_str} |\n"
                report += "\n"

                report += "## 3) Surface Area Classification\n"
                if surfaces:
                    for s in surfaces: report += f"- [x] {s}\n"
                else:
                    report += "No specific surface area patterns (IOCTL, NDIS, Storage) detected in changed functions.\n"
                report += "\n"

                report += "## 4) Security-Relevant Fix Patterns\n"
                if detections:
                    for det in detections:
                        report += f"### 4.{detections.index(det)+1} {det['type']}\n"
                        report += f"**Function:** `{det['func']}`\n"
                        report += f"**Confidence:** {det['confidence']}\n"
                        report += "```diff\n"
                        # Show snippet of diff
                        func_diff = diff_obj.diffs[det['func']]
                        # Find the relevant lines
                        for line in func_diff[:20]: # First 20 lines of diff
                            report += line + "\n"
                        report += "```\n\n"
                else:
                    report += "No high-confidence security fix patterns found.\n\n"

                report += "## 5) Top Candidates for Inspection\n"
                for i, func in enumerate(top_changed[:3]):
                    report += f"### Candidate {i+1}: `{func}`\n"
                    # Add reachability info check
                    surf = self._classify_surface(new_funcs_dict[func])
                    if surf: report += f"**Reachability:** {', '.join(surf)}\n"

                    report += "```diff\n"
                    for line in diff_obj.diffs[func][:30]: # First 30 lines
                        report += line + "\n"
                    report += "...\n```\n\n"

                # Run AutoPiff semantic analysis
                semantic_hits = self._run_semantic_analysis(diff_obj, old_funcs_dict, new_funcs_dict)
                if semantic_hits:
                    report += self._generate_semantic_report_section(semantic_hits)
                    logger.info(f"Semantic analysis found {len(semantic_hits)} rule hits")

                    # Add semantic tags
                    semantic_categories = set(h['category'] for h in semantic_hits)
                    for cat in list(semantic_categories)[:5]:
                        mwdb_tags.append(f"semantic:{cat.replace('_', '-')}")

                # 7. Upload
                report_filename = f"Patch_Diff_v{version}_vs_v{old_ver}.md"
                logger.info(f"Uploading report {report_filename}...")
                
                mwdb_tags.extend(["patch_diff", f"patchdiff:family={product_tag}", f"same_family:{product_tag}"])
                for s in surfaces: mwdb_tags.append(f"surface:{s.split(' ')[0].lower()}")
                for det in detections: mwdb_tags.append(f"fix:{det['type'].lower().replace(' ','_')}")

                self.mwdb.upload_file(
                    name=report_filename,
                    content=report.encode('utf-8'),
                    parent=sha256,
                    tags=list(set(mwdb_tags))[:20] # Limit to 20 tags
                )
                
                # Add tag to original sample
                try: self.mwdb.file(sha256).add_tag("patch_diff_analyzed")
                except: pass

                logger.info("Analysis completed.")

        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    PatchDiffKarton().loop()
