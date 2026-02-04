"""
Semantic Diff Engine

Glue layer: parses .c files, normalizes, diffs, runs rule engine.
"""

import os
import difflib
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from .code_normalizer import normalize_decompiled_code, parse_decompiled_functions
from .semantic_rule_engine import SemanticRuleEngine, RuleHit

logger = logging.getLogger("driver_analyzer.semantic_diff")


@dataclass
class SemanticFinding:
    """A semantic finding from diff analysis."""
    function: str
    rule_id: str
    category: str
    confidence: float
    sinks: List[str]
    indicators: List[str]
    why_matters: str
    diff_snippet: str
    reachability_class: str = "unknown"
    delta_score: float = 0.0


@dataclass
class SemanticDiffResult:
    """Result of semantic diff analysis."""
    vuln_path: str
    patched_path: str
    total_functions_vuln: int
    total_functions_patched: int
    matched_functions: int
    changed_functions: int
    match_rate: float
    findings: List[SemanticFinding]

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class SemanticDiffEngine:
    """
    Engine for semantic diff analysis of decompiled code.

    Parses decompiled .c files, normalizes code, produces diffs,
    and runs semantic rule engine to detect vulnerability fixes.
    """

    def __init__(self, rules_dir: str = None):
        """
        Initialize the semantic diff engine.

        Args:
            rules_dir: Optional path to rules directory
        """
        self.rule_engine = SemanticRuleEngine(rules_dir)
        logger.info(f"SemanticDiffEngine initialized with {self.rule_engine.get_rule_count()} rules")

    def diff(self, vuln_c_path: str, patched_c_path: str,
             dispatch_table: Dict = None) -> SemanticDiffResult:
        """
        Perform semantic diff analysis between vulnerable and patched versions.

        Args:
            vuln_c_path: Path to vulnerable version's decompiled .c file
            patched_c_path: Path to patched version's decompiled .c file
            dispatch_table: Optional dispatch table for reachability classification

        Returns:
            SemanticDiffResult with findings
        """
        # Parse functions from both files
        vuln_funcs = parse_decompiled_functions(vuln_c_path)
        patched_funcs = parse_decompiled_functions(patched_c_path)

        logger.info(f"Parsed {len(vuln_funcs)} vuln functions, {len(patched_funcs)} patched functions")

        # Find matched functions
        matched = set(vuln_funcs.keys()) & set(patched_funcs.keys())
        logger.info(f"Matched {len(matched)} functions")

        # Calculate match rate
        total_patched = len(patched_funcs)
        match_rate = (len(matched) / total_patched * 100) if total_patched > 0 else 0.0

        # Find changed functions and analyze them
        findings = []
        changed_count = 0

        for func_name in matched:
            vuln_code = vuln_funcs[func_name]
            patched_code = patched_funcs[func_name]

            # Normalize for comparison
            vuln_normalized = normalize_decompiled_code(vuln_code)
            patched_normalized = normalize_decompiled_code(patched_code)

            if vuln_normalized != patched_normalized:
                changed_count += 1

                # Generate unified diff
                diff_lines = list(difflib.unified_diff(
                    vuln_normalized.splitlines(keepends=True),
                    patched_normalized.splitlines(keepends=True),
                    lineterm=''
                ))

                # Run semantic rule engine
                hits = self.rule_engine.evaluate(
                    func_name,
                    vuln_code,
                    patched_code,
                    diff_lines
                )

                # Convert hits to findings
                for hit in hits:
                    reachability = self._classify_reachability(func_name, dispatch_table)
                    finding = SemanticFinding(
                        function=func_name,
                        rule_id=hit.rule_id,
                        category=hit.category,
                        confidence=hit.confidence,
                        sinks=hit.sinks,
                        indicators=hit.indicators,
                        why_matters=hit.why_matters,
                        diff_snippet=hit.diff_snippet,
                        reachability_class=reachability
                    )
                    findings.append(finding)

        logger.info(f"Found {len(findings)} semantic findings in {changed_count} changed functions")

        return SemanticDiffResult(
            vuln_path=vuln_c_path,
            patched_path=patched_c_path,
            total_functions_vuln=len(vuln_funcs),
            total_functions_patched=len(patched_funcs),
            matched_functions=len(matched),
            changed_functions=changed_count,
            match_rate=match_rate,
            findings=findings
        )

    def _classify_reachability(self, func_name: str, dispatch_table: Dict = None) -> str:
        """
        Classify function reachability from dispatch table.

        Returns: 'ioctl', 'irp', 'pnp', 'internal', or 'unknown'
        """
        if not dispatch_table:
            return "unknown"

        # Check if function is in dispatch table
        handlers = dispatch_table.get('handlers', {})

        for handler_type, handler_info in handlers.items():
            if isinstance(handler_info, dict):
                handler_func = handler_info.get('function', '')
            else:
                handler_func = str(handler_info)

            if func_name.lower() in handler_func.lower():
                if 'ioctl' in handler_type.lower() or 'device_control' in handler_type.lower():
                    return 'ioctl'
                elif 'irp' in handler_type.lower():
                    return 'irp'
                elif 'pnp' in handler_type.lower():
                    return 'pnp'

        # Check call graph if available
        call_graph = dispatch_table.get('call_graph', {})
        for caller, callees in call_graph.items():
            if func_name in callees:
                # Check if caller is reachable
                caller_reach = self._classify_reachability(caller, dispatch_table)
                if caller_reach != 'unknown':
                    return caller_reach

        return "internal"

    def diff_from_json(self, analysis_json: Dict) -> SemanticDiffResult:
        """
        Perform semantic diff from cached analysis JSON.

        Args:
            analysis_json: Dictionary with 'vuln_source' and 'patched_source' paths

        Returns:
            SemanticDiffResult
        """
        vuln_path = analysis_json.get('vuln_source', analysis_json.get('vuln_c_path'))
        patched_path = analysis_json.get('patched_source', analysis_json.get('patched_c_path'))
        dispatch_table = analysis_json.get('dispatch_table')

        if not vuln_path or not patched_path:
            raise ValueError("Missing vuln_source or patched_source in analysis JSON")

        return self.diff(vuln_path, patched_path, dispatch_table)
