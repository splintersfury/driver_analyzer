"""
Report Generator - Stage 7 Implementation

Generates markdown reports from analysis results.
"""

import os
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

from .semantic_diff import SemanticDiffResult
from .patch_scorer import ScoredFinding, PatchScorer

logger = logging.getLogger("driver_analyzer.report_generator")


class ReportGenerator:
    """
    Generates markdown reports from CVE analysis results.

    Report sections:
    - Executive Summary
    - Semantic Rule Findings (top 10 ranked)
    - Score Breakdown
    - Binary Diff Summary
    - Deep Analysis Summary
    - Diff Snippets
    """

    def __init__(self):
        """Initialize the report generator."""
        self.scorer = PatchScorer()

    def generate_cve_report(self,
                            cve_id: str,
                            scored_findings: List[ScoredFinding],
                            semantic_diff_result: SemanticDiffResult = None,
                            binary_diff_result: Dict = None,
                            deep_analysis_result: Dict = None,
                            cve_metadata: Dict = None) -> str:
        """
        Generate a complete CVE analysis report.

        Args:
            cve_id: CVE identifier
            scored_findings: List of scored semantic findings
            semantic_diff_result: Result from SemanticDiffEngine
            binary_diff_result: Result from BinaryDiffer
            deep_analysis_result: Result from DeepAnalyzer
            cve_metadata: Additional CVE metadata

        Returns:
            Markdown report string
        """
        metadata = cve_metadata or {}
        lines = []

        # Header
        lines.append(f"# CVE Analysis Report: {cve_id}")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")

        if scored_findings:
            top_score = max(f.final_score for f in scored_findings)
            categories = set(f.finding.category for f in scored_findings)
            lines.append(f"- **Semantic Findings:** {len(scored_findings)}")
            lines.append(f"- **Top Score:** {top_score:.1f}")
            lines.append(f"- **Categories:** {', '.join(categories)}")
        else:
            lines.append("- **Semantic Findings:** 0 (no vulnerability patterns detected)")

        if semantic_diff_result:
            lines.append(f"- **Function Match Rate:** {semantic_diff_result.match_rate:.1f}%")
            lines.append(f"- **Changed Functions:** {semantic_diff_result.changed_functions}")

        if metadata.get('driver_name'):
            lines.append(f"- **Driver:** {metadata['driver_name']}")
        if metadata.get('vuln_version'):
            lines.append(f"- **Vulnerable Version:** {metadata['vuln_version']}")
        if metadata.get('patched_version'):
            lines.append(f"- **Patched Version:** {metadata['patched_version']}")

        lines.append("")

        # Semantic Findings
        if scored_findings:
            lines.append("## Semantic Rule Findings")
            lines.append("")
            lines.append("| Rank | Function | Rule | Category | Confidence | Score |")
            lines.append("|------|----------|------|----------|------------|-------|")

            for sf in scored_findings[:10]:
                lines.append(
                    f"| {sf.rank} | `{sf.finding.function}` | "
                    f"{sf.finding.rule_id} | {sf.finding.category} | "
                    f"{sf.finding.confidence:.0%} | **{sf.final_score:.1f}** |"
                )

            lines.append("")

            # Detailed findings
            lines.append("### Finding Details")
            lines.append("")

            for sf in scored_findings[:5]:
                lines.append(f"#### {sf.rank}. {sf.finding.function}")
                lines.append("")
                lines.append(f"**Rule:** {sf.finding.rule_id}")
                lines.append("")
                lines.append(f"**Why it matters:** {sf.finding.why_matters}")
                lines.append("")

                if sf.finding.sinks:
                    lines.append(f"**Sinks:** {', '.join(sf.finding.sinks)}")
                    lines.append("")

                if sf.finding.indicators:
                    lines.append("**Indicators:**")
                    for ind in sf.finding.indicators[:5]:
                        lines.append(f"- `{ind}`")
                    lines.append("")

                # Score breakdown
                lines.append("**Score Breakdown:**")
                bd = sf.breakdown
                lines.append(f"- Semantic: {bd.semantic_contributions[0]['contribution']:.2f}")
                lines.append(f"- Reachability ({sf.finding.reachability_class}): {bd.reachability['contribution']:.2f}")
                lines.append(f"- Sinks: {bd.sinks['confidence_scaled']:.2f}")
                if bd.penalties:
                    total_pen = sum(bd.penalties.values())
                    lines.append(f"- Penalties: -{total_pen:.2f}")
                if bd.gates_triggered:
                    lines.append(f"- Gates: {', '.join(bd.gates_triggered)}")
                lines.append("")

        # Binary Diff Summary
        if binary_diff_result:
            lines.append("## Binary Diff Summary")
            lines.append("")
            lines.append(f"- **Total Functions (Vuln):** {binary_diff_result.get('vuln_function_count', 'N/A')}")
            lines.append(f"- **Total Functions (Patched):** {binary_diff_result.get('patched_function_count', 'N/A')}")
            lines.append(f"- **Added Functions:** {binary_diff_result.get('added_count', 0)}")
            lines.append(f"- **Removed Functions:** {binary_diff_result.get('removed_count', 0)}")
            lines.append(f"- **Changed Functions:** {binary_diff_result.get('changed_count', 0)}")
            lines.append("")

        # Deep Analysis Summary
        if deep_analysis_result:
            lines.append("## Deep Analysis Summary")
            lines.append("")

            vuln_patterns = deep_analysis_result.get('vuln_patterns', {})
            if vuln_patterns:
                lines.append("### Vulnerability Patterns Detected")
                lines.append("")
                for pattern, data in vuln_patterns.items():
                    if isinstance(data, dict) and data.get('count', 0) > 0:
                        lines.append(f"- **{pattern}:** {data['count']} occurrences")
                    elif isinstance(data, list) and len(data) > 0:
                        lines.append(f"- **{pattern}:** {len(data)} occurrences")
                lines.append("")

            dispatch = deep_analysis_result.get('dispatch_table', {})
            if dispatch:
                lines.append("### Dispatch Table")
                lines.append("")
                handlers = dispatch.get('handlers', {})
                for handler_type, handler_info in handlers.items():
                    if handler_info:
                        lines.append(f"- **{handler_type}:** {handler_info}")
                lines.append("")

        # Diff Snippets (for top findings)
        if scored_findings:
            lines.append("## Diff Snippets")
            lines.append("")

            for sf in scored_findings[:3]:
                lines.append(f"### {sf.finding.function}")
                lines.append("")
                lines.append("```diff")
                # Truncate long snippets
                snippet = sf.finding.diff_snippet
                if len(snippet) > 2000:
                    snippet = snippet[:2000] + "\n... (truncated)"
                lines.append(snippet)
                lines.append("```")
                lines.append("")

        # Footer
        lines.append("---")
        lines.append("*Generated by driver_analyzer with AutoPiff semantic rules*")

        return '\n'.join(lines)

    def generate_summary_report(self, all_cve_results: List[Dict]) -> str:
        """
        Generate a summary report across multiple CVEs.

        Args:
            all_cve_results: List of CVE result dictionaries

        Returns:
            Markdown summary report string
        """
        lines = []

        lines.append("# CVE Analysis Summary Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**CVEs Analyzed:** {len(all_cve_results)}")
        lines.append("")

        # Overview table
        lines.append("## Overview")
        lines.append("")
        lines.append("| CVE | Driver | Findings | Top Score | Match Rate |")
        lines.append("|-----|--------|----------|-----------|------------|")

        for result in all_cve_results:
            cve = result.get('cve', 'Unknown')
            driver = result.get('driver_name', 'Unknown')
            findings = result.get('semantic_findings', 0)
            top_score = result.get('top_score', 0.0)
            match_rate = result.get('semantic_match_rate', 0.0)

            lines.append(
                f"| {cve} | {driver} | {findings} | "
                f"{top_score:.1f} | {match_rate:.1f}% |"
            )

        lines.append("")

        # High-priority findings
        high_priority = [r for r in all_cve_results if r.get('top_score', 0) >= 5.0]
        if high_priority:
            lines.append("## High-Priority CVEs (Score >= 5.0)")
            lines.append("")
            for result in sorted(high_priority, key=lambda x: x.get('top_score', 0), reverse=True):
                lines.append(f"### {result.get('cve', 'Unknown')}")
                lines.append("")
                lines.append(f"- **Driver:** {result.get('driver_name', 'Unknown')}")
                lines.append(f"- **Top Score:** {result.get('top_score', 0):.1f}")
                lines.append(f"- **Findings:** {result.get('semantic_findings', 0)}")
                if result.get('report_path'):
                    lines.append(f"- **Report:** [{result['cve']}_report.md]({result['report_path']})")
                lines.append("")

        # Statistics
        lines.append("## Statistics")
        lines.append("")

        total_findings = sum(r.get('semantic_findings', 0) for r in all_cve_results)
        avg_score = sum(r.get('top_score', 0) for r in all_cve_results) / len(all_cve_results) if all_cve_results else 0
        avg_match = sum(r.get('semantic_match_rate', 0) for r in all_cve_results) / len(all_cve_results) if all_cve_results else 0

        lines.append(f"- **Total Semantic Findings:** {total_findings}")
        lines.append(f"- **Average Top Score:** {avg_score:.2f}")
        lines.append(f"- **Average Match Rate:** {avg_match:.1f}%")
        lines.append("")

        # Category breakdown
        category_counts = {}
        for result in all_cve_results:
            for cat in result.get('categories', []):
                category_counts[cat] = category_counts.get(cat, 0) + 1

        if category_counts:
            lines.append("### Findings by Category")
            lines.append("")
            for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
                lines.append(f"- **{cat}:** {count}")
            lines.append("")

        lines.append("---")
        lines.append("*Generated by driver_analyzer*")

        return '\n'.join(lines)
