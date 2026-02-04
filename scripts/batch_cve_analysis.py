#!/usr/bin/env python3
"""
Batch CVE Analysis Pipeline

Runs the complete 7-step analysis pipeline:
1. Binary diff (existing)
2. Deep analysis (existing)
3. Ghidra decompilation (existing)
4. Function matching (existing)
5. Semantic diff (NEW)
6. Scoring/ranking (NEW)
7. Report generation (NEW)

Plus: Timeline generation for multi-CVE drivers

Usage:
    GHIDRA_HOME=/path/to/ghidra python3 scripts/batch_cve_analysis.py

Configuration via CVE_CONFIG or auto-discovery from results/
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis import (
    SemanticDiffEngine,
    SemanticDiffResult,
    PatchScorer,
    ScoredFinding,
    ReportGenerator,
    TimelineGenerator,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("batch_cve_analysis")

# Project paths
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
REPORTS_DIR = os.path.join(RESULTS_DIR, "reports")
TIMELINES_DIR = os.path.join(RESULTS_DIR, "timelines")
GHIDRA_CACHE_DIR = os.path.join(PROJECT_ROOT, "ghidra_cache")


def discover_cve_configs() -> List[Dict]:
    """
    Discover CVE configurations from Ghidra cache.

    Looks for pairs of decompiled .c files with vuln/patched naming.
    """
    configs = []

    if not os.path.exists(GHIDRA_CACHE_DIR):
        logger.warning(f"Ghidra cache not found: {GHIDRA_CACHE_DIR}")
        return configs

    # Look for .c files in cache
    c_files = []
    for root, dirs, files in os.walk(GHIDRA_CACHE_DIR):
        for f in files:
            if f.endswith('.c'):
                c_files.append(os.path.join(root, f))

    # Group by driver/CVE
    # Expected naming: driver_vuln.c, driver_patched.c or similar
    pairs = {}
    for c_file in c_files:
        base = os.path.basename(c_file)

        # Try to identify vuln vs patched
        if 'vuln' in base.lower():
            key = base.lower().replace('vuln', '').replace('.c', '').strip('_-')
            if key not in pairs:
                pairs[key] = {}
            pairs[key]['vuln'] = c_file
        elif 'patch' in base.lower() or 'fixed' in base.lower():
            key = base.lower().replace('patched', '').replace('patch', '').replace('fixed', '').replace('.c', '').strip('_-')
            if key not in pairs:
                pairs[key] = {}
            pairs[key]['patched'] = c_file

    # Convert pairs to configs
    for key, paths in pairs.items():
        if 'vuln' in paths and 'patched' in paths:
            # Try to extract CVE from filename or path
            cve_id = f"CVE-UNKNOWN-{key.upper()}"
            for part in key.split('_'):
                if part.lower().startswith('cve'):
                    cve_id = part.upper()
                    break

            configs.append({
                'cve': cve_id,
                'driver_name': key,
                'vuln_c_path': paths['vuln'],
                'patched_c_path': paths['patched'],
            })

    return configs


def load_cve_config(config_path: str = None) -> List[Dict]:
    """Load CVE configuration from JSON file or auto-discover."""
    if config_path and os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)

    # Try default location
    default_config = os.path.join(PROJECT_ROOT, "cve_config.json")
    if os.path.exists(default_config):
        with open(default_config, 'r') as f:
            return json.load(f)

    # Auto-discover
    logger.info("No config file found, auto-discovering from Ghidra cache...")
    return discover_cve_configs()


def analyze_single_cve(cve_config: Dict,
                       semantic_engine: SemanticDiffEngine,
                       scorer: PatchScorer,
                       report_gen: ReportGenerator) -> Dict:
    """
    Run complete analysis pipeline for a single CVE.

    Steps:
    1-4: Assumed to be already done (Ghidra decompilation exists)
    5: Semantic diff
    6: Scoring
    7: Report generation
    """
    cve_id = cve_config.get('cve', 'UNKNOWN')
    driver_name = cve_config.get('driver_name', 'unknown')

    logger.info(f"Analyzing {cve_id} ({driver_name})")

    result = {
        'cve': cve_id,
        'driver_name': driver_name,
        'vuln_version': cve_config.get('vuln_version', 'N/A'),
        'patched_version': cve_config.get('patched_version', 'N/A'),
        'status': 'pending',
        'semantic_findings': 0,
        'semantic_match_rate': 0.0,
        'top_score': 0.0,
        'scored_findings_count': 0,
        'categories': [],
        'report_path': None,
    }

    try:
        # Check for required files
        vuln_path = cve_config.get('vuln_c_path')
        patched_path = cve_config.get('patched_c_path')

        if not vuln_path or not os.path.exists(vuln_path):
            logger.warning(f"  Vulnerable .c file not found: {vuln_path}")
            result['status'] = 'missing_vuln'
            return result

        if not patched_path or not os.path.exists(patched_path):
            logger.warning(f"  Patched .c file not found: {patched_path}")
            result['status'] = 'missing_patched'
            return result

        # Step 5: Semantic diff
        logger.info(f"  [5] Running semantic diff...")
        dispatch_table = cve_config.get('dispatch_table', {})
        semantic_result = semantic_engine.diff(vuln_path, patched_path, dispatch_table)

        result['semantic_findings'] = len(semantic_result.findings)
        result['semantic_match_rate'] = semantic_result.match_rate

        logger.info(f"      Found {len(semantic_result.findings)} findings, {semantic_result.match_rate:.1f}% match rate")

        if not semantic_result.findings:
            logger.info(f"      No semantic findings - skipping scoring/reporting")
            result['status'] = 'no_findings'
            return result

        # Step 6: Scoring
        logger.info(f"  [6] Scoring findings...")
        matching_conf = semantic_result.match_rate / 100.0
        scored_findings = scorer.score_findings(
            semantic_result.findings,
            matching_confidence=matching_conf,
            pairing_decision="accept",
            noise_risk="low" if matching_conf > 0.7 else "medium",
            matching_quality="high" if matching_conf > 0.8 else ("medium" if matching_conf > 0.6 else "low")
        )

        result['scored_findings_count'] = len(scored_findings)
        result['categories'] = list(set(sf.finding.category for sf in scored_findings))

        if scored_findings:
            result['top_score'] = scored_findings[0].final_score
            logger.info(f"      Top score: {result['top_score']:.1f}, {len(scored_findings)} ranked findings")

        # Step 7: Report generation
        logger.info(f"  [7] Generating report...")
        os.makedirs(REPORTS_DIR, exist_ok=True)

        report_content = report_gen.generate_cve_report(
            cve_id=cve_id,
            scored_findings=scored_findings,
            semantic_diff_result=semantic_result,
            binary_diff_result=cve_config.get('binary_diff'),
            deep_analysis_result=cve_config.get('deep_analysis'),
            cve_metadata={
                'driver_name': driver_name,
                'vuln_version': cve_config.get('vuln_version'),
                'patched_version': cve_config.get('patched_version'),
            }
        )

        report_filename = f"{cve_id.lower().replace('-', '_')}_report.md"
        report_path = os.path.join(REPORTS_DIR, report_filename)

        with open(report_path, 'w') as f:
            f.write(report_content)

        result['report_path'] = report_path
        result['status'] = 'complete'

        logger.info(f"      Report saved: {report_path}")

    except Exception as e:
        logger.error(f"  Error analyzing {cve_id}: {e}", exc_info=True)
        result['status'] = 'error'
        result['error'] = str(e)

    return result


def print_summary_table(results: List[Dict]):
    """Print summary table of all CVE results."""
    print("\n" + "=" * 100)
    print("CVE ANALYSIS SUMMARY")
    print("=" * 100)
    print(f"{'CVE':<20} {'Driver':<20} {'Findings':<10} {'Top Score':<12} {'Match %':<10} {'Status':<15}")
    print("-" * 100)

    for r in results:
        print(f"{r['cve']:<20} {r['driver_name']:<20} "
              f"{r['semantic_findings']:<10} {r['top_score']:<12.1f} "
              f"{r['semantic_match_rate']:<10.1f} {r['status']:<15}")

    print("=" * 100)

    # Summary stats
    complete = [r for r in results if r['status'] == 'complete']
    total_findings = sum(r['semantic_findings'] for r in results)
    high_priority = [r for r in results if r['top_score'] >= 5.0]

    print(f"\nTotal CVEs: {len(results)}")
    print(f"Completed: {len(complete)}")
    print(f"Total findings: {total_findings}")
    print(f"High-priority (score >= 5.0): {len(high_priority)}")


def run_all(config_path: str = None):
    """Run the complete batch analysis pipeline."""
    logger.info("=" * 70)
    logger.info("BATCH CVE ANALYSIS PIPELINE")
    logger.info("=" * 70)

    # Load configuration
    cve_configs = load_cve_config(config_path)

    if not cve_configs:
        logger.error("No CVE configurations found!")
        logger.info("Create cve_config.json or ensure Ghidra cache has vuln/patched .c files")
        return

    logger.info(f"Found {len(cve_configs)} CVE configurations")

    # Initialize engines
    logger.info("Initializing analysis engines...")
    semantic_engine = SemanticDiffEngine()
    scorer = PatchScorer()
    report_gen = ReportGenerator()
    timeline_gen = TimelineGenerator()

    # Analyze each CVE
    all_results = []
    for config in cve_configs:
        result = analyze_single_cve(config, semantic_engine, scorer, report_gen)
        all_results.append(result)

    # Print summary
    print_summary_table(all_results)

    # Generate timelines
    logger.info("Generating timelines...")
    os.makedirs(TIMELINES_DIR, exist_ok=True)
    timeline_paths = timeline_gen.generate_all_timelines(all_results, TIMELINES_DIR)
    logger.info(f"Generated {len(timeline_paths)} timeline(s)")

    # Generate summary report
    logger.info("Generating summary report...")
    summary_content = report_gen.generate_summary_report(all_results)
    summary_path = os.path.join(RESULTS_DIR, "summary_report.md")
    with open(summary_path, 'w') as f:
        f.write(summary_content)
    logger.info(f"Summary report: {summary_path}")

    # Save JSON summary
    json_path = os.path.join(RESULTS_DIR, "cve_analysis_summary.json")
    with open(json_path, 'w') as f:
        json.dump(all_results, f, indent=2, default=str)
    logger.info(f"JSON summary: {json_path}")

    logger.info("=" * 70)
    logger.info("ANALYSIS COMPLETE")
    logger.info("=" * 70)

    return all_results


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Batch CVE Analysis Pipeline")
    parser.add_argument('--config', '-c', help='Path to CVE config JSON file')
    parser.add_argument('--cve', help='Analyze single CVE by ID')
    parser.add_argument('--list', action='store_true', help='List discovered CVE configs')

    args = parser.parse_args()

    if args.list:
        configs = load_cve_config(args.config)
        print(f"\nDiscovered {len(configs)} CVE configurations:")
        for c in configs:
            print(f"  - {c['cve']}: {c['driver_name']}")
        return

    run_all(args.config)


if __name__ == "__main__":
    main()
