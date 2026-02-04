#!/usr/bin/env python3
"""
Test script for the semantic analysis pipeline.
Creates mock decompiled files and runs through all stages.
"""

import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis import (
    SemanticDiffEngine,
    PatchScorer,
    ReportGenerator,
    TimelineGenerator,
    parse_decompiled_functions,
    normalize_decompiled_code,
)


def create_mock_files(temp_dir: str):
    """Create mock vulnerable and patched decompiled files."""

    # Vulnerable version - no null after free
    vuln_code = '''
// FUNCTION_START: DriverEntry
void DriverEntry(void *param_1) {
    DbgPrint("Driver loading");
    return;
}
// FUNCTION_END: DriverEntry

// FUNCTION_START: HandleIoctl
int HandleIoctl(void *buffer, int length) {
    void *ptr;

    ptr = ExAllocatePoolWithTag(0, length, 'Test');
    if (ptr == NULL) {
        return -1;
    }

    RtlCopyMemory(ptr, buffer, length);

    // Process data
    ProcessBuffer(ptr);

    // Free without null assignment (vulnerable!)
    ExFreePoolWithTag(ptr, 'Test');

    return 0;
}
// FUNCTION_END: HandleIoctl

// FUNCTION_START: ProcessBuffer
void ProcessBuffer(void *buf) {
    // Some processing
    return;
}
// FUNCTION_END: ProcessBuffer
'''

    # Patched version - adds null after free
    patched_code = '''
// FUNCTION_START: DriverEntry
void DriverEntry(void *param_1) {
    DbgPrint("Driver loading");
    return;
}
// FUNCTION_END: DriverEntry

// FUNCTION_START: HandleIoctl
int HandleIoctl(void *buffer, int length) {
    void *ptr;

    // Added length check in patched version
    if (length > 4096) {
        return -2;
    }

    ptr = ExAllocatePoolWithTag(0, length, 'Test');
    if (ptr == NULL) {
        return -1;
    }

    RtlCopyMemory(ptr, buffer, length);

    // Process data
    ProcessBuffer(ptr);

    // Fixed: null after free
    ExFreePoolWithTag(ptr, 'Test');
    ptr = NULL;  // <-- FIX: null assignment after free

    return 0;
}
// FUNCTION_END: HandleIoctl

// FUNCTION_START: ProcessBuffer
void ProcessBuffer(void *buf) {
    // Some processing
    return;
}
// FUNCTION_END: ProcessBuffer
'''

    vuln_path = os.path.join(temp_dir, "driver_vuln.c")
    patched_path = os.path.join(temp_dir, "driver_patched.c")

    with open(vuln_path, 'w') as f:
        f.write(vuln_code)

    with open(patched_path, 'w') as f:
        f.write(patched_code)

    return vuln_path, patched_path


def test_pipeline():
    """Run the complete test pipeline."""
    print("=" * 70)
    print("SEMANTIC ANALYSIS PIPELINE TEST")
    print("=" * 70)

    # Create temp directory
    temp_dir = tempfile.mkdtemp(prefix="pipeline_test_")
    print(f"\nTemp directory: {temp_dir}")

    try:
        # Create mock files
        print("\n[1] Creating mock decompiled files...")
        vuln_path, patched_path = create_mock_files(temp_dir)
        print(f"    Vuln: {vuln_path}")
        print(f"    Patched: {patched_path}")

        # Test code normalizer
        print("\n[2] Testing code normalizer...")
        vuln_funcs = parse_decompiled_functions(vuln_path)
        patched_funcs = parse_decompiled_functions(patched_path)
        print(f"    Parsed {len(vuln_funcs)} vuln functions")
        print(f"    Parsed {len(patched_funcs)} patched functions")

        # Test semantic diff engine
        print("\n[3] Testing semantic diff engine...")
        engine = SemanticDiffEngine()
        result = engine.diff(vuln_path, patched_path)

        print(f"    Match rate: {result.match_rate:.1f}%")
        print(f"    Changed functions: {result.changed_functions}")
        print(f"    Semantic findings: {len(result.findings)}")

        for f in result.findings:
            print(f"      - {f.function}: {f.rule_id} ({f.category})")

        # Test scorer
        print("\n[4] Testing patch scorer...")
        scorer = PatchScorer()
        scored = scorer.score_findings(
            result.findings,
            matching_confidence=result.match_rate / 100.0
        )

        print(f"    Scored findings: {len(scored)}")
        for sf in scored:
            print(f"      - Rank {sf.rank}: {sf.finding.function} = {sf.final_score:.1f}")

        # Test report generator
        print("\n[5] Testing report generator...")
        report_gen = ReportGenerator()
        report = report_gen.generate_cve_report(
            cve_id="CVE-2024-TEST",
            scored_findings=scored,
            semantic_diff_result=result,
            cve_metadata={
                'driver_name': 'TestDriver',
                'vuln_version': '1.0.0',
                'patched_version': '1.0.1',
            }
        )

        report_path = os.path.join(temp_dir, "test_report.md")
        with open(report_path, 'w') as f:
            f.write(report)
        print(f"    Report saved: {report_path}")
        print(f"    Report size: {len(report)} bytes")

        # Test timeline generator
        print("\n[6] Testing timeline generator...")
        timeline_gen = TimelineGenerator()
        cve_results = [{
            'cve': 'CVE-2024-TEST',
            'driver_name': 'testdriver',
            'semantic_findings': len(result.findings),
            'top_score': scored[0].final_score if scored else 0,
            'semantic_match_rate': result.match_rate,
            'patched_version': '1.0.1',
        }]

        points = timeline_gen.build_timeline('testdriver', cve_results)
        print(f"    Timeline points: {len(points)}")

        if points:
            html = timeline_gen.generate_timeline_html('TestDriver', points)
            html_path = os.path.join(temp_dir, "test_timeline.html")
            with open(html_path, 'w') as f:
                f.write(html)
            print(f"    Timeline HTML saved: {html_path}")

        # Summary
        print("\n" + "=" * 70)
        print("TEST RESULTS")
        print("=" * 70)

        success = len(result.findings) > 0 and len(scored) > 0

        if success:
            print("\n[PASS] Pipeline detected the vulnerability fix!")
            print(f"       - Found {len(result.findings)} semantic finding(s)")
            print(f"       - Top score: {scored[0].final_score:.1f}" if scored else "")
            print(f"       - Rule triggered: {result.findings[0].rule_id}" if result.findings else "")
        else:
            print("\n[WARN] No findings detected (may need rule tuning)")

        print("\n[INFO] Test files available in: " + temp_dir)
        print("       Run 'rm -rf " + temp_dir + "' to cleanup")

        return success

    except Exception as e:
        print(f"\n[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_pipeline()
    sys.exit(0 if success else 1)
