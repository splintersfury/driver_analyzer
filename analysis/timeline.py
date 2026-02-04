"""
Timeline Generator

Generates interactive Chart.js HTML visualizations of driver version timelines.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger("driver_analyzer.timeline")


@dataclass
class VersionPoint:
    """A point on the driver version timeline."""
    version: str
    build_number: int
    match_rate: float
    semantic_findings: int
    top_score: float
    cve_ids: List[str] = field(default_factory=list)


class TimelineGenerator:
    """
    Generates interactive timelines showing driver version analysis over time.

    Uses Chart.js for visualization.
    """

    def __init__(self):
        """Initialize the timeline generator."""
        pass

    def build_timeline(self, driver_name: str, cve_results: List[Dict]) -> List[VersionPoint]:
        """
        Build a timeline from CVE analysis results.

        Args:
            driver_name: Name of the driver
            cve_results: List of CVE result dictionaries

        Returns:
            List of VersionPoint objects sorted by build number
        """
        # Group results by version
        version_data = {}

        for result in cve_results:
            if result.get('driver_name', '').lower() != driver_name.lower():
                continue

            # Use patched version as the reference point
            version = result.get('patched_version', result.get('vuln_version', 'unknown'))
            if version == 'unknown':
                continue

            if version not in version_data:
                version_data[version] = {
                    'findings': 0,
                    'top_score': 0.0,
                    'match_rate': 0.0,
                    'cve_ids': [],
                    'build_number': self._extract_build_number(version)
                }

            version_data[version]['findings'] += result.get('semantic_findings', 0)
            version_data[version]['top_score'] = max(
                version_data[version]['top_score'],
                result.get('top_score', 0.0)
            )
            version_data[version]['match_rate'] = result.get('semantic_match_rate', 0.0)
            version_data[version]['cve_ids'].append(result.get('cve', 'Unknown'))

        # Convert to VersionPoint list
        points = []
        for version, data in version_data.items():
            points.append(VersionPoint(
                version=version,
                build_number=data['build_number'],
                match_rate=data['match_rate'],
                semantic_findings=data['findings'],
                top_score=data['top_score'],
                cve_ids=data['cve_ids']
            ))

        # Sort by build number
        points.sort(key=lambda p: p.build_number)

        return points

    def _extract_build_number(self, version: str) -> int:
        """Extract a numeric build number from version string."""
        # Try to parse common version formats
        # e.g., "10.0.19041.1234" -> 190411234
        # e.g., "6.3.9600.18340" -> 9600018340

        parts = version.replace('-', '.').split('.')
        try:
            # Take last 2-3 significant parts
            nums = [int(p) for p in parts if p.isdigit()]
            if len(nums) >= 2:
                # Combine last parts into a sortable number
                return nums[-2] * 100000 + nums[-1]
            elif len(nums) == 1:
                return nums[0]
        except (ValueError, IndexError):
            pass

        return 0

    def generate_timeline_html(self, driver_name: str, points: List[VersionPoint]) -> str:
        """
        Generate an interactive HTML timeline using Chart.js.

        Args:
            driver_name: Name of the driver
            points: List of VersionPoint objects

        Returns:
            HTML string
        """
        # Prepare data for Chart.js
        labels = [p.version for p in points]
        scores = [p.top_score for p in points]
        findings = [p.semantic_findings for p in points]
        match_rates = [p.match_rate for p in points]

        # Generate tooltips
        tooltips = []
        for p in points:
            tooltip = f"Version: {p.version}\\nScore: {p.top_score:.1f}\\nFindings: {p.semantic_findings}"
            if p.cve_ids:
                tooltip += f"\\nCVEs: {', '.join(p.cve_ids)}"
            tooltips.append(tooltip)

        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>{driver_name} - Version Timeline</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #666;
            margin-bottom: 30px;
        }}
        .chart-container {{
            position: relative;
            height: 400px;
            margin-bottom: 30px;
        }}
        .legend {{
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 20px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 4px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 30px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
        }}
        .score-high {{ color: #dc3545; font-weight: bold; }}
        .score-medium {{ color: #fd7e14; }}
        .score-low {{ color: #28a745; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{driver_name}</h1>
        <p class="subtitle">Semantic Analysis Timeline - {len(points)} versions analyzed</p>

        <div class="chart-container">
            <canvas id="timelineChart"></canvas>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Version</th>
                    <th>Top Score</th>
                    <th>Findings</th>
                    <th>Match Rate</th>
                    <th>CVEs</th>
                </tr>
            </thead>
            <tbody>
'''

        for p in points:
            score_class = 'score-high' if p.top_score >= 5 else ('score-medium' if p.top_score >= 3 else 'score-low')
            cves = ', '.join(p.cve_ids) if p.cve_ids else '-'
            html += f'''                <tr>
                    <td>{p.version}</td>
                    <td class="{score_class}">{p.top_score:.1f}</td>
                    <td>{p.semantic_findings}</td>
                    <td>{p.match_rate:.1f}%</td>
                    <td>{cves}</td>
                </tr>
'''

        html += f'''            </tbody>
        </table>
    </div>

    <script>
        const ctx = document.getElementById('timelineChart').getContext('2d');
        new Chart(ctx, {{
            type: 'line',
            data: {{
                labels: {json.dumps(labels)},
                datasets: [{{
                    label: 'Top Score',
                    data: {json.dumps(scores)},
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    fill: true,
                    tension: 0.3,
                    yAxisID: 'y'
                }}, {{
                    label: 'Findings Count',
                    data: {json.dumps(findings)},
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    fill: false,
                    tension: 0.3,
                    yAxisID: 'y1'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                interaction: {{
                    mode: 'index',
                    intersect: false,
                }},
                plugins: {{
                    title: {{
                        display: true,
                        text: 'Vulnerability Fix Detection Over Versions'
                    }},
                    tooltip: {{
                        callbacks: {{
                            afterBody: function(context) {{
                                const idx = context[0].dataIndex;
                                const tooltips = {json.dumps(tooltips)};
                                return tooltips[idx];
                            }}
                        }}
                    }}
                }},
                scales: {{
                    y: {{
                        type: 'linear',
                        display: true,
                        position: 'left',
                        title: {{
                            display: true,
                            text: 'Score'
                        }},
                        min: 0,
                        max: 15
                    }},
                    y1: {{
                        type: 'linear',
                        display: true,
                        position: 'right',
                        title: {{
                            display: true,
                            text: 'Findings'
                        }},
                        grid: {{
                            drawOnChartArea: false
                        }},
                        min: 0
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>'''

        return html

    def generate_all_timelines(self, cve_results: List[Dict], output_dir: str) -> List[str]:
        """
        Generate timeline HTML files for all drivers.

        Args:
            cve_results: List of all CVE result dictionaries
            output_dir: Directory to write timeline HTML files

        Returns:
            List of generated file paths
        """
        os.makedirs(output_dir, exist_ok=True)

        # Group by driver
        drivers = set()
        for result in cve_results:
            driver = result.get('driver_name', '').lower()
            if driver:
                drivers.add(driver)

        generated = []

        for driver_name in drivers:
            points = self.build_timeline(driver_name, cve_results)

            if not points:
                continue

            html = self.generate_timeline_html(driver_name, points)

            # Sanitize filename
            safe_name = ''.join(c if c.isalnum() or c in '-_' else '_' for c in driver_name)
            output_path = os.path.join(output_dir, f"{safe_name}_timeline.html")

            with open(output_path, 'w') as f:
                f.write(html)

            logger.info(f"Generated timeline: {output_path}")
            generated.append(output_path)

        return generated
