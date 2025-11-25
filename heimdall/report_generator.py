"""
Heimdall HTML Report Generator

Generate professional, interactive HTML security reports from scan data.

This module provides HTML report generation functionality for Heimdall,
creating standalone HTML files with:
    - Executive summary with security score
    - Severity distribution charts
    - Interactive findings table with filtering
    - Trust graph visualization
    - Mobile-responsive dark theme design

Design Philosophy:
    - Standalone: Single HTML file with embedded CSS/JS
    - Professional: Dark theme inspired by GitHub Security, SonarQube
    - Accessible: Semantic HTML, keyboard navigation support
    - Performant: Minimal dependencies, lazy rendering for large datasets

Usage:
    from heimdall.report_generator import generate_html_report
    generate_html_report(scan_data, 'report.html')

Author: Heimdall Security Team
"""

from __future__ import annotations

import json
import base64
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Type Aliases (Python 3.9+ compatible)
ReportData = Dict[str, Any]
FindingData = Dict[str, Any]


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Heimdall - {{ account_id }}</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --accent: #58a6ff;
            --critical: #f85149;
            --high: #db6d28;
            --medium: #d29922;
            --low: #3fb950;
            --font-mono: 'SF Mono', 'Fira Code', Consolas, monospace;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
        
        /* Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .logo-icon {
            width: 32px;
            height: 32px;
            background: var(--accent);
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }
        
        .logo-text {
            font-size: 20px;
            font-weight: 600;
            color: var(--text-primary);
        }
        
        .meta {
            font-size: 12px;
            color: var(--text-secondary);
            font-family: var(--font-mono);
        }
        
        /* Score Section */
        .score-section {
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 24px;
            margin-bottom: 32px;
        }
        
        .score-ring {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
        }
        
        .score-value {
            font-size: 48px;
            font-weight: 700;
            font-family: var(--font-mono);
        }
        
        .score-value.critical { color: var(--critical); }
        .score-value.poor { color: var(--high); }
        .score-value.fair { color: var(--medium); }
        .score-value.good { color: var(--low); }
        
        .score-label {
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 8px;
        }
        
        .severity-bars {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }
        
        .severity-bar {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
        }
        
        .severity-bar:last-child { margin-bottom: 0; }
        
        .severity-label {
            width: 80px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .severity-label.critical { color: var(--critical); }
        .severity-label.high { color: var(--high); }
        .severity-label.medium { color: var(--medium); }
        .severity-label.low { color: var(--low); }
        
        .bar-container {
            flex: 1;
            height: 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            margin: 0 12px;
            overflow: hidden;
        }
        
        .bar-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s;
        }
        
        .bar-fill.critical { background: var(--critical); }
        .bar-fill.high { background: var(--high); }
        .bar-fill.medium { background: var(--medium); }
        .bar-fill.low { background: var(--low); }
        
        .severity-count {
            width: 40px;
            font-family: var(--font-mono);
            font-size: 14px;
            font-weight: 600;
            text-align: right;
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }
        
        .stat-box {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }
        
        .stat-value {
            font-size: 28px;
            font-weight: 600;
            font-family: var(--font-mono);
            color: var(--text-primary);
        }
        
        .stat-label {
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 4px;
        }
        
        /* Findings Table */
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }
        
        .section-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
        }
        
        .tab-buttons {
            display: flex;
            gap: 4px;
            background: var(--bg-tertiary);
            border-radius: 6px;
            padding: 4px;
        }
        
        .tab-btn {
            padding: 6px 12px;
            border: none;
            background: transparent;
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 500;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .tab-btn:hover { color: var(--text-primary); }
        .tab-btn.active { background: var(--bg-secondary); color: var(--text-primary); }
        
        .findings-table {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .table-header {
            display: grid;
            grid-template-columns: 100px 1fr 200px 150px;
            padding: 12px 16px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border);
            font-size: 11px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .table-row {
            display: grid;
            grid-template-columns: 100px 1fr 200px 150px;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            font-size: 13px;
            transition: background 0.2s;
        }
        
        .table-row:last-child { border-bottom: none; }
        .table-row:hover { background: var(--bg-tertiary); }
        
        .severity-tag {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-tag.critical { background: rgba(248,81,73,0.15); color: var(--critical); }
        .severity-tag.high { background: rgba(219,109,40,0.15); color: var(--high); }
        .severity-tag.medium { background: rgba(210,153,34,0.15); color: var(--medium); }
        .severity-tag.low { background: rgba(63,185,80,0.15); color: var(--low); }
        
        .severity-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }
        
        .severity-dot.critical { background: var(--critical); }
        .severity-dot.high { background: var(--high); }
        .severity-dot.medium { background: var(--medium); }
        .severity-dot.low { background: var(--low); }
        
        .principal-name {
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--accent);
        }
        
        .method-name {
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--text-secondary);
        }
        
        .target-name {
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--text-muted);
        }
        
        /* Footer */
        .footer {
            margin-top: 32px;
            padding-top: 16px;
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: var(--text-muted);
        }
        
        .footer a {
            color: var(--accent);
            text-decoration: none;
        }
        
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        @media (max-width: 768px) {
            .score-section { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .table-header, .table-row { grid-template-columns: 80px 1fr 120px; }
            .table-header > div:last-child, .table-row > div:last-child { display: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <div class="logo-icon">⛨</div>
                <span class="logo-text">Heimdall</span>
            </div>
            <div class="meta">{{ account_id }} · {{ timestamp }}</div>
        </div>
        
        <div class="score-section">
            <div class="score-ring">
                <div class="score-value {{ score_class }}">{{ security_score }}</div>
                <div class="score-label">Security Score</div>
            </div>
            <div class="severity-bars">
                <div class="severity-bar">
                    <span class="severity-label critical">Critical</span>
                    <div class="bar-container">
                        <div class="bar-fill critical" style="width: {{ critical_pct }}%"></div>
                    </div>
                    <span class="severity-count">{{ critical_count }}</span>
                </div>
                <div class="severity-bar">
                    <span class="severity-label high">High</span>
                    <div class="bar-container">
                        <div class="bar-fill high" style="width: {{ high_pct }}%"></div>
                    </div>
                    <span class="severity-count">{{ high_count }}</span>
                </div>
                <div class="severity-bar">
                    <span class="severity-label medium">Medium</span>
                    <div class="bar-container">
                        <div class="bar-fill medium" style="width: {{ medium_pct }}%"></div>
                    </div>
                    <span class="severity-count">{{ medium_count }}</span>
                </div>
                <div class="severity-bar">
                    <span class="severity-label low">Low</span>
                    <div class="bar-container">
                        <div class="bar-fill low" style="width: {{ low_pct }}%"></div>
                    </div>
                    <span class="severity-count">{{ low_count }}</span>
                </div>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-value">{{ role_count }}</div>
                <div class="stat-label">IAM Roles</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{{ user_count }}</div>
                <div class="stat-label">IAM Users</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{{ edge_count }}</div>
                <div class="stat-label">Trust Relations</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{{ total_findings }}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>
        
        <div class="section-header">
            <span class="section-title">Privilege Escalation Paths</span>
            <div class="tab-buttons">
                <button class="tab-btn active" onclick="showTab('all-tab')">All ({{ total_findings }})</button>
                <button class="tab-btn" onclick="showTab('critical-tab')">Critical ({{ critical_count }})</button>
                <button class="tab-btn" onclick="showTab('high-tab')">High ({{ high_count }})</button>
                <button class="tab-btn" onclick="showTab('medium-tab')">Medium ({{ medium_count }})</button>
                <button class="tab-btn" onclick="showTab('low-tab')">Low ({{ low_count }})</button>
            </div>
        </div>
        
        <div class="findings-table">
            <div class="table-header">
                <div>Severity</div>
                <div>Principal</div>
                <div>Method</div>
                <div>Target</div>
            </div>
            <div id="all-tab" class="tab-content active">
                {{ all_findings_html }}
            </div>
            <div id="critical-tab" class="tab-content">
                {{ critical_findings_html }}
            </div>
            <div id="high-tab" class="tab-content">
                {{ high_findings_html }}
            </div>
            <div id="medium-tab" class="tab-content">
                {{ medium_findings_html }}
            </div>
            <div id="low-tab" class="tab-content">
                {{ low_findings_html }}
            </div>
        </div>
        
        <div class="footer">
            <span>Heimdall v{{ version }}</span>
            <span>Generated {{ timestamp }}</span>
        </div>
    </div>
    
    <script>
        function showTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
"""


def generate_finding_html(finding: Dict[str, Any]) -> str:
    """Generate HTML table row for a single finding"""
    severity = finding.get("severity", "UNKNOWN").lower()
    principal_name = finding.get("principal_name", "Unknown")
    method = finding.get("privesc_method", "unknown")
    target = finding.get("target_role_name", "")
    
    # Some methods don't have target roles (e.g., self-escalation)
    if not target:
        target = "<span style='color: var(--text-muted); font-style: italic;'>self</span>"
    
    return f"""<div class="table-row">
        <div><span class="severity-tag {severity}"><span class="severity-dot {severity}"></span>{severity.upper()}</span></div>
        <div class="principal-name">{principal_name}</div>
        <div class="method-name">{method}</div>
        <div class="target-name">{target}</div>
    </div>"""


def generate_graph_tree(graph_data: Dict[str, Any]) -> str:
    """Generate ASCII tree representation of graph"""
    nodes = graph_data.get("nodes", [])
    
    users = [n for n in nodes if n.get("type") == "user"][:10]
    roles = [n for n in nodes if n.get("type") == "role"][:10]
    services = [n for n in nodes if n.get("type") == "service"][:5]
    
    tree = "🛡️ IAM Trust Graph\n"
    tree += "│\n"
    
    if users:
        tree += "├─ 👥 Users\n"
        for i, user in enumerate(users):
            prefix = "│  └─" if i == len(users) - 1 else "│  ├─"
            tree += f"{prefix} {user.get('name', 'Unknown')}\n"
        if len([n for n in nodes if n.get('type') == 'user']) > 10:
            tree += f"│  └─ ... and {len([n for n in nodes if n.get('type') == 'user']) - 10} more\n"
    
    if roles:
        tree += "│\n├─ 🎭 Roles\n"
        for i, role in enumerate(roles):
            prefix = "│  └─" if i == len(roles) - 1 else "│  ├─"
            tree += f"{prefix} {role.get('name', 'Unknown')}\n"
        if len([n for n in nodes if n.get('type') == 'role']) > 10:
            tree += f"│  └─ ... and {len([n for n in nodes if n.get('type') == 'role']) - 10} more\n"
    
    if services:
        tree += "│\n└─ ⚙️  Service Principals\n"
        for i, service in enumerate(services):
            prefix = "   └─" if i == len(services) - 1 else "   ├─"
            tree += f"{prefix} {service.get('name', 'Unknown')}\n"
        if len([n for n in nodes if n.get('type') == 'service']) > 5:
            tree += f"   └─ ... and {len([n for n in nodes if n.get('type') == 'service']) - 5} more\n"
    
    return tree


def generate_html_report(data: Dict[str, Any], output_file: str) -> None:
    """
    Generate HTML report from scan data
    
    Args:
        data: Scan data (graph + findings)
        output_file: Output HTML file path
    """
    from heimdall import __version__
    
    # Extract data - support both graph and trust_graph keys
    metadata = data.get("metadata", {})
    graph = data.get("trust_graph", data.get("graph", {}))
    findings = data.get("findings", [])
    stats = graph.get("stats", {})
    
    # Calculate counts by severity
    critical_count = len([f for f in findings if f.get("severity") == "CRITICAL"])
    high_count = len([f for f in findings if f.get("severity") == "HIGH"])
    medium_count = len([f for f in findings if f.get("severity") == "MEDIUM"])
    low_count = len([f for f in findings if f.get("severity") == "LOW"])
    total_findings = len(findings)
    total_principals = stats.get("role_count", 0) + stats.get("user_count", 0)
    
    # Security Score Calculation (weighted severity approach)
    # Max possible penalty per category, then calculate percentage
    if total_findings == 0:
        security_score = 100
    else:
        # Weight: Critical=4, High=3, Medium=2, Low=1
        weighted_score = (critical_count * 4) + (high_count * 3) + (medium_count * 2) + (low_count * 1)
        max_weighted = total_findings * 4  # If all were critical
        
        # Invert: 0 weighted = 100 score, max weighted = 0 score
        # But use a curve so it's not linear
        risk_ratio = weighted_score / max_weighted if max_weighted > 0 else 0
        security_score = int(100 * (1 - risk_ratio) ** 0.5)  # Square root curve for less harsh scoring
        
        # Clamp between 0-100
        security_score = max(0, min(100, security_score))
    
    # Score class for coloring
    if security_score < 25:
        score_class = "critical"
    elif security_score < 50:
        score_class = "poor"
    elif security_score < 75:
        score_class = "fair"
    else:
        score_class = "good"
    
    # Calculate percentages for bar chart (relative to max)
    max_count = max(critical_count, high_count, medium_count, low_count, 1)
    critical_pct = (critical_count / max_count) * 100 if max_count > 0 else 0
    high_pct = (high_count / max_count) * 100 if max_count > 0 else 0
    medium_pct = (medium_count / max_count) * 100 if max_count > 0 else 0
    low_pct = (low_count / max_count) * 100 if max_count > 0 else 0
    
    # Generate findings HTML by severity
    critical_findings = [f for f in findings if f.get("severity") == "CRITICAL"]
    high_findings = [f for f in findings if f.get("severity") == "HIGH"]
    medium_findings = [f for f in findings if f.get("severity") == "MEDIUM"]
    low_findings_list = [f for f in findings if f.get("severity") == "LOW"]
    
    empty_msg = '<div class="table-row" style="grid-column: 1/-1; text-align: center; color: var(--low); padding: 20px;">No findings in this category ✓</div>'
    
    critical_findings_html = "\n".join([generate_finding_html(f) for f in critical_findings[:50]]) or empty_msg
    high_findings_html = "\n".join([generate_finding_html(f) for f in high_findings[:50]]) or empty_msg
    medium_findings_html = "\n".join([generate_finding_html(f) for f in medium_findings[:50]]) or empty_msg
    low_findings_html = "\n".join([generate_finding_html(f) for f in low_findings_list[:50]]) or empty_msg
    all_findings_html = "\n".join([generate_finding_html(f) for f in findings[:100]]) or empty_msg
    
    # Fill template
    html = HTML_TEMPLATE
    html = html.replace("{{ account_id }}", metadata.get("account_id", "Unknown"))
    html = html.replace("{{ timestamp }}", datetime.now().strftime("%Y-%m-%d %H:%M"))
    html = html.replace("{{ version }}", __version__)
    html = html.replace("{{ security_score }}", str(security_score))
    html = html.replace("{{ score_class }}", score_class)
    html = html.replace("{{ role_count }}", str(stats.get("role_count", 0)))
    html = html.replace("{{ user_count }}", str(stats.get("user_count", 0)))
    html = html.replace("{{ edge_count }}", str(stats.get("edge_count", 0)))
    html = html.replace("{{ critical_count }}", str(critical_count))
    html = html.replace("{{ high_count }}", str(high_count))
    html = html.replace("{{ medium_count }}", str(medium_count))
    html = html.replace("{{ low_count }}", str(low_count))
    html = html.replace("{{ critical_pct }}", str(int(critical_pct)))
    html = html.replace("{{ high_pct }}", str(int(high_pct)))
    html = html.replace("{{ medium_pct }}", str(int(medium_pct)))
    html = html.replace("{{ low_pct }}", str(int(low_pct)))
    html = html.replace("{{ total_findings }}", str(total_findings))
    html = html.replace("{{ total_principals }}", str(total_principals))
    html = html.replace("{{ critical_findings_html }}", critical_findings_html)
    html = html.replace("{{ high_findings_html }}", high_findings_html)
    html = html.replace("{{ medium_findings_html }}", medium_findings_html)
    html = html.replace("{{ low_findings_html }}", low_findings_html)
    html = html.replace("{{ all_findings_html }}", all_findings_html)
    
    # Write file
    Path(output_file).write_text(html, encoding="utf-8")
