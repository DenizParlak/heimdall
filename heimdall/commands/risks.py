# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                              ᚾᛟᚱᚾᛊ • THE NORNS
#                   Urðr, Verðandi, Skuld - Weavers of Fate
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "Beneath the great ash Yggdrasil, the three Norns weave the threads
#    of destiny, seeing what was, what is, and what shall be."
#
#   This module reveals the risks woven into your IAM fabric - the
#   dangerous threads that could unravel your realm's security.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import json
import logging

from rich.table import Table

from heimdall.cli_utils import (
    console, truncate, format_severity, DEFAULT_TABLE_LIMIT
)

logger = logging.getLogger(__name__)


def run_risks(graph: str, severity: str) -> None:
    """
    Show risky privilege escalation paths.
    
    Args:
        graph: Path to graph JSON file
        severity: Filter by severity level (critical/high/medium/low/all)
    """
    logger.info("Analyzing risks: graph=%s, severity=%s", graph, severity)
    console.print("\n[bold cyan]⚠️  Heimdall Risk Assessment[/bold cyan]\n")
    
    # Load graph
    with open(graph) as f:
        data = json.load(f)
    
    # Support multiple data sources
    risky_paths = data.get('risky_paths', [])
    findings = data.get('findings', [])
    
    # Convert findings to risky_paths format if no risky_paths
    if not risky_paths and findings:
        risky_paths = _convert_findings_to_paths(findings)
    
    # Filter by severity
    if severity != 'all':
        risky_paths = [p for p in risky_paths if p.get('severity', '').lower() == severity]
    
    if not risky_paths:
        console.print(f"[green]✓ No {severity} severity risks found![/green]\n")
        return
    
    console.print(f"[yellow]Found {len(risky_paths)} {severity} risk(s):[/yellow]\n")
    
    # Create and display table
    _display_risks_table(risky_paths)
    
    console.print(f"\n[dim]Total: {len(risky_paths)} risks[/dim]\n")


def _convert_findings_to_paths(findings: list) -> list:
    """Convert detect-privesc findings to risky_paths format."""
    return [
        {
            'severity': f.get('severity', 'UNKNOWN'),
            'path': [f.get('principal_name', 'Unknown'), f.get('target_role_name', f.get('privesc_method', 'target'))],
            'reason': f.get('privesc_method', 'Privilege escalation'),
            'principal': f.get('principal_name'),
            'method': f.get('privesc_method'),
            'target': f.get('target_role_name'),
        }
        for f in findings
    ]


def _display_risks_table(risky_paths: list) -> None:
    """Display risks in a formatted table."""
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Principal", width=20)
    table.add_column("Method", width=25)
    table.add_column("Target", width=20)
    
    for path_info in risky_paths[:DEFAULT_TABLE_LIMIT]:
        sev = path_info.get('severity', 'UNKNOWN')
        
        # Support both formats
        if 'principal' in path_info:
            principal = path_info.get('principal', 'N/A')
            method = path_info.get('method', path_info.get('reason', 'N/A'))
            target = path_info.get('target') or 'self'
        else:
            path = path_info.get('path', [])
            principal = path[0].split('/')[-1] if path else 'N/A'
            method = path_info.get('reason', 'N/A')
            target = path[-1].split('/')[-1] if len(path) > 1 else 'N/A'
        
        table.add_row(
            format_severity(sev),
            truncate(principal, 20),
            truncate(method, 25),
            truncate(target, 20) if target else 'self'
        )
    
    console.print(table)
