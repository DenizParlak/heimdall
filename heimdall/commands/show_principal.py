# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                        ᚷᛃᚨᛚᛚᚨᚱᚺᛟᚱᚾ • GJALLARHORN
#                     Heimdall's Horn - The Voice of Warning
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "When Heimdall raises Gjallarhorn, its blast echoes across all realms,
#    announcing the presence and nature of those who approach."
#
#   This command sounds the horn for a single entity - revealing all
#   that is known about a principal's powers and weaknesses.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import json
import logging
from typing import Dict, Any, List, Optional

from rich.table import Table

from heimdall.cli_utils import console, SEVERITY_EMOJI

logger = logging.getLogger(__name__)


def run_show_principal(graph: str, name: str, output_format: str) -> None:
    """
    Deep dive into a specific IAM principal.
    
    Args:
        graph: Path to JSON file from detect-privesc
        name: Principal name or ARN
        output_format: Output format (table/json)
    """
    console.print(f"[bold cyan]👤 Principal Analysis: {name}[/bold cyan]\n")
    
    # Load data
    with open(graph, 'r') as f:
        data = json.load(f)
    
    metadata = data.get('metadata', {})
    graph_data = data.get('graph', data.get('trust_graph', {}))
    findings = data.get('findings', [])
    
    # Warn if no findings
    if not findings:
        console.print("[yellow]⚠ No findings in this file.[/yellow]")
        console.print("[dim]Tip: Run 'heimdall iam detect-privesc' to generate findings[/dim]\n")
    
    # Find principal
    principal = _find_principal(name, graph_data.get('nodes', []), findings)
    
    if not principal:
        console.print(f"[red]✗ Principal not found:[/red] {name}")
        console.print("[yellow]Tip:[/yellow] Try 'heimdall iam list-paths' or 'heimdall iam summary' to see available principals")
        return
    
    # Extract principal info
    principal_arn = principal.get('id', 'Unknown')
    principal_name = principal.get('name', 'Unknown')
    principal_type = principal.get('type', 'unknown')
    
    # Find all findings for this principal
    principal_findings = [f for f in findings if f.get('principal') == principal_arn or 
                         f.get('principal_name') == principal_name]
    
    # Calculate metrics
    metrics = _calculate_principal_metrics(principal_findings, graph_data.get('links', []), principal_arn)
    
    if output_format == 'json':
        _output_json(principal_arn, principal_name, principal_type, metadata, metrics, principal_findings)
    else:
        _output_table(principal_arn, principal_name, principal_type, metadata, metrics, principal_findings)


def _find_principal(name: str, nodes: List[Dict], findings: List[Dict]) -> Optional[Dict]:
    """Find principal in nodes or findings."""
    # Try nodes first
    for node in nodes:
        node_name = node.get('name', '')
        node_arn = node.get('id', '')
        if name in node_arn or name == node_name or name in node_name:
            return node
    
    # Try findings
    for finding in findings:
        if finding.get('principal_name') == name or name in finding.get('principal_name', ''):
            return {
                'id': finding.get('principal'),
                'name': finding.get('principal_name'),
                'type': finding.get('principal_type', 'unknown')
            }
    
    return None


def _calculate_principal_metrics(findings: List[Dict], links: List[Dict], principal_arn: str) -> Dict[str, Any]:
    """Calculate metrics for principal."""
    return {
        'critical_count': len([f for f in findings if f.get('severity') == 'CRITICAL']),
        'high_count': len([f for f in findings if f.get('severity') == 'HIGH']),
        'medium_count': len([f for f in findings if f.get('severity') == 'MEDIUM']),
        'low_count': len([f for f in findings if f.get('severity') == 'LOW']),
        'outgoing': [l for l in links if l.get('source') == principal_arn],
        'incoming': [l for l in links if l.get('target') == principal_arn],
        'methods': list(set([f.get('privesc_method', 'unknown') for f in findings]))
    }


def _output_json(arn: str, name: str, ptype: str, metadata: Dict, metrics: Dict, findings: List) -> None:
    """Output principal data as JSON."""
    principal_data = {
        'arn': arn,
        'name': name,
        'type': ptype,
        'account': metadata.get('account_id', 'Unknown'),
        'relationships': {
            'outgoing': len(metrics['outgoing']),
            'incoming': len(metrics['incoming'])
        },
        'findings': {
            'total': len(findings),
            'critical': metrics['critical_count'],
            'high': metrics['high_count'],
            'medium': metrics['medium_count'],
            'low': metrics['low_count']
        },
        'privesc_methods': metrics['methods'],
        'details': findings[:20]
    }
    console.print_json(data=principal_data)


def _output_table(arn: str, name: str, ptype: str, metadata: Dict, metrics: Dict, findings: List) -> None:
    """Output principal data as rich table."""
    # Basic info
    console.print(f"[bold]ARN:[/bold] {arn}")
    console.print(f"[bold]Name:[/bold] {name}")
    console.print(f"[bold]Type:[/bold] {ptype}")
    console.print(f"[bold]Account:[/bold] {metadata.get('account_id', 'Unknown')}")
    console.print()
    
    # Relationships
    console.print(f"[bold cyan]🔗 Trust Relationships[/bold cyan]")
    console.print(f"  • Can Assume: {len(metrics['outgoing'])} roles")
    console.print(f"  • Assumed By: {len(metrics['incoming'])} principals")
    console.print()
    
    if findings:
        _print_findings_summary(metrics, findings)
    else:
        console.print("[green]✓ No privilege escalation findings for this principal![/green]")


def _print_findings_summary(metrics: Dict, findings: List) -> None:
    """Print findings summary for principal."""
    console.print(f"[bold red]⚠️  Privilege Escalation Findings ({len(findings)})[/bold red]")
    
    # Severity table
    table = Table(show_header=True, box=None)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    
    if metrics['critical_count'] > 0:
        table.add_row("🔴 CRITICAL", str(metrics['critical_count']), style="red")
    if metrics['high_count'] > 0:
        table.add_row("🟠 HIGH", str(metrics['high_count']), style="yellow")
    if metrics['medium_count'] > 0:
        table.add_row("🟡 MEDIUM", str(metrics['medium_count']), style="bright_yellow")
    if metrics['low_count'] > 0:
        table.add_row("🟢 LOW", str(metrics['low_count']), style="green")
    
    console.print(table)
    console.print()
    
    # Attack vectors
    methods = metrics['methods']
    console.print(f"[bold yellow]🎯 Attack Vectors ({len(methods)})[/bold yellow]")
    for method in methods[:10]:
        console.print(f"  • {method}")
    if len(methods) > 10:
        console.print(f"  ... and {len(methods) - 10} more")
    console.print()
    
    # Top findings
    console.print(f"[bold]🚨 Top Findings[/bold]")
    for i, finding in enumerate(findings[:5], 1):
        severity = finding.get('severity', 'UNKNOWN')
        method = finding.get('privesc_method', 'unknown')
        target = finding.get('target_role_name', 'N/A')
        
        severity_icon = SEVERITY_EMOJI.get(severity, '⚪')
        
        console.print(f"  {i}. {severity_icon} {severity}: {method}")
        if target != 'N/A':
            console.print(f"     → Target: {target}")
    
    if len(findings) > 5:
        console.print(f"\n[dim]  ... and {len(findings) - 5} more findings[/dim]")
    console.print()
    
    # Risk assessment
    risk_score = max(0, 100 - (metrics['critical_count'] * 10) - (metrics['high_count'] * 5))
    console.print(f"[bold]📊 Risk Score:[/bold] {risk_score}/100")
    
    if metrics['critical_count'] > 0:
        console.print(f"[red bold]⚠️  CRITICAL:[/red bold] This principal has {metrics['critical_count']} CRITICAL privilege escalation paths!")
    elif metrics['high_count'] > 0:
        console.print(f"[yellow]⚠️  HIGH:[/yellow] This principal has {metrics['high_count']} HIGH severity findings.")
    else:
        console.print("[green]✓ No critical or high severity findings for this principal.[/green]")
