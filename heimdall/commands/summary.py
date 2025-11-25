# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                         ᚺᛚᛁᛞᛊᚲᛃᚨᛚᚠ • HLIDSKJÁLF
#                      Odin's High Throne - The All-Seeing Seat
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "From Hlidskjálf, the Allfather surveys all Nine Realms at once,
#    seeing the movements of gods, giants, elves, and men."
#
#   This command grants you Odin's vision - a complete overview of your
#   realm's security posture from the highest vantage point.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import json
import logging
from typing import Dict, Any

from rich.table import Table
from rich.panel import Panel

from heimdall.cli_utils import console

logger = logging.getLogger(__name__)


def run_summary(graph: str, output_format: str) -> None:
    """
    Show quick security posture summary.
    
    Args:
        graph: Path to JSON file from detect-privesc
        output_format: Output format (table/json/compact)
    """
    console.print("[bold cyan]📊 Security Posture Summary[/bold cyan]\n")
    
    # Load data
    with open(graph, 'r') as f:
        data = json.load(f)
    
    metadata = data.get('metadata', {})
    graph_data = data.get('graph', data.get('trust_graph', {}))
    findings = data.get('findings', [])
    
    # Warn if no findings
    if not findings and output_format != 'json':
        console.print("[yellow]⚠ No findings in this file.[/yellow]")
        console.print("[dim]Tip: Run 'heimdall iam detect-privesc' to generate findings[/dim]\n")
    
    # Calculate metrics
    metrics = _calculate_metrics(metadata, graph_data, findings, data)
    
    # Output based on format
    if output_format == 'json':
        _output_json(metrics, findings)
    elif output_format == 'compact':
        _output_compact(metrics)
    else:
        _output_table(metrics, findings)


def _calculate_metrics(metadata: Dict, graph_data: Dict, findings: list, data: Dict) -> Dict[str, Any]:
    """Calculate all summary metrics."""
    stats = graph_data.get('stats', {})
    
    # Basic counts
    role_count = stats.get('role_count', 0)
    user_count = stats.get('user_count', 0)
    edge_count = stats.get('edge_count', 0)
    service_count = stats.get('service_count', 0)
    federated_count = stats.get('federated_count', 0)
    
    # Findings by severity
    critical_count = len([f for f in findings if f.get('severity') == 'CRITICAL'])
    high_count = len([f for f in findings if f.get('severity') == 'HIGH'])
    medium_count = len([f for f in findings if f.get('severity') == 'MEDIUM'])
    low_count = len([f for f in findings if f.get('severity') == 'LOW'])
    
    # Paths
    risky_paths = data.get('risky_paths', [])
    human_to_role_paths = len([p for p in risky_paths if 'user' in p.get('source', {}).get('type', '')])
    
    # Security score
    security_score = max(0, 100 - (critical_count * 10) - (high_count * 5))
    
    return {
        'account_id': metadata.get('account_id', 'Unknown'),
        'scan_time': metadata.get('scan_timestamp', 'Unknown'),
        'role_count': role_count,
        'user_count': user_count,
        'edge_count': edge_count,
        'service_count': service_count,
        'federated_count': federated_count,
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'risky_paths': risky_paths,
        'human_to_role_paths': human_to_role_paths,
        'security_score': security_score
    }


def _output_json(metrics: Dict, findings: list) -> None:
    """Output summary as JSON."""
    summary_data = {
        'account_id': metrics['account_id'],
        'scan_timestamp': metrics['scan_time'],
        'security_score': metrics['security_score'],
        'principals': {
            'roles': metrics['role_count'],
            'users': metrics['user_count'],
            'services': metrics['service_count'],
            'federated': metrics['federated_count'],
            'total': metrics['role_count'] + metrics['user_count']
        },
        'relationships': metrics['edge_count'],
        'findings': {
            'critical': metrics['critical_count'],
            'high': metrics['high_count'],
            'medium': metrics['medium_count'],
            'low': metrics['low_count'],
            'total': len(findings)
        },
        'paths': {
            'human_to_role': metrics['human_to_role_paths'],
            'total_risky': len(metrics['risky_paths'])
        }
    }
    console.print_json(data=summary_data)


def _output_compact(metrics: Dict) -> None:
    """Output summary in compact one-line format."""
    console.print(
        f"Account: {metrics['account_id']} | Score: {metrics['security_score']}/100 | "
        f"Principals: {metrics['role_count'] + metrics['user_count']} | "
        f"Findings: 🔴{metrics['critical_count']} 🟠{metrics['high_count']} "
        f"🟡{metrics['medium_count']} 🟢{metrics['low_count']}"
    )


def _output_table(metrics: Dict, findings: list) -> None:
    """Output summary as rich tables."""
    # Account info
    console.print(f"[bold]Account:[/bold] {metrics['account_id']}")
    console.print(f"[bold]Scan Time:[/bold] {metrics['scan_time']}")
    console.print(f"[bold]Security Score:[/bold] {metrics['security_score']}/100", end=" ")
    
    score = metrics['security_score']
    if score >= 90:
        console.print("[green]Excellent ✓[/green]")
    elif score >= 70:
        console.print("[yellow]Good[/yellow]")
    elif score >= 50:
        console.print("[orange]Fair ⚠️[/orange]")
    else:
        console.print("[red]Poor ✗[/red]")
    
    console.print()
    
    # Principals table
    _print_principals_table(metrics)
    
    # Findings table
    _print_findings_table(metrics, findings)
    
    # Attack surface
    console.print(f"[bold]Attack Surface:[/bold]")
    console.print(f"  • Trust Relationships: {metrics['edge_count']}")
    console.print(f"  • Human→Role Paths: {metrics['human_to_role_paths']}")
    console.print(f"  • Total Risky Paths: {len(metrics['risky_paths'])}")
    console.print()
    
    # Recommendations
    if metrics['critical_count'] > 0:
        console.print(f"[red bold]⚠️  Action Required:[/red bold] {metrics['critical_count']} CRITICAL findings need immediate attention!")
    elif metrics['high_count'] > 0:
        console.print(f"[yellow]⚠️  Attention:[/yellow] {metrics['high_count']} HIGH severity findings detected.")
    else:
        console.print("[green]✓ No critical or high severity findings![/green]")


def _print_principals_table(metrics: Dict) -> None:
    """Print principals summary table."""
    table = Table(title="IAM Principals", show_header=True, box=None)
    table.add_column("Type", style="cyan")
    table.add_column("Count", justify="right", style="bold white")
    
    table.add_row("👥 IAM Roles", str(metrics['role_count']))
    table.add_row("👤 IAM Users", str(metrics['user_count']))
    table.add_row("⚙️  Service Principals", str(metrics['service_count']))
    table.add_row("🌐 Federated Identities", str(metrics['federated_count']))
    table.add_row("━━━━━━━━━━━━━━━━", "━━━━━━")
    table.add_row("Total Principals", str(metrics['role_count'] + metrics['user_count']), style="bold")
    
    console.print(table)
    console.print()


def _print_findings_table(metrics: Dict, findings: list) -> None:
    """Print findings summary table."""
    table = Table(title="⚠️  Security Findings", show_header=True, box=None)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Graph", style="dim")
    
    max_count = max(
        metrics['critical_count'], metrics['high_count'], 
        metrics['medium_count'], metrics['low_count'], 1
    )
    
    if metrics['critical_count'] > 0:
        bar = "█" * int((metrics['critical_count'] / max_count) * 20)
        table.add_row("🔴 CRITICAL", str(metrics['critical_count']), bar, style="red")
    
    if metrics['high_count'] > 0:
        bar = "█" * int((metrics['high_count'] / max_count) * 20)
        table.add_row("🟠 HIGH", str(metrics['high_count']), bar, style="yellow")
    
    if metrics['medium_count'] > 0:
        bar = "█" * int((metrics['medium_count'] / max_count) * 20)
        table.add_row("🟡 MEDIUM", str(metrics['medium_count']), bar, style="bright_yellow")
    
    if metrics['low_count'] > 0:
        bar = "█" * int((metrics['low_count'] / max_count) * 20)
        table.add_row("🟢 LOW", str(metrics['low_count']), bar, style="green")
    
    table.add_row("━━━━━━━━━━━━", "━━━━━━", "━━━━━━━━━━━━━━━━━━━━")
    table.add_row("Total Findings", str(len(findings)), "", style="bold")
    
    console.print(table)
    console.print()
