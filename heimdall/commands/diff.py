# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                       ᛗᛁᛗᛁᚱᛊ ᛒᚱᚢᚾᚾᚱ • MÍMIR'S WELL
#                    The Well of Wisdom at Yggdrasil's Root
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "Odin sacrificed his eye to drink from Mímir's Well, gaining the
#    wisdom to see the past and compare it with the present."
#
#   This module compares two moments in time - revealing what changed,
#   what emerged, and what dangers now lurk in your realm.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import json
import logging
from typing import Optional, Dict, Any

from rich.table import Table
from rich.panel import Panel

from heimdall.cli_utils import console, SEVERITY_EMOJI

logger = logging.getLogger(__name__)


def run_diff(
    baseline: str,
    current: str,
    output_format: str,
    output_file: Optional[str],
    fail_on_new_critical: bool,
    fail_on_new_high: bool
) -> None:
    """
    Compare two IAM scans and show security changes.
    
    Args:
        baseline: Path to baseline (older) scan JSON
        current: Path to current (newer) scan JSON
        output_format: Output format (table/json/github)
        output_file: Optional file path to save output
        fail_on_new_critical: Exit code 2 if new CRITICAL findings
        fail_on_new_high: Exit code 2 if new HIGH+ findings
    """
    from heimdall.diff_engine import DiffEngine
    
    console.print("[bold cyan]🔄 Comparing IAM Scans...[/bold cyan]\n")
    
    # Load both scans
    with open(baseline, 'r') as f:
        baseline_data = json.load(f)
    
    with open(current, 'r') as f:
        current_data = json.load(f)
    
    # Run diff
    engine = DiffEngine()
    diff_result = engine.compare(baseline_data, current_data)
    
    # Handle output format
    if output_format == 'json':
        _output_json(engine, diff_result, output_file)
    elif output_format == 'github':
        _output_github(engine, diff_result, output_file)
    else:
        _output_table(diff_result)
    
    # CI/CD exit codes
    _handle_exit_codes(diff_result, fail_on_new_critical, fail_on_new_high)


def _output_json(engine, diff_result, output_file: Optional[str]) -> None:
    """Output diff result as JSON."""
    output = engine.format_diff_json(diff_result)
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        console.print(f"[green]✓ JSON saved to:[/green] {output_file}")
    else:
        console.print_json(data=output)


def _output_github(engine, diff_result, output_file: Optional[str]) -> None:
    """Output diff result as GitHub markdown."""
    output = engine.format_diff_github(diff_result)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(output)
        console.print(f"[green]✓ GitHub markdown saved to:[/green] {output_file}")
    else:
        console.print(output)


def _output_table(diff_result) -> None:
    """Output diff result as rich table."""
    # Header
    console.print(f"[bold]Baseline:[/bold] {diff_result.baseline_timestamp}")
    console.print(f"[bold]Current:[/bold] {diff_result.current_timestamp}")
    console.print()
    
    # Risk score
    score_color = "green" if diff_result.score_delta > 0 else "red" if diff_result.score_delta < 0 else "yellow"
    trend = "⬆️ IMPROVED" if diff_result.score_delta > 0 else "⬇️ WORSE" if diff_result.score_delta < 0 else "➡️ NO CHANGE"
    
    console.print(f"[bold]Security Score:[/bold]")
    console.print(f"  Baseline: {diff_result.baseline_score}/100")
    console.print(f"  Current:  {diff_result.current_score}/100")
    console.print(f"  Change:   [{score_color}]{diff_result.score_delta:+d} {trend}[/{score_color}]")
    console.print()
    
    # Summary table
    _print_summary_table(diff_result)
    
    # New findings detail
    _print_new_findings(diff_result)
    
    # Resolved findings
    _print_resolved_findings(diff_result)
    
    # Principal changes
    _print_principal_changes(diff_result)
    
    # Recommendation
    _print_recommendation(diff_result)


def _print_summary_table(diff_result) -> None:
    """Print changes summary table."""
    summary_table = Table(title="📊 Changes Summary", show_header=True, box=None)
    summary_table.add_column("Category", style="cyan")
    summary_table.add_column("New", justify="right", style="red")
    summary_table.add_column("Resolved", justify="right", style="green")
    summary_table.add_column("Unchanged", justify="right", style="dim")
    
    summary_table.add_row(
        "🔴 CRITICAL",
        str(diff_result.new_critical),
        str(diff_result.resolved_critical),
        str(len([f for f in diff_result.unchanged_findings if f.get('severity') == 'CRITICAL']))
    )
    summary_table.add_row(
        "🟠 HIGH",
        str(diff_result.new_high),
        str(diff_result.resolved_high),
        str(len([f for f in diff_result.unchanged_findings if f.get('severity') == 'HIGH']))
    )
    summary_table.add_row(
        "🟡 MEDIUM",
        str(diff_result.new_medium),
        str(diff_result.resolved_medium),
        str(len([f for f in diff_result.unchanged_findings if f.get('severity') == 'MEDIUM']))
    )
    summary_table.add_row(
        "🟢 LOW",
        str(diff_result.new_low),
        str(diff_result.resolved_low),
        str(len([f for f in diff_result.unchanged_findings if f.get('severity') == 'LOW']))
    )
    summary_table.add_row("━━━━━━━━━━", "━━━━", "━━━━━━━━", "━━━━━━━━━")
    summary_table.add_row(
        "Total",
        str(len(diff_result.new_findings)),
        str(len(diff_result.resolved_findings)),
        str(len(diff_result.unchanged_findings)),
        style="bold"
    )
    
    console.print(summary_table)
    console.print()


def _print_new_findings(diff_result) -> None:
    """Print new findings detail."""
    if not diff_result.new_findings:
        return
    
    console.print(f"[bold red]🆕 New Findings ({len(diff_result.new_findings)})[/bold red]")
    
    for i, finding in enumerate(diff_result.new_findings[:10], 1):
        severity = finding.get('severity', 'UNKNOWN')
        severity_icon = SEVERITY_EMOJI.get(severity, '⚪')
        
        principal = finding.get('principal_name', 'Unknown')
        method = finding.get('privesc_method', 'unknown')
        target = finding.get('target_role_name', '')
        
        console.print(f"  {i}. {severity_icon} {severity}: {principal} → {method}")
        if target:
            console.print(f"     [dim]Target: {target}[/dim]")
    
    if len(diff_result.new_findings) > 10:
        console.print(f"\n[dim]  ... and {len(diff_result.new_findings) - 10} more[/dim]")
    console.print()


def _print_resolved_findings(diff_result) -> None:
    """Print resolved findings."""
    if not diff_result.resolved_findings:
        return
    
    console.print(f"[bold green]✅ Resolved Findings ({len(diff_result.resolved_findings)})[/bold green]")
    
    for i, finding in enumerate(diff_result.resolved_findings[:5], 1):
        severity = finding.get('severity', 'UNKNOWN')
        principal = finding.get('principal_name', 'Unknown')
        method = finding.get('privesc_method', 'unknown')
        console.print(f"  {i}. {severity}: {principal} → {method}")
    
    if len(diff_result.resolved_findings) > 5:
        console.print(f"[dim]  ... and {len(diff_result.resolved_findings) - 5} more[/dim]")
    console.print()


def _print_principal_changes(diff_result) -> None:
    """Print principal changes."""
    if not diff_result.new_principals and not diff_result.removed_principals:
        return
    
    console.print(f"[bold]👥 Principal Changes[/bold]")
    if diff_result.new_principals:
        console.print(f"  New: {len(diff_result.new_principals)}")
    if diff_result.removed_principals:
        console.print(f"  Removed: {len(diff_result.removed_principals)}")
    console.print()


def _print_recommendation(diff_result) -> None:
    """Print security recommendation."""
    console.print("[bold]🎯 Recommendation:[/bold]")
    if diff_result.new_critical > 0:
        console.print(f"[red bold]  ❌ BLOCK - {diff_result.new_critical} new CRITICAL findings![/red bold]")
    elif diff_result.new_high > 0:
        console.print(f"[yellow]  ⚠️  REVIEW - {diff_result.new_high} new HIGH findings[/yellow]")
    elif len(diff_result.new_findings) > 0:
        console.print(f"[yellow]  ⚠️  CAUTION - {len(diff_result.new_findings)} new findings[/yellow]")
    else:
        console.print("[green]  ✅ APPROVED - No new security issues[/green]")


def _handle_exit_codes(diff_result, fail_on_new_critical: bool, fail_on_new_high: bool) -> None:
    """Handle CI/CD exit codes."""
    exit_code = 0
    if fail_on_new_critical and diff_result.new_critical > 0:
        console.print("\n[red]Exiting with code 2 (new CRITICAL findings)[/red]")
        exit_code = 2
    elif fail_on_new_high and (diff_result.new_critical > 0 or diff_result.new_high > 0):
        console.print("\n[red]Exiting with code 2 (new HIGH+ findings)[/red]")
        exit_code = 2
    
    if exit_code != 0:
        raise SystemExit(exit_code)
