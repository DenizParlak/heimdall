# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                      TERRAFORM COMMANDS
#              CLI commands for Terraform security analysis
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


@click.group()
def terraform():
    """Terraform security analysis commands."""
    pass


@terraform.command()
@click.argument('plan_file', type=click.Path(exists=True))
@click.option('--quick', '-q', is_flag=True, help='Quick analysis without AWS state')
@click.option('--json', 'json_output', is_flag=True, help='Output as JSON')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'low']), 
              default='critical', help='Exit with error on this severity or higher')
@click.option('--profile', '-p', help='AWS profile to use')
def scan(plan_file: str, quick: bool, json_output: bool, fail_on: str, profile: str):
    """
    Scan a Terraform plan for security issues.
    
    Analyzes the plan to detect privilege escalation paths that would be
    created by the proposed infrastructure changes.
    
    Example:
        heimdall terraform scan terraform.plan.json
        heimdall terraform scan plan.json --quick
        heimdall terraform scan plan.json --fail-on high --json
    """
    from heimdall.terraform.analyzer import TerraformAnalyzer
    
    # Create session
    session = None
    if not quick:
        try:
            import boto3
            if profile:
                session = boto3.Session(profile_name=profile)
            else:
                session = boto3.Session()  # Default credentials
        except Exception as e:
            console.print(f"[yellow]Warning: Could not create AWS session: {e}[/yellow]")
    
    analyzer = TerraformAnalyzer(session)
    
    # Run analysis
    if quick:
        report = analyzer.analyze_plan_quick(plan_file)
    else:
        report = analyzer.analyze_plan(plan_file, fetch_aws_state=session is not None)
    
    # Output
    if json_output:
        click.echo(json.dumps(report.to_dict(), indent=2))
    else:
        mode = "quick (Terraform plan only)" if quick else "full (AWS state + Terraform plan)"
        _display_report(report, plan_file, mode)
    
    # Determine exit code
    severity_order = ['low', 'medium', 'high', 'critical']
    fail_level = severity_order.index(fail_on)
    
    should_fail = False
    if fail_level <= severity_order.index('critical') and report.new_critical_count > 0:
        should_fail = True
    if fail_level <= severity_order.index('high') and report.new_high_count > 0:
        should_fail = True
    
    if should_fail:
        sys.exit(1)


@terraform.command()
@click.argument('plan_file', type=click.Path(exists=True))
@click.option('--format', 'output_format', type=click.Choice(['text', 'json', 'markdown']), 
              default='text', help='Output format')
def report(plan_file: str, output_format: str):
    """
    Generate a detailed security report for a Terraform plan.
    
    Example:
        heimdall terraform report terraform.plan.json
        heimdall terraform report plan.json --format markdown
    """
    from heimdall.terraform.analyzer import TerraformAnalyzer
    
    analyzer = TerraformAnalyzer()
    result = analyzer.analyze_plan(plan_file, fetch_aws_state=False)
    
    if output_format == 'json':
        click.echo(json.dumps(result.to_dict(), indent=2))
    elif output_format == 'markdown':
        _output_markdown(result, plan_file)
    else:
        _display_detailed_report(result)


def _display_report(report, plan_file: str, mode: str = "quick"):
    """Display the analysis report with rich formatting."""
    from collections import Counter
    
    # Header
    console.print()
    console.print(Panel.fit(
        "[bold cyan]🛡️ HEIMDALL TERRAFORM SECURITY ANALYSIS[/bold cyan]",
        border_style="cyan"
    ))
    console.print()
    
    # Plan info
    console.print(f"[dim]Plan: {plan_file}[/dim]")
    console.print(f"[dim]Mode: {mode}[/dim]")
    console.print()
    
    # ════════════════════════════════════════════════════════════════════
    # BEFORE/AFTER COMPARISON
    # ════════════════════════════════════════════════════════════════════
    
    # Create comparison table
    diff_table = Table(
        title="[bold cyan]Security Posture Comparison[/bold cyan]",
        box=box.DOUBLE_EDGE,
        show_header=True,
        header_style="bold white",
        title_style="bold cyan"
    )
    diff_table.add_column("Metric", style="dim", width=25)
    diff_table.add_column("Before", style="cyan", justify="center", width=12)
    diff_table.add_column("After", style="yellow", justify="center", width=12)
    diff_table.add_column("Change", justify="center", width=15)
    
    # Resource counts
    diff_table.add_row(
        "📦 Total Resources",
        "-",
        str(len(report.resource_changes)),
        f"[green]+{len(report.resource_changes)}[/green]"
    )
    diff_table.add_row(
        "🔐 IAM Resources",
        "-",
        str(len(report.iam_changes)),
        f"[{'red' if len(report.iam_changes) > 0 else 'green'}]+{len(report.iam_changes)}[/]"
    )
    diff_table.add_row(
        "💻 Compute Resources",
        "-",
        str(len(report.compute_changes)),
        f"+{len(report.compute_changes)}"
    )
    diff_table.add_row("", "", "", "")  # Separator
    
    # Attack paths - before/after
    before_count = report.before_path_count
    after_count = report.after_path_count
    path_delta = after_count - before_count
    
    delta_str = f"[red]+{path_delta}[/red]" if path_delta > 0 else f"[green]{path_delta}[/green]" if path_delta < 0 else "[dim]0[/dim]"
    
    diff_table.add_row(
        "⚔️ Attack Paths",
        str(before_count),
        str(after_count),
        delta_str
    )
    
    # Risk score
    risk_before = getattr(report, 'risk_score_before', 0)
    risk_after = getattr(report, 'risk_score_after', report.risk_delta)
    risk_delta = report.risk_delta
    
    risk_delta_str = f"[bold red]+{risk_delta}[/bold red]" if risk_delta > 0 else f"[bold green]{risk_delta}[/bold green]" if risk_delta < 0 else "[dim]0[/dim]"
    
    diff_table.add_row(
        "🎯 Risk Score",
        str(risk_before),
        str(risk_after if risk_after else risk_delta),
        risk_delta_str
    )
    
    console.print(diff_table)
    console.print()
    
    # ════════════════════════════════════════════════════════════════════
    # NEW vs REMOVED PATHS DIFF
    # ════════════════════════════════════════════════════════════════════
    
    new_paths = report.new_paths or []
    removed_paths = getattr(report, 'removed_paths', []) or []
    
    if new_paths or removed_paths:
        console.print("[bold cyan]📈 Attack Path Changes[/bold cyan]")
        console.print()
        
        # Categorize new paths
        if new_paths:
            # Group by severity
            critical_paths = [p for p in new_paths if p.get('severity') == 'CRITICAL']
            high_paths = [p for p in new_paths if p.get('severity') == 'HIGH']
            other_paths = [p for p in new_paths if p.get('severity') not in ('CRITICAL', 'HIGH')]
            
            # Critical paths
            if critical_paths:
                console.print(f"  [bold red]🔴 NEW CRITICAL ({len(critical_paths)})[/bold red]")
                for p in critical_paths[:5]:  # Show max 5
                    ptype = p.get('type', 'unknown').replace('_', ' ').title()
                    role = p.get('role', p.get('source_role', p.get('resource', '')))
                    console.print(f"     [red]+ {ptype}[/red] → [dim]{role}[/dim]")
                if len(critical_paths) > 5:
                    console.print(f"     [dim]... and {len(critical_paths) - 5} more[/dim]")
                console.print()
            
            # High paths
            if high_paths:
                console.print(f"  [bold yellow]🟠 NEW HIGH ({len(high_paths)})[/bold yellow]")
                for p in high_paths[:5]:
                    ptype = p.get('type', 'unknown').replace('_', ' ').title()
                    role = p.get('role', p.get('source_role', p.get('resource', '')))
                    console.print(f"     [yellow]+ {ptype}[/yellow] → [dim]{role}[/dim]")
                if len(high_paths) > 5:
                    console.print(f"     [dim]... and {len(high_paths) - 5} more[/dim]")
                console.print()
            
            # Other paths
            if other_paths:
                console.print(f"  [bold blue]🔵 NEW MEDIUM/LOW ({len(other_paths)})[/bold blue]")
                for p in other_paths[:3]:
                    ptype = p.get('type', 'unknown').replace('_', ' ').title()
                    console.print(f"     [blue]+ {ptype}[/blue]")
                if len(other_paths) > 3:
                    console.print(f"     [dim]... and {len(other_paths) - 3} more[/dim]")
                console.print()
        
        # Removed paths (if any)
        if removed_paths:
            console.print(f"  [bold green]✅ REMOVED ({len(removed_paths)})[/bold green]")
            for p in removed_paths[:3]:
                ptype = p.get('type', 'unknown').replace('_', ' ').title()
                console.print(f"     [green]- {ptype}[/green]")
            if len(removed_paths) > 3:
                console.print(f"     [dim]... and {len(removed_paths) - 3} more[/dim]")
            console.print()
    
    # ════════════════════════════════════════════════════════════════════
    # PATTERN SUMMARY
    # ════════════════════════════════════════════════════════════════════
    
    if new_paths:
        type_counts = Counter(p.get('type', 'unknown') for p in new_paths)
        
        console.print("[bold cyan]🔍 Pattern Distribution[/bold cyan]")
        
        pattern_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        pattern_table.add_column("Pattern", style="white", width=35)
        pattern_table.add_column("Count", justify="right", width=5)
        pattern_table.add_column("Bar", width=20)
        
        max_count = max(type_counts.values()) if type_counts else 1
        for ptype, count in sorted(type_counts.items(), key=lambda x: -x[1])[:8]:
            bar_len = int((count / max_count) * 15)
            bar = "█" * bar_len + "░" * (15 - bar_len)
            pattern_table.add_row(
                ptype.replace('_', ' '),
                str(count),
                f"[cyan]{bar}[/cyan]"
            )
        
        console.print(pattern_table)
        console.print()
    
    # ════════════════════════════════════════════════════════════════════
    # BLOCKING ISSUES
    # ════════════════════════════════════════════════════════════════════
    
    if report.blocking_issues:
        console.print(Panel(
            "[bold red]⛔ BLOCKING ISSUES[/bold red]",
            border_style="red",
            expand=False
        ))
        console.print()
        for i, issue in enumerate(report.blocking_issues, 1):
            # Color parentheses for visibility on dark terminals
            colored_issue = issue.replace('(', '[yellow]([/yellow]').replace(')', '[yellow])[/yellow]')
            console.print(f"  [red]{i}.[/red] {colored_issue}")
        console.print()
    
    # ════════════════════════════════════════════════════════════════════
    # RECOMMENDATIONS
    # ════════════════════════════════════════════════════════════════════
    
    if report.recommendations:
        console.print(Panel(
            "[bold yellow]💡 RECOMMENDATIONS[/bold yellow]",
            border_style="yellow",
            expand=False
        ))
        console.print()
        for rec in report.recommendations[:10]:  # Limit to 10
            console.print(f"  [yellow]→[/yellow] {rec}")
        if len(report.recommendations) > 10:
            console.print(f"  [dim]... and {len(report.recommendations) - 10} more recommendations[/dim]")
        console.print()
    
    # ════════════════════════════════════════════════════════════════════
    # FINAL VERDICT
    # ════════════════════════════════════════════════════════════════════
    
    console.print()
    if report.should_block:
        verdict = Text()
        verdict.append("❌ FAILED", style="bold red")
        verdict.append(" - This plan introduces ", style="red")
        verdict.append(f"{report.new_critical_count} critical", style="bold red")
        if report.new_high_count:
            verdict.append(f" and {report.new_high_count} high", style="bold yellow")
        verdict.append(" severity issues", style="red")
        console.print(Panel(verdict, border_style="red"))
    else:
        verdict = Text()
        verdict.append("✅ PASSED", style="bold green")
        verdict.append(" - No critical security issues detected", style="green")
        if report.new_high_count:
            verdict.append(f" ({report.new_high_count} high severity warnings)", style="yellow")
        console.print(Panel(verdict, border_style="green"))


def _display_detailed_report(report):
    """Display detailed report with all findings."""
    _display_report(report, "terraform plan")
    
    console.print()
    console.print("[bold]RESOURCE CHANGES[/bold]")
    console.print()
    
    for change in report.resource_changes:
        style = "red" if change.action.value == "delete" else "green" if change.action.value == "create" else "yellow"
        console.print(f"  [{style}]{change.action.value.upper()}[/{style}] {change.address}")
        
        for imp in change.iam_implications:
            sev_style = "red" if imp.severity == "CRITICAL" else "yellow" if imp.severity == "HIGH" else "dim"
            console.print(f"    [{sev_style}][{imp.severity}][/{sev_style}] {imp.description}")


@terraform.command()
@click.argument('directory', type=click.Path(exists=True))
@click.option('--json', 'json_output', is_flag=True, help='Output as JSON')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'low']),
              default='critical', help='Exit with error on this severity or higher')
def scan_hcl(directory: str, json_output: bool, fail_on: str):
    """
    Scan Terraform .tf files directly (without terraform plan).
    
    This performs static analysis on HCL files to detect security issues.
    Useful for quick checks without running terraform plan.
    
    Example:
        heimdall terraform scan-hcl ./infrastructure
        heimdall terraform scan-hcl ./modules/iam --fail-on high
    """
    try:
        from heimdall.terraform.hcl_parser import HCLParser
    except ImportError:
        console.print("[red]Error: python-hcl2 is required for HCL parsing.[/red]")
        console.print("[dim]Install with: pip install python-hcl2[/dim]")
        sys.exit(1)
    
    parser = HCLParser()
    findings = parser.parse_directory(directory)
    summary = parser.get_summary()
    
    if json_output:
        import json as json_lib
        click.echo(json_lib.dumps({
            "summary": summary,
            "findings": findings,
        }, indent=2))
    else:
        _display_hcl_report(findings, summary, directory)
    
    # Determine exit code
    severity_order = ['low', 'medium', 'high', 'critical']
    fail_level = severity_order.index(fail_on)
    
    should_fail = False
    if fail_level <= severity_order.index('critical') and summary['critical'] > 0:
        should_fail = True
    if fail_level <= severity_order.index('high') and summary['high'] > 0:
        should_fail = True
    if fail_level <= severity_order.index('medium') and summary['medium'] > 0:
        should_fail = True
    
    if should_fail:
        sys.exit(1)


def _display_hcl_report(findings: list, summary: dict, directory: str):
    """Display HCL analysis report."""
    console.print()
    console.print(Panel.fit(
        "[bold cyan]🛡️ HEIMDALL TERRAFORM HCL ANALYSIS[/bold cyan]",
        border_style="cyan"
    ))
    console.print()
    console.print(f"[dim]Directory: {directory}[/dim]")
    console.print()
    
    # Summary
    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2))
    table.add_column("Severity", style="dim")
    table.add_column("Count", style="bold")
    
    if summary['critical'] > 0:
        table.add_row("🔴 CRITICAL", f"[red]{summary['critical']}[/red]")
    if summary['high'] > 0:
        table.add_row("🟠 HIGH", f"[yellow]{summary['high']}[/yellow]")
    if summary['medium'] > 0:
        table.add_row("🟡 MEDIUM", f"[blue]{summary['medium']}[/blue]")
    if summary['info'] > 0:
        table.add_row("⚪ INFO", f"[dim]{summary['info']}[/dim]")
    
    table.add_row("", "")
    table.add_row("Total Findings", str(summary['total']))
    
    console.print(table)
    console.print()
    
    # Critical and High findings
    critical_high = [f for f in findings if f['severity'] in ['CRITICAL', 'HIGH']]
    if critical_high:
        console.print("[bold red]⛔ SECURITY ISSUES[/bold red]")
        console.print()
        for finding in critical_high:
            sev = finding['severity']
            color = "red" if sev == "CRITICAL" else "yellow"
            console.print(f"  [{color}][{sev}][/{color}] {finding['message']}")
            console.print(f"  [dim]Resource: {finding['resource']}[/dim]")
            if 'recommendation' in finding:
                console.print(f"  [cyan]Fix: {finding['recommendation']}[/cyan]")
            console.print()
    
    # Verdict
    if summary['critical'] > 0:
        console.print(Panel(
            "[bold red]❌ FAILED - Critical security issues found[/bold red]",
            border_style="red"
        ))
    elif summary['high'] > 0:
        console.print(Panel(
            "[bold yellow]⚠️ WARNING - High severity issues found[/bold yellow]",
            border_style="yellow"
        ))
    else:
        console.print(Panel(
            "[bold green]✅ PASSED - No critical/high issues[/bold green]",
            border_style="green"
        ))


def _output_markdown(report, plan_file: str):
    """Output report as Markdown (for PR comments)."""
    lines = []
    
    lines.append("## 🛡️ Heimdall Terraform Security Analysis")
    lines.append("")
    
    if report.should_block:
        lines.append("**Status:** ⚠️ **FAILED** - Critical security issues detected")
    else:
        lines.append("**Status:** ✅ **PASSED** - No critical issues")
    
    lines.append("")
    lines.append("### Summary")
    lines.append("")
    lines.append(f"- **Resource Changes:** {len(report.resource_changes)}")
    lines.append(f"- **Attack Paths Before:** {report.before_path_count}")
    lines.append(f"- **Attack Paths After:** {report.after_path_count}")
    lines.append(f"- **Risk Delta:** {report.risk_delta:+d}")
    lines.append("")
    
    if report.new_critical_count > 0 or report.new_high_count > 0:
        lines.append("### ⚠️ New Security Issues")
        lines.append("")
        
        if report.new_critical_count > 0:
            lines.append(f"**🔴 Critical:** {report.new_critical_count}")
        if report.new_high_count > 0:
            lines.append(f"**🟠 High:** {report.new_high_count}")
        lines.append("")
    
    if report.blocking_issues:
        lines.append("### Blocking Issues")
        lines.append("")
        for issue in report.blocking_issues:
            lines.append(f"- ❌ {issue}")
        lines.append("")
    
    if report.recommendations:
        lines.append("### Recommendations")
        lines.append("")
        for rec in report.recommendations:
            lines.append(f"- 💡 {rec}")
        lines.append("")
    
    lines.append("---")
    lines.append("*Analyzed by [Heimdall](https://github.com/h3xitsec/heimdall-iam)*")
    
    click.echo("\n".join(lines))
