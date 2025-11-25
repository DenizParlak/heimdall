# ᛞᚨᛊᚺᛒᛟᚨᚱᛞ • Dashboard - Security Posture Overview
"""
Heimdall Dashboard - One command security overview.

From Himinbjörg, the celestial fortress at Bifröst's edge,
Heimdall surveys all nine realms at once. This dashboard provides
a similar all-seeing view of your AWS security posture.

Usage:
    heimdall dashboard              # Full scan
    heimdall dashboard --profile prod
    heimdall dashboard --quick      # Skip cross-service scan
    heimdall dashboard -o report.json
"""

import click
from typing import Optional
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()


@click.command()
@click.option('--profile', default='default', help='AWS profile name')
@click.option('--region', default=None, help='AWS region')
@click.option('--quick', is_flag=True, help='Quick scan (skip cross-service analysis)')
@click.option('--output', '-o', type=click.Path(), help='Export dashboard to JSON')
def dashboard(profile: str, region: Optional[str], quick: bool, output: Optional[str]):
    """
    🎯 Security Dashboard - Complete posture overview in one command.
    
    Shows:
    - Account summary
    - IAM statistics  
    - Privilege escalation risks
    - Cross-service attack paths
    - Top recommendations
    
    Example:
        heimdall dashboard
        heimdall dashboard --profile prod
        heimdall dashboard --quick
    """
    start_time = datetime.now()
    
    # Header
    console.print()
    console.print(Panel.fit(
        "[bold cyan]🛡️  Heimdall Security Dashboard[/bold cyan]\n"
        "[dim]Complete AWS IAM security posture overview[/dim]",
        border_style="cyan"
    ))
    console.print()
    
    # Initialize results
    results = {
        'account': {},
        'iam_stats': {},
        'privesc_findings': [],
        'cross_service': {},
        'recommendations': []
    }
    
    try:
        # Step 1: AWS Connection & Account Info
        with console.status("[bold green]Connecting to AWS..."):
            import boto3
            session = boto3.Session(profile_name=profile, region_name=region)
            sts = session.client('sts')
            
            identity = sts.get_caller_identity()
            results['account'] = {
                'account_id': identity['Account'],
                'user_arn': identity['Arn'],
                'user_id': identity['UserId'],
                'region': session.region_name or 'us-east-1',
                'profile': profile
            }
        
        _print_account_box(results['account'])
        
        # Step 2: IAM Scan
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Scanning IAM...", total=None)
            
            from heimdall.iam.scanner import IAMScanner
            scanner = IAMScanner(profile_name=profile, region_name=region)
            
            progress.update(task, description="Scanning IAM roles...")
            roles = scanner.scan_roles()
            
            progress.update(task, description="Scanning IAM users...")
            users = scanner.scan_users()
            
            results['iam_stats'] = {
                'roles': len(roles),
                'users': len(users),
                'roles_data': roles,
                'users_data': users
            }
        
        _print_iam_stats(results['iam_stats'])
        
        # Step 3: Privilege Escalation Analysis
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Analyzing privilege escalation...", total=None)
            
            from heimdall.graph.permission_analyzer import PermissionAnalyzer
            analyzer = PermissionAnalyzer(roles, users, iam_client=scanner.iam)
            findings = analyzer.detect_direct_privesc()
            
            results['privesc_findings'] = findings
        
        _print_privesc_summary(results['privesc_findings'])
        
        # Step 4: Cross-Service Analysis (unless --quick)
        if not quick:
            console.print()
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("Analyzing cross-service risks...", total=None)
                
                try:
                    from heimdall.cross_service.scanner import CrossServiceScanner, ScanConfig
                    from heimdall.cross_service.models import ServiceType
                    
                    # CrossServiceScanner needs session, not profile_name
                    cs_scanner = CrossServiceScanner(
                        session=session,
                        account_id=results['account']['account_id'],
                        region=session.region_name or 'us-east-1'
                    )
                    
                    progress.update(task, description="Scanning S3, Lambda, EC2...")
                    # Create config with specific services
                    scan_config = ScanConfig(
                        services=[ServiceType.S3, ServiceType.LAMBDA, ServiceType.EC2, 
                                  ServiceType.SECRETS_MANAGER, ServiceType.KMS],
                        regions=[session.region_name or 'us-east-1']
                    )
                    cs_result = cs_scanner.scan(config=scan_config)
                    
                    results['cross_service'] = {
                        'chains': len(cs_result.chains),
                        'findings': len(cs_result.findings),
                        'services_scanned': cs_result.services_scanned,
                        'severity_summary': cs_result.severity_summary
                    }
                except Exception as e:
                    results['cross_service'] = {'error': str(e)}
            
            _print_cross_service_summary(results.get('cross_service', {}))
        
        # Step 5: Top Recommendations
        console.print()
        recommendations = _generate_recommendations(results)
        results['recommendations'] = recommendations
        _print_recommendations(recommendations)
        
        # Summary Footer
        duration = (datetime.now() - start_time).total_seconds()
        _print_summary_footer(results, duration, quick)
        
        # Export if requested
        if output:
            import json
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': duration,
                'account': results['account'],
                'iam_stats': {
                    'roles': results['iam_stats']['roles'],
                    'users': results['iam_stats']['users']
                },
                'privesc_summary': {
                    'total': len(results['privesc_findings']),
                    'critical': sum(1 for f in results['privesc_findings'] if f.get('severity') == 'CRITICAL'),
                    'high': sum(1 for f in results['privesc_findings'] if f.get('severity') == 'HIGH'),
                },
                'cross_service': results.get('cross_service', {}),
                'recommendations': recommendations
            }
            with open(output, 'w') as f:
                json.dump(export_data, f, indent=2)
            console.print(f"\n[dim]Dashboard exported to {output}[/dim]")
        
    except Exception as e:
        console.print(f"\n[red]❌ Error: {e}[/red]")
        raise click.ClickException(str(e))


def _print_account_box(account: dict):
    """Print account info box."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Account ID", f"[bold]{account['account_id']}[/bold]")
    table.add_row("Region", account['region'])
    table.add_row("Profile", account['profile'])
    table.add_row("Identity", account['user_arn'].split('/')[-1] if '/' in account['user_arn'] else account['user_arn'])
    
    console.print(Panel(table, title="☁️  AWS Account", border_style="blue"))


def _print_iam_stats(stats: dict):
    """Print IAM statistics."""
    # Count special principals
    roles = stats.get('roles_data', [])
    users = stats.get('users_data', [])
    
    admin_roles = sum(1 for r in roles if 'admin' in r.get('name', '').lower())
    service_roles = sum(1 for r in roles if r.get('path', '').startswith('/service-role/'))
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="cyan", width=25)
    table.add_column("Count", style="bold white", justify="right", width=8)
    table.add_column("", width=20)
    
    table.add_row("🎭 IAM Roles", str(stats['roles']), f"[dim]({admin_roles} admin-like)[/dim]")
    table.add_row("👤 IAM Users", str(stats['users']), "")
    table.add_row("⚙️  Service Roles", str(service_roles), "")
    
    console.print(Panel(table, title="👥 IAM Statistics", border_style="green"))


def _print_privesc_summary(findings: list):
    """Print privilege escalation summary."""
    critical = [f for f in findings if f.get('severity') == 'CRITICAL']
    high = [f for f in findings if f.get('severity') == 'HIGH']
    medium = [f for f in findings if f.get('severity') == 'MEDIUM']
    low = [f for f in findings if f.get('severity') == 'LOW']
    
    # Severity bars
    total = len(findings) or 1
    
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Sev", width=20)
    table.add_column("Count", width=8, justify="right")
    table.add_column("Bar", width=26)
    
    def make_bar(count, color):
        pct = int((count / total) * 25)
        # Ensure at least 1 bar if count > 0
        if count > 0 and pct == 0:
            pct = 1
        return f"[{color}]{'█' * pct}[/{color}][dim]{'░' * (25 - pct)}[/dim]"
    
    table.add_row("🔴 CRITICAL", str(len(critical)), make_bar(len(critical), "red"))
    table.add_row("🟠 HIGH", str(len(high)), make_bar(len(high), "orange1"))
    table.add_row("🟡 MEDIUM", str(len(medium)), make_bar(len(medium), "yellow"))
    table.add_row("🟢 LOW", str(len(low)), make_bar(len(low), "green"))
    
    # Top methods
    method_counts = {}
    for f in findings:
        m = f.get('privesc_method', 'unknown')
        method_counts[m] = method_counts.get(m, 0) + 1
    
    top_methods = sorted(method_counts.items(), key=lambda x: -x[1])[:3]
    
    if top_methods:
        table.add_row("", "", "")
        table.add_row("[dim]Top Methods:[/dim]", "", "")
        for method, count in top_methods:
            # Show method name truncated to fit column
            table.add_row(f"  • {method[:18]}", str(count), "")
    
    title = f"⚠️  Privilege Escalation ({len(findings)} total)"
    border_color = "red" if critical else ("orange1" if high else "yellow")
    console.print(Panel(table, title=title, border_style=border_color))


def _print_cross_service_summary(cs_data: dict):
    """Print cross-service analysis summary."""
    if cs_data.get('error'):
        console.print(Panel(
            f"[yellow]⚠️  Cross-service scan skipped: {cs_data['error'][:50]}[/yellow]",
            title="🔗 Cross-Service Analysis",
            border_style="yellow"
        ))
        return
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="cyan", width=25)
    table.add_column("Value", style="bold white", width=10)
    
    table.add_row("🔗 Attack Chains", str(cs_data.get('chains', 0)))
    table.add_row("🎯 Findings", str(cs_data.get('findings', 0)))
    table.add_row("📦 Services Scanned", str(len(cs_data.get('services_scanned', []))))
    
    severity = cs_data.get('severity_summary', {})
    if severity:
        table.add_row("", "")
        # Keys are uppercase: CRITICAL, HIGH, etc.
        table.add_row("🔴 Critical Chains", str(severity.get('CRITICAL', severity.get('critical', 0))))
        table.add_row("🟠 High Chains", str(severity.get('HIGH', severity.get('high', 0))))
    
    console.print(Panel(table, title="🔗 Cross-Service Analysis", border_style="magenta"))


def _generate_recommendations(results: dict) -> list:
    """Generate actionable recommendations."""
    recommendations = []
    
    findings = results.get('privesc_findings', [])
    critical = [f for f in findings if f.get('severity') == 'CRITICAL']
    high = [f for f in findings if f.get('severity') == 'HIGH']
    
    # Critical findings
    if critical:
        methods = set(f.get('privesc_method', '') for f in critical[:5])
        recommendations.append({
            'priority': 'CRITICAL',
            'title': f'{len(critical)} Critical Privilege Escalation Paths',
            'description': f"Top methods: {', '.join(list(methods)[:3])}",
            'action': 'Review and restrict permissions immediately'
        })
    
    # High findings
    if high:
        recommendations.append({
            'priority': 'HIGH',
            'title': f'{len(high)} High-Risk Escalation Paths',
            'description': 'Principals can escalate privileges through policy manipulation',
            'action': 'Implement least-privilege policies'
        })
    
    # IAM stats based
    iam_stats = results.get('iam_stats', {})
    if iam_stats.get('users', 0) > 10:
        recommendations.append({
            'priority': 'MEDIUM',
            'title': 'Consider reducing IAM users',
            'description': f"{iam_stats['users']} IAM users found - prefer roles for applications",
            'action': 'Migrate to IAM roles where possible'
        })
    
    # Cross-service
    cs = results.get('cross_service', {})
    if cs.get('chains', 0) > 50:
        recommendations.append({
            'priority': 'HIGH',
            'title': 'High cross-service risk exposure',
            'description': f"{cs['chains']} attack chains detected across services",
            'action': 'Run: heimdall iam cross-service --compact'
        })
    
    # Default recommendation
    if not recommendations:
        recommendations.append({
            'priority': 'INFO',
            'title': 'Good security posture',
            'description': 'No critical issues detected',
            'action': 'Continue monitoring with regular scans'
        })
    
    return recommendations


def _print_recommendations(recommendations: list):
    """Print recommendations."""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("", width=55)
    
    priority_icons = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢',
        'INFO': '💡'
    }
    
    for rec in recommendations[:5]:
        icon = priority_icons.get(rec['priority'], '•')
        table.add_row(f"{icon} [bold]{rec['title']}[/bold]")
        table.add_row(f"   [dim]{rec['description']}[/dim]")
        table.add_row(f"   [cyan]→ {rec['action']}[/cyan]")
        table.add_row("")
    
    console.print(Panel(table, title="💡 Recommendations", border_style="cyan"))


def _print_summary_footer(results: dict, duration: float, quick: bool):
    """Print summary footer."""
    findings = results.get('privesc_findings', [])
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    
    # Risk score (simple calculation)
    risk_score = min(100, critical * 20 + high * 5 + len(findings))
    
    if risk_score >= 80:
        risk_label = "[red bold]HIGH RISK[/red bold]"
        risk_bar = "[red]" + "█" * 10 + "[/red]"
    elif risk_score >= 40:
        risk_label = "[yellow bold]MEDIUM RISK[/yellow bold]"
        risk_bar = "[yellow]" + "█" * int(risk_score / 10) + "[/yellow]" + "[dim]" + "░" * (10 - int(risk_score / 10)) + "[/dim]"
    else:
        risk_label = "[green bold]LOW RISK[/green bold]"
        risk_bar = "[green]" + "█" * int(risk_score / 10) + "[/green]" + "[dim]" + "░" * (10 - int(risk_score / 10)) + "[/dim]"
    
    console.print()
    console.print("─" * 60)
    console.print(f"  Risk Score: {risk_bar} {risk_label} ({risk_score}/100)")
    console.print(f"  Scan Duration: {duration:.1f}s {'[dim](quick mode)[/dim]' if quick else ''}")
    console.print("─" * 60)
    console.print()
    console.print("[dim]Next steps:[/dim]")
    console.print("  [cyan]heimdall iam detect-privesc[/cyan]     Full analysis")
    console.print("  [cyan]heimdall iam cross-service[/cyan]      Cross-service chains")
    console.print("  [cyan]heimdall iam tui[/cyan]                Interactive explorer")
