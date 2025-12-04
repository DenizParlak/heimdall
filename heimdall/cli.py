# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                              ᛒᛁᚠᚱᛟᛊᛏ • BIFRÖST
#                     The Rainbow Bridge Between Realms
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "From Himinbjörg, where Heimdall dwells, the guardian of the gods
#    watches over the burning rainbow bridge that connects all realms."
#
#   This is the main gateway - the Bifröst that connects mortals to
#   the Nine Realms of Heimdall's powers. All commands flow through
#   this sacred bridge, watched eternally by the Gjallarhorn's keeper.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List, Union, Callable
import json
import csv
from functools import wraps

import click
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.tree import Tree

from heimdall import __version__
from heimdall.iam.scanner import IAMScanner
from heimdall.graph.builder import GraphBuilder
from heimdall.graph.analyzer import PathAnalyzer
from heimdall.graph.permission_analyzer import PermissionAnalyzer

# ᚱᚢᚾᛖᛊ • Runic Imports from the Sacred Scrolls
from heimdall.cli_utils import (
    # Type aliases
    GraphData, Finding, PathInfo,
    # Constants
    DEFAULT_OUTPUT_FILE, DEFAULT_PRIVESC_OUTPUT, DEFAULT_MAX_DEPTH,
    DEFAULT_TABLE_LIMIT, SCAN_TIMEOUT_SECONDS,
    SEVERITY_ORDER, SEVERITY_COLORS, SEVERITY_EMOJI,
    # Console
    console, set_console_theme,
    # Helper functions
    truncate, get_severity_color, get_severity_emoji,
    format_severity, load_graph_file, extract_graph_data,
    # Banner
    print_banner, print_version_info, HEIMDALL_BANNER,
)

# ᛗᛁᛗᛁᚱ • Mimir's Well of Wisdom - Logger
logger = logging.getLogger(__name__)

# ᚺᛚᛁᛞᛊᚲᛃᚨᛚᚠ • Hlidskjalf - Odin's Throne (Optional Sight)
try:
    from heimdall.pr_simulator.cli import pr_simulate
    PR_SIMULATOR_AVAILABLE = True
except ImportError:
    PR_SIMULATOR_AVAILABLE = False


@click.group(invoke_without_command=True)
@click.option('--version', '-v', is_flag=True, help='Show version and exit')
@click.pass_context
def main(ctx, version):
    """
    ⚔️  HEIMDALL - AWS IAM Attack Path Finder
    
    The Bifröst Guardian watches over your AWS realm, detecting privilege
    escalation paths before attackers can exploit them.
    
    \b
    Quick Start:
      heimdall iam scan                    # Scan your AWS account
      heimdall iam detect-privesc          # Find privilege escalation paths
      heimdall iam attack-chain            # Analyze attack chains
      heimdall iam summary -g scan.json    # View security summary
    
    \b
    Documentation:
      https://github.com/DenizParlak/Heimdall
    """
    if version:
        print_version_info()
        ctx.exit(0)
    elif ctx.invoked_subcommand is None:
        print_banner()
        console.print()
        console.print("[bold bright_white]Usage:[/bold bright_white] heimdall [grey50][[/grey50][cyan]OPTIONS[/cyan][grey50]][/grey50] COMMAND [grey50][[/grey50][cyan]ARGS[/cyan][grey50]][/grey50]...")
        console.print()
        console.print("[bold cyan]Core Commands:[/bold cyan]")
        console.print("  [cyan]iam[/cyan]                   IAM security analysis")
        console.print("  [grey50]├──[/grey50] [bright_white]scan[/bright_white]              Scan AWS account, build trust graph")
        console.print("  [grey50]│[/grey50]   [grey50]--profile, --region, --output[/grey50]")
        console.print("  [grey50]├──[/grey50] [bright_white]detect-privesc[/bright_white]    Find privilege escalation paths")
        console.print("  [grey50]│[/grey50]   [grey50]--graph, --severity, --include-indirect[/grey50]")
        console.print("  [grey50]├──[/grey50] [bright_white]attack-chain[/bright_white]      Analyze multi-step attack chains")
        console.print("  [grey50]│[/grey50]   [grey50]--graph, --from, --format, --top, --steps[/grey50]")
        console.print("  [grey50]├──[/grey50] [bright_white]cross-service[/bright_white]     Cross-service escalation [grey50]([/grey50][cyan]10 services[/cyan][grey50])[/grey50]")
        console.print("  [grey50]│[/grey50]   [grey50]--services, --principal, --compact, --output[/grey50]")
        console.print("  [grey50]├──[/grey50] [bright_white]risks[/bright_white]             Show risky escalation paths")
        console.print("  [grey50]├──[/grey50] [bright_white]summary[/bright_white]           Quick security posture overview")
        console.print("  [grey50]├──[/grey50] [bright_white]report[/bright_white]            Generate HTML report")
        console.print("  [grey50]├──[/grey50] [bright_white]analyze[/bright_white]           AI-powered analysis")
        console.print("  [grey50]└──[/grey50] [bright_white]tui[/bright_white]               Interactive Terminal UI")
        console.print()
        console.print("  [cyan]aws[/cyan]                   AWS utilities")
        console.print("  [grey50]└──[/grey50] [bright_white]profiles[/bright_white]          List configured AWS profiles")
        console.print()
        console.print("[bold cyan]Quick Start:[/bold cyan]")
        console.print("  [cyan]dashboard[/cyan]             🎯 Security posture overview [bold](NEW)[/bold]")
        console.print("  [grey50]│[/grey50]   [grey50]--quick, --profile, --output[/grey50]")
        console.print()
        console.print("[bold cyan]Setup & Info:[/bold cyan]")
        console.print("  [cyan]quickstart[/cyan]            Interactive guide for new users")
        console.print("  [cyan]doctor[/cyan]                Check system health and dependencies")
        console.print("  [cyan]version[/cyan]               Show version and system information")
        console.print("  [cyan]completion[/cyan]            Generate shell completion scripts")
        console.print()
        console.print("[grey50]Run 'heimdall COMMAND --help' for more information[/grey50]")
        console.print("[grey50]Run 'heimdall quickstart' for a guided tour[/grey50]")


@main.command()
def version():
    """Show detailed version and system information."""
    print_version_info()


@main.command()
def quickstart():
    """
    Interactive quick start guide for new users.
    
    Walks through the basic setup and first scan.
    """
    from rich.panel import Panel
    from rich.markdown import Markdown
    
    console.print()
    print_banner(small=True)
    console.print()
    
    console.print(Panel.fit(
        "[bold cyan]Welcome to Heimdall! 🛡️[/bold cyan]\n\n"
        "Let's get you started with AWS IAM security analysis.",
        title="⚔️ Quick Start Guide",
        border_style="cyan"
    ))
    console.print()
    
    # Step 1: Check AWS
    console.print("[bold cyan]Step 1: AWS Configuration[/bold cyan]")
    console.print("━" * 50)
    
    try:
        import boto3
        session = boto3.Session()
        creds = session.get_credentials()
        if creds:
            console.print("[green]✓[/green] AWS credentials found!")
            if session.region_name:
                console.print(f"[green]✓[/green] Region: {session.region_name}")
            console.print()
        else:
            console.print("[yellow]⚠[/yellow] No AWS credentials found.")
            console.print()
            console.print("To configure AWS credentials, run:")
            console.print("  [cyan]aws configure[/cyan]")
            console.print()
            console.print("Or set environment variables:")
            console.print("  [cyan]export AWS_ACCESS_KEY_ID=AKIA...[/cyan]")
            console.print("  [cyan]export AWS_SECRET_ACCESS_KEY=...[/cyan]")
            console.print("  [cyan]export AWS_DEFAULT_REGION=us-east-1[/cyan]")
            console.print()
            return
    except Exception as e:
        console.print(f"[red]✗[/red] Error checking AWS: {e}")
        return
    
    # Step 2: Basic commands
    console.print("[bold cyan]Step 2: Essential Commands[/bold cyan]")
    console.print("━" * 50)
    console.print()
    
    commands = [
        ("heimdall iam scan", "Scan your AWS account and build trust graph"),
        ("heimdall iam detect-privesc", "Find privilege escalation paths"),
        ("heimdall iam attack-chain", "Analyze multi-step attack chains"),
        ("heimdall iam summary -g scan.json", "View security summary"),
        ("heimdall iam report -g scan.json", "Generate HTML report"),
    ]
    
    for cmd, desc in commands:
        console.print(f"  [cyan]{cmd}[/cyan]")
        console.print(f"  [dim]{desc}[/dim]")
        console.print()
    
    # Step 3: First scan
    console.print("[bold cyan]Step 3: Run Your First Scan[/bold cyan]")
    console.print("━" * 50)
    console.print()
    console.print("Ready to scan? Run this command:")
    console.print()
    console.print("  [bold cyan]heimdall iam detect-privesc --output scan.json[/bold cyan]")
    console.print()
    console.print("This will:")
    console.print("  • Enumerate IAM users, roles, groups, and policies")
    console.print("  • Build a trust relationship graph")
    console.print("  • Detect 85+ privilege escalation patterns")
    console.print("  • Save results to scan.json")
    console.print()
    
    # Tips
    console.print("[bold cyan]💡 Pro Tips[/bold cyan]")
    console.print("━" * 50)
    console.print()
    console.print("  • Use [cyan]--profile[/cyan] to scan different AWS accounts")
    console.print("  • Use [cyan]heimdall iam tui[/cyan] for interactive exploration")
    console.print("  • Use [cyan]heimdall iam analyze[/cyan] for AI-powered insights")
    console.print("  • Run [cyan]heimdall doctor[/cyan] to check system health")
    console.print()
    
    console.print(Panel.fit(
        "Need help? Visit: [link]https://github.com/DenizParlak/Heimdall[/link]",
        border_style="dim"
    ))


@main.command()
@click.option('--shell', type=click.Choice(['bash', 'zsh', 'fish']), help='Shell type')
@click.option('--install', is_flag=True, help='Install completion to shell config')
def completion(shell, install):
    """
    Generate shell completion scripts.
    
    \b
    Usage:
      heimdall completion --shell bash          # Print bash completion
      heimdall completion --shell zsh           # Print zsh completion
      heimdall completion --shell bash --install  # Auto-install for bash
    
    \b
    Manual Installation:
      # Bash (~/.bashrc)
      eval "$(heimdall completion --shell bash)"
      
      # Zsh (~/.zshrc)
      eval "$(heimdall completion --shell zsh)"
      
      # Fish (~/.config/fish/completions/heimdall.fish)
      heimdall completion --shell fish > ~/.config/fish/completions/heimdall.fish
    """
    import os
    from pathlib import Path
    
    if not shell:
        console.print("[yellow]Please specify a shell: --shell bash|zsh|fish[/yellow]")
        console.print()
        console.print("Examples:")
        console.print("  heimdall completion --shell bash")
        console.print("  heimdall completion --shell zsh --install")
        return
    
    # Generate completion script
    import subprocess
    env = os.environ.copy()
    env['_HEIMDALL_COMPLETE'] = f'{shell}_source'
    
    try:
        result = subprocess.run(
            ['heimdall'],
            env=env,
            capture_output=True,
            text=True
        )
        completion_script = result.stdout
    except Exception as e:
        console.print(f"[red]Error generating completion: {e}[/red]")
        return
    
    if install:
        home = Path.home()
        
        if shell == 'bash':
            rc_file = home / '.bashrc'
            line = 'eval "$(heimdall completion --shell bash)"'
        elif shell == 'zsh':
            rc_file = home / '.zshrc'
            line = 'eval "$(heimdall completion --shell zsh)"'
        elif shell == 'fish':
            fish_dir = home / '.config' / 'fish' / 'completions'
            fish_dir.mkdir(parents=True, exist_ok=True)
            fish_file = fish_dir / 'heimdall.fish'
            fish_file.write_text(completion_script)
            console.print(f"[green]✓[/green] Completion installed to {fish_file}")
            console.print("[dim]Restart your shell or run: source ~/.config/fish/config.fish[/dim]")
            return
        
        # Check if already installed
        if rc_file.exists():
            content = rc_file.read_text()
            if 'heimdall completion' in content:
                console.print(f"[yellow]⚠[/yellow] Completion already in {rc_file}")
                return
        
        # Append to rc file
        with open(rc_file, 'a') as f:
            f.write(f'\n# Heimdall CLI completion\n{line}\n')
        
        console.print(f"[green]✓[/green] Completion installed to {rc_file}")
        console.print(f"[dim]Restart your shell or run: source {rc_file}[/dim]")
    else:
        # Just print the script
        click.echo(completion_script)


@main.command()
def doctor():
    """
    Check system health and dependencies.
    
    Verifies that all required components are properly configured:
    - Python version compatibility
    - AWS credentials and configuration
    - Required Python packages
    - Optional AI/LLM providers
    """
    import platform
    import sys
    
    console.print()
    print_banner(small=True)
    console.print()
    console.print("[bold cyan]🏥 System Health Check[/bold cyan]")
    console.print("━" * 50)
    
    all_ok = True
    
    # Python version
    py_version = sys.version_info
    if py_version >= (3, 9):
        console.print(f"[green]✓ Python {py_version.major}.{py_version.minor}.{py_version.micro}[/green]")
    else:
        console.print(f"[red]✗ Python {py_version.major}.{py_version.minor} (requires 3.9+)[/red]")
        all_ok = False
    
    # Platform
    console.print(f"[green]✓ Platform: {platform.system()} {platform.release()}[/green]")
    
    # Required packages
    console.print()
    console.print("[bold cyan]📦 Required Packages[/bold cyan]")
    console.print("━" * 50)
    
    required_packages = [
        ('boto3', 'AWS SDK'),
        ('click', 'CLI Framework'),
        ('rich', 'Terminal UI'),
    ]
    
    for package, desc in required_packages:
        try:
            mod = __import__(package)
            ver = getattr(mod, '__version__', 'installed')
            console.print(f"[green]✓ {package} ({ver}) - {desc}[/green]")
        except ImportError:
            console.print(f"[red]✗ {package} - {desc} NOT INSTALLED[/red]")
            all_ok = False
    
    # Optional packages
    console.print()
    console.print("[bold cyan]🔌 Optional Packages[/bold cyan]")
    console.print("━" * 50)
    
    optional_packages = [
        ('openai', 'OpenAI LLM Provider'),
        ('anthropic', 'Anthropic Claude Provider'),
        ('ollama', 'Local LLM Provider'),
        ('textual', 'TUI Framework'),
    ]
    
    for package, desc in optional_packages:
        try:
            mod = __import__(package)
            ver = getattr(mod, '__version__', 'installed')
            console.print(f"[green]✓ {package} ({ver}) - {desc}[/green]")
        except ImportError:
            console.print(f"[yellow]○ {package} - {desc} not installed[/yellow]")
    
    # AWS Configuration
    console.print()
    console.print("[bold cyan]☁️  AWS Configuration[/bold cyan]")
    console.print("━" * 50)
    
    try:
        import boto3
        session = boto3.Session()
        
        # Check credentials
        creds = session.get_credentials()
        if creds:
            console.print("[green]✓ AWS credentials configured[/green]")
            if hasattr(creds, 'access_key') and creds.access_key:
                masked_key = creds.access_key[:4] + '*' * 12 + creds.access_key[-4:]
                console.print(f"  [dim]Access Key: {masked_key}[/dim]")
        else:
            console.print("[yellow]⚠ No AWS credentials found[/yellow]")
            console.print("  [dim]Run 'aws configure' or set AWS_ACCESS_KEY_ID[/dim]")
            all_ok = False
        
        # Check default region
        region = session.region_name
        if region:
            console.print(f"[green]✓ Default region: {region}[/green]")
        else:
            console.print("[yellow]⚠ No default region set[/yellow]")
            console.print("  [dim]Run 'aws configure' or set AWS_DEFAULT_REGION[/dim]")
        
        # List profiles
        from heimdall.aws_utils import get_aws_profiles
        profiles = get_aws_profiles()
        if profiles:
            console.print(f"[green]✓ {len(profiles)} AWS profile(s) available[/green]")
        
    except Exception as e:
        console.print(f"[red]✗ AWS SDK error: {e}[/red]")
        all_ok = False
    
    # Summary
    console.print()
    console.print("━" * 50)
    if all_ok:
        console.print("[bold green]✓ All checks passed! Heimdall is ready.[/bold green]")
    else:
        console.print("[bold yellow]⚠ Some issues found. See above for details.[/bold yellow]")
    console.print()


@main.group(invoke_without_command=True)
@click.pass_context
def iam(ctx):
    """
    IAM security analysis commands.
    
    \b
    🔍 Discovery:
      scan            Scan AWS account and build trust graph
      detect-privesc  Find privilege escalation paths
    
    \b
    📊 Analysis:
      attack-chain    Analyze multi-step attack chains
      cross-service   Cross-service escalation (10 AWS services)
      risks           Show risky escalation paths
      path            Find path between principals
      list-paths      List all assume-role paths
    
    \b
    📋 Reporting:
      summary         Quick security posture overview
      show-principal  Deep dive into a principal
      report          Generate HTML report
      diff            Compare two scans
    
    \b
    🤖 AI-Powered:
      analyze         AI analysis of findings
      ask             Natural language queries
      simulate-attack Realistic attack simulation
    
    \b
    🖥️  Interactive:
      tui             Launch Terminal UI
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.group()
def aws():
    """AWS configuration and utility commands."""
    pass


@aws.command()
def profiles():
    """
    List available AWS profiles from ~/.aws/credentials and ~/.aws/config
    
    Shows all configured AWS profiles with their regions (if configured).
    Helps identify which profile to use with --profile flag.
    
    Example:
        heimdall aws profiles
    """
    from heimdall.aws_utils import get_aws_profiles
    
    profiles_list = get_aws_profiles()
    
    if not profiles_list:
        console.print("[yellow]⚠️  No AWS profiles found[/yellow]")
        console.print("\n[dim]Configure AWS credentials:[/dim]")
        console.print("  aws configure")
        console.print("  [dim]or manually edit ~/.aws/credentials[/dim]")
        return
    
    console.print(f"\n[bold cyan]📋 Available AWS Profiles:[/bold cyan] [dim]({len(profiles_list)} found)[/dim]\n")
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Profile", style="green")
    table.add_column("Region", style="yellow")
    table.add_column("Status", style="dim")
    
    for profile in profiles_list:
        region = profile.get('region') or '[dim]not configured[/dim]'
        status = "✓ default" if profile['name'] == 'default' else ""
        table.add_row(profile['name'], region, status)
    
    console.print(table)
    console.print("\n[dim]💡 Usage:[/dim] heimdall iam scan --profile <name>")
    console.print()


@iam.command()
@click.option(
    '--profile',
    default='default',
    help='AWS profile name to use'
)
@click.option(
    '--region',
    default=None,
    help='AWS region - only used for future resource enrichment (IAM is global)'
)
@click.option(
    '--output',
    default=DEFAULT_OUTPUT_FILE,
    help='Output file for graph data'
)
@click.option(
    '--summary',
    is_flag=True,
    help='Show only summary statistics'
)
@click.option(
    '--fail-on-critical',
    is_flag=True,
    help='Exit with code 2 if critical risks found (useful for CI/CD)'
)
@click.option(
    '--no-color',
    is_flag=True,
    help='Disable colored output (useful for CI/CD logs)'
)
@click.option(
    '--progress',
    is_flag=True,
    help='Show detailed progress bar instead of spinner'
)
def scan(
    profile: str,
    region: Optional[str],
    output: str,
    summary: bool,
    fail_on_critical: bool,
    no_color: bool,
    progress: bool
) -> None:
    """
    Scan AWS IAM and build assume-role graph.
    
    Retrieves IAM principals, builds a trust graph, and analyzes it for
    privilege escalation paths.
    
    Args:
        profile: AWS CLI profile name
        region: AWS region name (optional)
        output: Path to output JSON file
        summary: If True, show only summary stats
        fail_on_critical: If True, exit with code 2 on critical findings
        no_color: If True, disable colored output
        progress: If True, show detailed progress bar
    """
    # Apply theme settings
    set_console_theme(no_color=no_color)
    
    logger.info("Starting IAM scan: profile=%s, region=%s, output=%s", profile, region, output)
    console.print("\n[bold cyan]🔍 Heimdall IAM Scanner[/bold cyan]\n")
    
    # Warn if region is specified (IAM is global)
    if region:
        console.print("[yellow]⚠️  IAM is a global service. Region parameter is ignored for IAM scanning.[/yellow]")
        console.print("[dim]💡 Region only affects resource enrichment (EC2, Lambda, RDS in detect-privesc)[/dim]\n")
    
    # Smart profile selection
    from heimdall.aws_utils import profile_exists, get_default_profile
    
    if profile == 'default' and not profile_exists('default'):
        # User didn't specify profile and default doesn't exist
        fallback_profile = get_default_profile()
        if fallback_profile and fallback_profile != 'default':
            console.print(f"[yellow]⚠️  'default' profile not found. Using '{fallback_profile}' instead.[/yellow]")
            console.print(f"[dim]💡 Tip: Specify profile with --profile {fallback_profile}[/dim]\n")
            profile = fallback_profile
        elif not fallback_profile:
            console.print("[red]✗ No AWS profiles found![/red]")
            console.print("\n[dim]Configure AWS credentials:[/dim]")
            console.print("  aws configure")
            console.print("  [dim]or run: heimdall aws profiles[/dim]\n")
            sys.exit(1)
    elif not profile_exists(profile):
        console.print(f"[red]✗ Profile '{profile}' not found![/red]")
        console.print("\n[dim]Available profiles:[/dim]")
        console.print("  heimdall aws profiles\n")
        sys.exit(1)
    
    try:
        # Initialize scanner
        console.print(f"[dim]Using AWS profile:[/dim] {profile}")
        logger.debug("Initializing IAMScanner with profile=%s", profile)
        scanner = IAMScanner(profile_name=profile, region_name=region)
        logger.info("Scanner initialized for account %s", scanner.account_id)
        
        # Use progress bar if requested, otherwise use spinner
        if progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress_bar:
                # Scan IAM roles
                task1 = progress_bar.add_task("[cyan]Scanning IAM roles...", total=100)
                roles = scanner.scan_roles()
                progress_bar.update(task1, completed=100)
                console.print(f"[green]✓[/green] Scanned {len(roles)} IAM roles")
                
                # Scan IAM users
                task2 = progress_bar.add_task("[cyan]Scanning IAM users...", total=100)
                users = scanner.scan_users()
                progress_bar.update(task2, completed=100)
                console.print(f"[green]✓[/green] Scanned {len(users)} IAM users")
                
                # Build graph
                task3 = progress_bar.add_task("[cyan]Building assume-role graph...", total=100)
                builder = GraphBuilder()
                graph = builder.build_from_principals(roles, users)
                progress_bar.update(task3, completed=100)
                console.print(f"[green]✓[/green] Found {graph['stats']['edge_count']} assume-role relationships")
                
                # Analyze for risky paths
                task4 = progress_bar.add_task("[cyan]Analyzing privilege escalation paths...", total=100)
                analyzer = PathAnalyzer(graph)
                risky_paths = analyzer.find_risky_paths()
                progress_bar.update(task4, completed=100)
                console.print(f"[green]✓[/green] Identified {len(risky_paths)} privilege escalation paths")
        else:
            # Original spinner-based approach
            with console.status("[bold green]Scanning IAM roles..."):
                roles = scanner.scan_roles()
            console.print(f"[green]✓[/green] Scanned {len(roles)} IAM roles")
            
            with console.status("[bold green]Scanning IAM users..."):
                users = scanner.scan_users()
            console.print(f"[green]✓[/green] Scanned {len(users)} IAM users")
            
            # Build graph
            with console.status("[bold green]Building assume-role graph..."):
                builder = GraphBuilder()
                graph = builder.build_from_principals(roles, users)
            
            console.print(f"[green]✓[/green] Found {graph['stats']['edge_count']} assume-role relationships")
            
            # Analyze for risky paths
            with console.status("[bold green]Analyzing privilege escalation paths..."):
                analyzer = PathAnalyzer(graph)
                risky_paths = analyzer.find_risky_paths()
            
            console.print(f"[green]✓[/green] Identified {len(risky_paths)} privilege escalation paths")
        
        # Count critical risks
        critical_count = sum(1 for p in risky_paths if p['severity'] == 'CRITICAL')
        high_count = sum(1 for p in risky_paths if p['severity'] == 'HIGH')
        
        # Check for cross-account relationships
        primary_account = scanner.account_id
        has_cross_account = False
        for node in graph.get('nodes', []):
            node_account = node.get('account_id')
            if node_account and node_account != primary_account:
                has_cross_account = True
                break
        
        # Check if SCP analysis was enabled (future: detect from scanner)
        # For now, check if scp_resolver was instantiated (placeholder)
        scp_analysis_enabled = hasattr(scanner, 'scp_resolver') and scanner.scp_resolver is not None
        
        # Save graph
        output_path = Path(output)
        
        from datetime import datetime, UTC
        
        with open(output_path, 'w') as f:
            json.dump({
                'schema_version': '0.1.0',
                'metadata': {
                    'profile': profile,
                    'region': region or 'default',
                    'account_id': scanner.account_id,
                    'scan_timestamp': datetime.now(UTC).isoformat(),
                    'heimdall_version': __version__,
                    'scp_analysis_enabled': scp_analysis_enabled,
                    'has_cross_account_findings': has_cross_account
                },
                'graph': graph,
                'risky_paths': risky_paths
            }, f, indent=2)
        
        console.print(f"[green]✓[/green] Exported to {output}\n")
        logger.info("Scan completed successfully: %d roles, %d users, %d risky paths", 
                   len(roles), len(users), len(risky_paths))
        
        # Summary mode: just show stats
        if summary:
            console.print("[bold]Summary:[/bold]")
            console.print(f"  Roles: {graph['stats']['role_count']}")
            console.print(f"  Users: {graph['stats']['user_count']}")
            console.print(f"  Service principals: {graph['stats']['service_count']}")
            console.print(f"  Federated principals: {graph['stats']['federated_count']}")
            console.print(f"  Relationships: {graph['stats']['edge_count']}")
            console.print(f"  Human→Role paths: {graph['stats']['human_to_role_paths']}")
            console.print(f"  Risky paths: {len(risky_paths)} (Critical: {critical_count}, High: {high_count})\n")
            
            # Exit with appropriate code
            if fail_on_critical and critical_count > 0:
                raise SystemExit(2)
            return
        
        # Show top risky paths
        if risky_paths:
            console.print("[bold yellow]⚠️  Top Risky Paths:[/bold yellow]\n")
            
            for i, path_info in enumerate(risky_paths[:5], 1):
                sev = path_info['severity']
                path_str = ' → '.join(path_info['path'])
                console.print(f"  {format_severity(sev)} {path_str}")
            
            if len(risky_paths) > 5:
                console.print(f"\n[dim]  ... and {len(risky_paths) - 5} more (see {output})[/dim]")
        else:
            console.print("[green]✓ No critical privilege escalation paths found![/green]")
        
        console.print()
        
        # Exit with code 2 if critical risks found and flag is set
        if fail_on_critical and critical_count > 0:
            console.print(f"[red]Exiting with code 2: {critical_count} critical risk(s) found[/red]\n")
            raise SystemExit(2)
        
    except SystemExit:
        raise
    except Exception as e:
        logger.error("Scan command failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise SystemExit(1)


# Path Command - Logic moved to commands/path.py
@iam.command()
@click.option('--graph', required=True, type=click.Path(exists=True), help='Path to graph JSON file')
@click.option('--from', 'source', required=True, help='Source principal')
@click.option('--to', 'target', required=True, help='Target principal')
@click.option('--max-depth', default=DEFAULT_MAX_DEPTH, help='Maximum path length')
@click.option('--tree-view', is_flag=True, help='Display as tree structure')
@click.option('--no-color', is_flag=True, help='Disable colored output')
def path(graph: str, source: str, target: str, max_depth: int, tree_view: bool, no_color: bool) -> None:
    """Find privilege escalation path. Example: heimdall iam path --graph g.json --from user/intern --to role/Admin"""
    try:
        from heimdall.commands.path import run_path
        run_path(graph, source, target, max_depth, tree_view, no_color)
    except Exception as e:
        logger.error("Path command failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise click.Abort()


# Risks Command - Logic moved to commands/risks.py
@iam.command()
@click.option('--graph', required=True, type=click.Path(exists=True), help='Path to graph JSON file')
@click.option('--severity', type=click.Choice(['critical', 'high', 'medium', 'low', 'all']), default='all', help='Filter by severity')
def risks(graph: str, severity: str) -> None:
    """Show risky privilege escalation paths. Example: heimdall iam risks --graph graph.json --severity critical"""
    try:
        from heimdall.commands.risks import run_risks
        run_risks(graph, severity)
    except Exception as e:
        logger.error("Risks command failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise click.Abort()


# Attack Chain Command - Multi-step attack path analysis
@iam.command('attack-chain')
@click.option('--graph', default='heimdall-privesc.json', type=click.Path(exists=True), help='Path to graph JSON file')
@click.option('--from', 'from_principal', default=None, help='Filter by source principal')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'tree']), default='table', help='Output format')
@click.option('--top', 'top_n', default=10, help='Show top N chains')
@click.option('--steps', 'show_steps', is_flag=True, help='Show detailed attack steps')
def attack_chain(graph: str, from_principal: Optional[str], output_format: str, top_n: int, show_steps: bool) -> None:
    """
    Analyze multi-step attack chains.
    
    Transforms isolated findings into attack narratives showing
    how an attacker can chain multiple permissions for privilege escalation.
    
    Example:
        heimdall iam attack-chain
        heimdall iam attack-chain --from user/intern --steps
        heimdall iam attack-chain --format tree --top 5
    """
    try:
        from heimdall.commands.attack_chain import run_attack_chain
        run_attack_chain(graph, from_principal, output_format, top_n, show_steps)
    except Exception as e:
        logger.error("Attack-chain command failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise click.Abort()


@iam.command('detect-privesc')
@click.option(
    '--profile',
    default='default',
    help='AWS profile name to use'
)
@click.option(
    '--region',
    default=None,
    help='AWS region for resource enrichment (EC2, Lambda, RDS, etc.)'
)
@click.option(
    '--output',
    default='heimdall-privesc.json',
    help='Output file for privesc findings'
)
@click.option(
    '--explain',
    is_flag=True,
    help='Generate AI-powered explanations (requires LLM API key)'
)
@click.option(
    '--llm-provider',
    type=click.Choice(['openai', 'anthropic']),
    default='openai',
    help='LLM provider for explanations'
)
@click.option(
    '--llm-model',
    default=None,
    help='LLM model to use (defaults to provider default)'
)
@click.option(
    '--explain-top',
    type=int,
    default=None,
    help='Explain only top N critical findings (default: all)'
)
@click.option(
    '--exclude-admin-roles',
    is_flag=True,
    help='Exclude findings where the principal is an admin/high-privilege role (noise reduction)'
)
@click.option(
    '--include-indirect',
    is_flag=True,
    help='Include indirect (second-order) privilege escalation paths through trust chains'
)
@click.option(
    '--max-depth',
    type=int,
    default=2,
    help='Maximum depth for indirect path detection (default: 2)'
)
@click.option(
    '--enrich-resources',
    is_flag=True,
    help='Enrich findings with impacted AWS resources (EC2, Lambda, etc.)'
)
@click.option(
    '--scan-scp',
    is_flag=True,
    help='[v1.0.0] Scan AWS Organizations Service Control Policies for cross-account analysis'
)
@click.option(
    '--enrich-eks',
    is_flag=True,
    help='[v1.1.0] Enrich findings with EKS cluster and IRSA role escalation paths'
)
@click.option(
    '--enrich-secrets',
    is_flag=True,
    help='[v1.2.0] Enrich findings with Secrets Manager and SSM Parameter Store impact'
)
@click.option(
    '--format',
    'output_format',
    type=click.Choice(['json', 'sarif', 'csv', 'markdown']),
    default='json',
    help='Output format (json, sarif for GitHub Security, csv for Excel, markdown for reports)'
)
@click.option(
    '--severity',
    default='critical,high',
    help='Show findings by severity: critical, high, medium, low, or all (default: critical,high)'
)
@click.option(
    '--baseline', '-b',
    type=click.Path(exists=False),
    help='Baseline file to ignore known risks (.heimdall-ignore)'
)
@click.option(
    '--init-baseline',
    is_flag=True,
    help='Create sample .heimdall-ignore file'
)
def detect_privesc(
    profile: str,
    region: Optional[str],
    output: str,
    explain: bool,
    llm_provider: str,
    llm_model: Optional[str],
    explain_top: Optional[int],
    exclude_admin_roles: bool,
    include_indirect: bool,
    max_depth: int,
    enrich_resources: bool,
    scan_scp: bool,
    enrich_eks: bool,
    enrich_secrets: bool,
    output_format: str,
    severity: str,
    baseline: Optional[str],
    init_baseline: bool
) -> None:
    """
    Detect IAM privilege escalation opportunities (Phase 2A-1)
    
    Analyzes IAM policies to find principals with dangerous permission combinations.
    
    Example:
        heimdall iam detect-privesc --profile prod
        heimdall iam detect-privesc --baseline .heimdall-ignore
        heimdall iam detect-privesc --init-baseline
    """
    # Handle --init-baseline
    if init_baseline:
        from heimdall.baseline import create_sample_baseline
        create_sample_baseline()
        console.print("[green]✓[/green] Created sample .heimdall-ignore file")
        console.print("[dim]Edit this file to ignore known/accepted risks.[/dim]")
        return
    
    logger.info("Starting privesc detection: profile=%s, region=%s, output=%s", profile, region, output)
    
    # Determine version tag
    if enrich_secrets:
        version_tag = "v1.2.0"
        phase_label = "v1.2.0: Secrets Impact Analysis"
        if enrich_eks:
            phase_label += " + EKS Detection"
        if scan_scp:
            phase_label += " + SCP Evaluation"
        if enrich_resources:
            phase_label += " + Resource Context"
        if include_indirect:
            phase_label += " + Multi-Hop Paths"
        if explain:
            phase_label += " + AI Analysis"
    elif enrich_eks:
        version_tag = "v1.1.0"
        phase_label = "v1.1.0: EKS + IRSA Detection"
        if scan_scp:
            phase_label += " + SCP Evaluation"
        if enrich_resources:
            phase_label += " + Resource Context"
        if include_indirect:
            phase_label += " + Multi-Hop Paths"
        if explain:
            phase_label += " + AI Analysis"
    elif scan_scp:
        version_tag = "v1.0.0"
        phase_label = "v1.0.0: Cross-Account + SCP Evaluation"
        if enrich_resources:
            phase_label += " + Resource Context"
        if include_indirect:
            phase_label += " + Multi-Hop Paths"
        if explain:
            phase_label += " + AI Analysis"
    elif enrich_resources:
        version_tag = "v0.9.1"
        phase_label = "v0.9.1: Resource Context + Production Guardrails"
        if include_indirect:
            phase_label += " + Second-Order Detection"
        if explain:
            phase_label += " + AI Analysis"
    elif include_indirect:
        version_tag = "v0.4.0"
        phase_label = "Phase 2C: Second-Order Path Detection" + (" + AI Analysis" if explain else "")
    elif explain:
        version_tag = "v0.3.0"
        phase_label = "Phase 2B: AI-Powered Analysis"
    else:
        version_tag = "v0.2.0"
        phase_label = "Phase 2A-1: Permission-Aware Analysis"
    
    console.print(f"\n[bold cyan]🔐 Heimdall Privilege Escalation Detector ({version_tag})[/bold cyan]\n")
    
    console.print(f"[dim]{phase_label}[/dim]\n")
    
    # Smart profile selection
    from heimdall.aws_utils import profile_exists, get_default_profile
    
    if profile == 'default' and not profile_exists('default'):
        fallback_profile = get_default_profile()
        if fallback_profile and fallback_profile != 'default':
            console.print(f"[yellow]⚠️  'default' profile not found. Using '{fallback_profile}' instead.[/yellow]")
            console.print(f"[dim]💡 Tip: Specify profile with --profile {fallback_profile}[/dim]\n")
            profile = fallback_profile
        elif not fallback_profile:
            console.print("[red]✗ No AWS profiles found![/red]")
            console.print("\n[dim]Configure AWS credentials:[/dim]")
            console.print("  aws configure")
            console.print("  [dim]or run: heimdall aws profiles[/dim]\n")
            sys.exit(1)
    elif not profile_exists(profile):
        console.print(f"[red]✗ Profile '{profile}' not found![/red]")
        console.print("\n[dim]Available profiles:[/dim]")
        console.print("  heimdall aws profiles\n")
        sys.exit(1)
    
    # Check API key if --explain is requested
    if explain:
        import os
        api_key_found = False
        
        if llm_provider == 'openai':
            if os.getenv('OPENAI_API_KEY'):
                api_key_found = True
            else:
                console.print("[yellow]⚠️  OpenAI API key not found (OPENAI_API_KEY)[/yellow]")
        elif llm_provider == 'anthropic':
            if os.getenv('ANTHROPIC_API_KEY'):
                api_key_found = True
            else:
                console.print("[yellow]⚠️  Anthropic API key not found (ANTHROPIC_API_KEY)[/yellow]")
        
        if not api_key_found:
            console.print("\n[dim]AI explanations require an API key.[/dim]")
            console.print("[dim]Continue without AI explanations?[/dim]")
            
            # Ask user
            response = console.input("\n[cyan]Continue? (y/n):[/cyan] ").strip().lower()
            
            if response != 'y' and response != 'yes':
                console.print("\n[yellow]Scan cancelled. Set your API key and try again:[/yellow]")
                if llm_provider == 'openai':
                    console.print("  export OPENAI_API_KEY='sk-...'")
                else:
                    console.print("  export ANTHROPIC_API_KEY='sk-ant-...'")
                console.print()
                sys.exit(0)
            else:
                # User wants to continue without explanations
                console.print()
                explain = False  # Disable explanations
    
    try:
        # Scan IAM
        console.print(f"[dim]Using AWS profile:[/dim] {profile}")
        
        # Show region info
        if region:
            console.print(f"[dim]Using AWS region:[/dim] {region}")
        else:
            console.print(f"[dim]Auto-detecting region from profile config...[/dim]")
        
        scanner = IAMScanner(profile_name=profile, region_name=region)
        
        # Show detected region
        if not region and scanner.region:
            console.print(f"[dim]Detected region:[/dim] {scanner.region}")
        
        with console.status("[bold green]Scanning IAM roles..."):
            roles = scanner.scan_roles()
        console.print(f"[green]✓[/green] Scanned {len(roles)} IAM roles")
        
        with console.status("[bold green]Scanning IAM users..."):
            users = scanner.scan_users()
        console.print(f"[green]✓[/green] Scanned {len(users)} IAM users")
        
        # Scan resources for impact analysis (if requested)
        ec2_instances = []
        lambda_functions = []
        instance_profiles = {}
        s3_client = None
        rds_client = None
        secrets_client = None
        ssm_client = None
        
        if enrich_resources:
            with console.status("[bold green]Scanning EC2 instances..."):
                ec2_instances = scanner.scan_ec2_instances()
            if len(ec2_instances) > 0:
                console.print(f"[green]✓[/green] Scanned {len(ec2_instances)} EC2 instances")
            else:
                console.print(f"[green]✓[/green] Scanned {len(ec2_instances)} EC2 instances")
                console.print(f"[dim]  No EC2 instances found in region. Try --region flag if instances exist in other regions.[/dim]")
            
            with console.status("[bold green]Scanning Lambda functions..."):
                lambda_functions = scanner.scan_lambda_functions()
            if len(lambda_functions) > 0:
                console.print(f"[green]✓[/green] Scanned {len(lambda_functions)} Lambda functions")
            else:
                console.print(f"[green]✓[/green] Scanned {len(lambda_functions)} Lambda functions")
                console.print(f"[dim]  No Lambda functions found in region. Try --region flag if functions exist in other regions.[/dim]")
            
            with console.status("[bold green]Loading instance profiles..."):
                instance_profiles = scanner.get_instance_profiles()
            console.print(f"[green]✓[/green] Loaded {len(instance_profiles)} instance profiles")
            
            # Initialize AWS clients for resource context (v0.8.0-0.8.1)
            import boto3
            session = boto3.Session(profile_name=profile, region_name=region)
            
            # Auto-detect region if not provided (same logic as scanner)
            client_region = region
            if client_region is None:
                client_region = session.region_name
                if client_region is None:
                    client_region = 'us-east-1'  # Fallback
            
            s3_client = session.client('s3', region_name=client_region)
            rds_client = session.client('rds', region_name=client_region)
            secrets_client = session.client('secretsmanager', region_name=client_region)
            ssm_client = session.client('ssm', region_name=client_region)
        
        # Scan EKS clusters if requested (v1.1.0)
        eks_data = None
        if enrich_eks:
            try:
                from heimdall.iam.eks_scanner import EKSScanner
                
                with console.status("[bold green]Scanning EKS clusters..."):
                    eks_scanner = EKSScanner(profile_name=profile, region_name=region)
                    eks_data = eks_scanner.scan_all()
                
                cluster_count = len(eks_data.get('clusters', []))
                total_irsa_roles = sum(len(roles) for roles in eks_data.get('irsa_roles', {}).values())
                
                console.print(f"[green]✓[/green] Scanned {cluster_count} EKS cluster(s) with {total_irsa_roles} IRSA role(s)")
                
                if cluster_count == 0:
                    console.print("[dim]No EKS clusters found in this region[/dim]")
            
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] EKS scan failed: {str(e)}")
                console.print("[dim]Continuing without EKS enrichment...[/dim]")
                eks_data = None
        
        # Scan Secrets Manager and SSM if requested (v1.2.0)
        secrets_data = None
        if enrich_secrets:
            try:
                from heimdall.iam.secrets_scanner import SecretsScanner
                
                with console.status("[bold green]Scanning Secrets Manager and SSM Parameter Store..."):
                    secrets_scanner = SecretsScanner(
                        session=boto3.Session(profile_name=profile, region_name=region),
                        region=region or 'us-east-1'
                    )
                    secrets_data = secrets_scanner.scan()
                
                secret_count = len(secrets_data.get('secrets', []))
                param_count = len(secrets_data.get('parameters', []))
                high_value_count = secrets_data['statistics']['high_value_secrets'] + secrets_data['statistics']['high_value_parameters']
                
                console.print(f"[green]✓[/green] Scanned {secret_count} secret(s) and {param_count} parameter(s) ({high_value_count} high-value)")
                
                if secret_count == 0 and param_count == 0:
                    console.print("[dim]No secrets or parameters found in this region[/dim]")
            
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Secrets scan failed: {str(e)}")
                console.print("[dim]Continuing without secrets enrichment...[/dim]")
                secrets_data = None
        
        # Build IAM trust graph (v1.1.0: include EKS data, v1.2.0: include secrets data)
        with console.status("[bold green]Building IAM trust graph..."):
            graph_builder = GraphBuilder()
            trust_graph = graph_builder.build_from_principals(
                roles, 
                users, 
                eks_data=eks_data if enrich_eks else None,
                secrets_data=secrets_data if enrich_secrets else None
            )
        console.print(f"[green]✓[/green] Built trust graph with {trust_graph['stats']['node_count']} nodes, {trust_graph['stats']['edge_count']} edges")
        
        # v1.1.0: Show EKS cluster count if available
        if enrich_eks and eks_data:
            eks_cluster_count = trust_graph['stats'].get('eks_cluster_count', 0)
            if eks_cluster_count > 0:
                console.print(f"[green]✓[/green] Integrated {eks_cluster_count} EKS cluster(s) into trust graph")
        
        # v1.2.0: Show secrets/parameters count if available
        if enrich_secrets and secrets_data:
            secret_count = trust_graph['stats'].get('secret_count', 0)
            parameter_count = trust_graph['stats'].get('parameter_count', 0)
            if secret_count > 0 or parameter_count > 0:
                console.print(f"[green]✓[/green] Integrated {secret_count} secret(s) and {parameter_count} parameter(s) into trust graph")
        
        # Scan SCPs if requested (v1.0.0)
        scp_policies = []
        if scan_scp:
            try:
                with console.status("[bold green]Scanning AWS Organizations SCPs..."):
                    import boto3
                    session = boto3.Session(profile_name=profile, region_name=region)
                    orgs_client = session.client('organizations')
                    
                    # Get organization structure
                    try:
                        org_response = orgs_client.describe_organization()
                        org_id = org_response['Organization']['Id']
                        
                        # List accounts
                        accounts_paginator = orgs_client.get_paginator('list_accounts')
                        accounts = []
                        for page in accounts_paginator.paginate():
                            accounts.extend(page.get('Accounts', []))
                        
                        # Scan SCPs for each account
                        for account in accounts:
                            account_id = account['Id']
                            
                            # List policies attached to account
                            try:
                                policies_response = orgs_client.list_policies_for_target(
                                    TargetId=account_id,
                                    Filter='SERVICE_CONTROL_POLICY'
                                )
                                
                                for policy_summary in policies_response.get('Policies', []):
                                    policy_id = policy_summary['Id']
                                    
                                    # Get policy content
                                    policy_detail = orgs_client.describe_policy(PolicyId=policy_id)
                                    policy_content_str = policy_detail['Policy']['Content']
                                    
                                    # Parse SCP JSON content (json already imported at module level)
                                    policy_content = json.loads(policy_content_str)
                                    
                                    scp_policies.append({
                                        'PolicyId': policy_id,
                                        'Name': policy_summary['Name'],
                                        'TargetType': 'ACCOUNT',
                                        'TargetId': account_id,
                                        'Content': policy_content
                                    })
                            except Exception:
                                # Account might not have SCPs or access denied
                                pass
                        
                        console.print(f"[green]✓[/green] Scanned {len(scp_policies)} Service Control Policies across {len(accounts)} accounts")
                    
                    except orgs_client.exceptions.AWSOrganizationsNotInUseException:
                        console.print("[yellow]⚠[/yellow] AWS Organizations not enabled in this account")
                    except Exception as e:
                        console.print(f"[yellow]⚠[/yellow] Could not scan Organizations: {str(e)}")
                        console.print("[dim]Continuing without SCP evaluation...[/dim]")
            
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] SCP scan failed: {str(e)}")
                console.print("[dim]Continuing without SCP evaluation...[/dim]")
        
        # Analyze permissions (Phase 2A-2: pass IAM client for custom policies, v1.0.0: pass SCPs, v1.1.0: pass EKS data, v1.2.0: pass secrets data)
        with console.status("[bold green]Analyzing IAM permissions..."):
            analyzer = PermissionAnalyzer(
                roles, 
                users, 
                iam_client=scanner.iam,
                scp_policies=scp_policies if scan_scp else None,
                eks_data=eks_data if enrich_eks else None,
                secrets_data=secrets_data if enrich_secrets else None
            )
            findings = analyzer.detect_direct_privesc(exclude_admin_roles=exclude_admin_roles)
        
        console.print(f"[green]✓[/green] Detected {len(findings)} direct privilege escalation opportunities")
        
        # Apply baseline filtering if specified
        baseline_stats = None
        if baseline or os.path.exists('.heimdall-ignore'):
            from heimdall.baseline import Baseline
            baseline_file = baseline or '.heimdall-ignore'
            baseline_obj = Baseline.load(baseline_file)
            if baseline_obj.rules:
                original_count = len(findings)
                findings, ignored, baseline_stats = baseline_obj.filter_findings(findings)
                console.print(f"[yellow]⚡[/yellow] Baseline applied: {baseline_stats['ignored']} findings ignored ({len(findings)} remaining)")
                if baseline_stats['by_rule']:
                    for rule, count in list(baseline_stats['by_rule'].items())[:3]:
                        console.print(f"  [dim]• {rule}: {count} ignored[/dim]")
        if exclude_admin_roles:
            console.print("[dim]Admin/high-privilege roles excluded from findings (use without --exclude-admin-roles to see all).[/dim]")
        
        # v1.2.0: Show secrets impact statistics
        if enrich_secrets and secrets_data:
            findings_with_secrets = sum(1 for f in findings if f.get('impacted_secrets'))
            if findings_with_secrets > 0:
                total_secrets_exposed = sum(f.get('impacted_secrets', {}).get('total_count', 0) for f in findings)
                console.print(f"[green]✓[/green] {findings_with_secrets} findings expose {total_secrets_exposed} secret(s)/parameter(s)")
        
        # Detect indirect privesc if requested
        indirect_findings = []
        if include_indirect:
            with console.status("[bold green]Detecting indirect privilege escalation paths..."):
                indirect_findings = analyzer.detect_indirect_privesc(
                    trust_graph=trust_graph,
                    max_depth=max_depth,
                    exclude_admin_roles=exclude_admin_roles
                )
            console.print(f"[green]✓[/green] Detected {len(indirect_findings)} indirect privilege escalation paths (max depth: {max_depth})")
        
        # Enrich findings with resource impact (if requested)
        if enrich_resources:
            from heimdall.iam.resource_analyzer import ResourceAnalyzer
            
            # Initialize resource analyzer
            resource_analyzer = ResourceAnalyzer(
                ec2_instances=ec2_instances,
                lambda_functions=lambda_functions,
                instance_profiles=instance_profiles,
                s3_client=s3_client,
                rds_client=rds_client,
                secrets_client=secrets_client,
                ssm_client=ssm_client
            )
            
            # Scan S3 buckets and RDS instances once (lazy-loaded, cached)
            if s3_client:
                with console.status("[bold green]Scanning S3 buckets..."):
                    s3_buckets = resource_analyzer.scan_s3_buckets()
                console.print(f"[green]✓[/green] Scanned {len(s3_buckets)} S3 buckets")
            
            if rds_client:
                with console.status("[bold green]Scanning RDS instances..."):
                    rds_instances = resource_analyzer.scan_rds_instances()
                console.print(f"[green]✓[/green] Scanned {len(rds_instances)} RDS instances")
            
            # Scan Secrets Manager and SSM Parameter Store (v0.8.1)
            if secrets_client:
                with console.status("[bold green]Scanning Secrets Manager..."):
                    secrets = resource_analyzer.scan_secrets()
                console.print(f"[green]✓[/green] Scanned {len(secrets)} secrets")
            
            if ssm_client:
                with console.status("[bold green]Scanning SSM Parameter Store..."):
                    ssm_parameters = resource_analyzer.scan_ssm_parameters()
                console.print(f"[green]✓[/green] Scanned {len(ssm_parameters)} SSM parameters")
            
            # Build role lookup dict for enrichment
            roles_by_arn = {role['arn']: role for role in roles}
            
            # Enrich direct findings
            enriched_count = 0
            s3_enriched = 0
            rds_enriched = 0
            secrets_enriched = 0
            ssm_enriched = 0
            
            with console.status("[bold green]Enriching findings with resource impact..."):
                for finding in findings:
                    # EC2/Lambda enrichment (existing)
                    enriched = resource_analyzer.enrich_finding(finding)
                    if 'impacted_resources' in enriched:
                        enriched_count += 1
                    
                    # S3/RDS/Secrets/SSM enrichment (v0.8.0-0.8.1)
                    target_role_arn = finding.get('target_role_arn')
                    if target_role_arn and target_role_arn in roles_by_arn:
                        role_data = roles_by_arn[target_role_arn]
                        
                        if s3_client:
                            resource_analyzer.enrich_finding_with_s3(finding, role_data)
                            if finding.get('impacted_resources', {}).get('s3_buckets'):
                                s3_enriched += 1
                        
                        if rds_client:
                            resource_analyzer.enrich_finding_with_rds(finding, role_data)
                            if finding.get('impacted_resources', {}).get('rds_instances'):
                                rds_enriched += 1
                        
                        if secrets_client:
                            resource_analyzer.enrich_finding_with_secrets(finding, role_data, secrets)
                            if finding.get('impacted_resources', {}).get('secrets'):
                                secrets_enriched += 1
                        
                        if ssm_client:
                            resource_analyzer.enrich_finding_with_ssm(finding, role_data, ssm_parameters)
                            if finding.get('impacted_resources', {}).get('ssm_parameters'):
                                ssm_enriched += 1
                
                # Enrich indirect findings
                for finding in indirect_findings:
                    resource_analyzer.enrich_finding(finding)
                    
                    target_role_arn = finding.get('target_role_arn')
                    if target_role_arn and target_role_arn in roles_by_arn:
                        role_data = roles_by_arn[target_role_arn]
                        
                        if s3_client:
                            resource_analyzer.enrich_finding_with_s3(finding, role_data)
                        
                        if rds_client:
                            resource_analyzer.enrich_finding_with_rds(finding, role_data)
                        
                        if secrets_client:
                            resource_analyzer.enrich_finding_with_secrets(finding, role_data, secrets)
                        
                        if ssm_client:
                            resource_analyzer.enrich_finding_with_ssm(finding, role_data, ssm_parameters)
            
            console.print(f"[green]✓[/green] Enriched {enriched_count} findings with EC2/Lambda impact")
            if s3_enriched > 0:
                console.print(f"[green]✓[/green] Enriched {s3_enriched} findings with S3 bucket impact")
            if rds_enriched > 0:
                console.print(f"[green]✓[/green] Enriched {rds_enriched} findings with RDS database impact")
            if secrets_enriched > 0:
                console.print(f"[green]✓[/green] Enriched {secrets_enriched} findings with Secrets Manager impact")
            if ssm_enriched > 0:
                console.print(f"[green]✓[/green] Enriched {ssm_enriched} findings with SSM Parameter Store impact")
        
        console.print()
        
        # Generate AI explanations if requested
        explanations = {}
        llm_metadata = {}
        
        if explain:
            try:
                from heimdall.llm.explainer import LLMExplainer
                from heimdall.iam.privesc_patterns import PRIVESC_PATTERNS
                
                console.print("[bold cyan]🤖 Generating AI explanations...[/bold cyan]\n")
                
                # Initialize LLM explainer
                with console.status("[bold green]Initializing LLM provider..."):
                    explainer = LLMExplainer(
                        provider=llm_provider,
                        model=llm_model
                    )
                    
                    # Test connection
                    if not explainer.test_connection():
                        raise Exception(f"{llm_provider} API connection failed. Check your API key.")
                
                console.print(f"[green]✓[/green] Connected to {llm_provider}\n")
                
                # Create pattern lookup dict
                from dataclasses import asdict
                patterns_dict = {k: asdict(v) for k, v in PRIVESC_PATTERNS.items()}
                
                # Generate explanations for direct findings
                with console.status("[bold green]Generating explanations for direct findings..."):
                    explanations = explainer.explain_findings_batch(
                        findings,
                        patterns_dict,
                        max_findings=explain_top
                    )
                
                explained_count = len(explanations)
                console.print(f"[green]✓[/green] Generated {explained_count} direct finding explanations")
                
                # Generate explanations for indirect findings
                indirect_explanations = {}
                if include_indirect and indirect_findings:
                    with console.status("[bold green]Generating explanations for indirect paths..."):
                        indirect_explanations = explainer.explain_indirect_findings_batch(
                            indirect_findings,
                            patterns_dict,
                            max_findings=explain_top
                        )
                    
                    indirect_explained_count = len(indirect_explanations)
                    console.print(f"[green]✓[/green] Generated {indirect_explained_count} indirect path explanations")
                
                console.print()
                
                # Get LLM stats
                stats = explainer.get_stats()
                llm_metadata = {
                    'llm_enabled': True,
                    'llm_provider': llm_provider,
                    'llm_model': explainer.provider.model,
                    'explained_findings': explained_count,
                    'explained_indirect_findings': len(indirect_explanations),
                    'cache_hit_rate': stats['cache_hit_rate']
                }
                
            except ImportError as e:
                console.print(f"[yellow]⚠[/yellow] LLM dependencies not installed: {e}")
                console.print("[dim]Install with: pip install heimdall-aws[llm][/dim]\n")
                llm_metadata = {'llm_enabled': False, 'llm_error': 'Dependencies not installed'}
            
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] LLM explanation failed: {e}")
                console.print("[dim]Continuing without explanations...[/dim]\n")
                llm_metadata = {'llm_enabled': False, 'llm_error': str(e)}
        
        # Add explanations to findings
        if explanations:
            for idx, finding in enumerate(findings):
                if idx in explanations:
                    finding['explanation'] = explanations[idx]
        
        # Add explanations to indirect findings
        if 'indirect_explanations' in locals() and indirect_explanations:
            for idx, finding in enumerate(indirect_findings):
                if idx in indirect_explanations:
                    finding['explanation'] = indirect_explanations[idx]
        
        # Save findings
        output_path = Path(output)
        from datetime import datetime, UTC
        
        # Determine schema version based on features used
        if scan_scp:
            schema_version = '1.0.0'  # Cross-account + SCP evaluation
        elif enrich_resources:
            schema_version = '0.9.1'  # S3/RDS/Secrets/SSM resource context + guardrails
        elif include_indirect:
            schema_version = '0.4.0'
        elif explain:
            schema_version = '0.3.0'
        else:
            # v1.0.0: Cross-account detection is always enabled (baseline)
            schema_version = '1.0.0'
        
        # Combine all findings for summary
        all_findings = findings + indirect_findings
        
        # Calculate resources_with_impact (v0.9.1) - count unique impacted resources
        resources_with_impact = {
            'ec2_instances': 0,
            'lambda_functions': 0,
            's3_buckets': 0,
            'rds_instances': 0,
            'secrets': 0,
            'ssm_parameters': 0,
            'total': 0
        }
        
        if enrich_resources:
            # Track unique resource identifiers
            unique_ec2 = set()
            unique_lambda = set()
            unique_s3 = set()
            unique_rds = set()
            unique_secrets = set()
            unique_ssm = set()
            
            for finding in all_findings:
                if 'impacted_resources' in finding:
                    resources = finding['impacted_resources']
                    
                    if 'ec2_instances' in resources:
                        for inst in resources['ec2_instances']:
                            unique_ec2.add(inst.get('instance_id'))
                    
                    if 'lambda_functions' in resources:
                        for func in resources['lambda_functions']:
                            unique_lambda.add(func.get('function_name'))
                    
                    if 's3_buckets' in resources:
                        for bucket in resources['s3_buckets']:
                            unique_s3.add(bucket.get('name'))
                    
                    if 'rds_instances' in resources:
                        for db in resources['rds_instances']:
                            unique_rds.add(db.get('identifier'))
                    
                    if 'secrets' in resources:
                        for secret in resources['secrets']:
                            unique_secrets.add(secret.get('name'))
                    
                    if 'ssm_parameters' in resources:
                        for param in resources['ssm_parameters']:
                            unique_ssm.add(param.get('name'))
            
            resources_with_impact = {
                'ec2_instances': len(unique_ec2),
                'lambda_functions': len(unique_lambda),
                's3_buckets': len(unique_s3),
                'rds_instances': len(unique_rds),
                'secrets': len(unique_secrets),
                'ssm_parameters': len(unique_ssm),
                'total': len(unique_ec2) + len(unique_lambda) + len(unique_s3) + len(unique_rds) + len(unique_secrets) + len(unique_ssm)
        }
        
        # Prepare full data structure
        full_data = {
            'schema_version': schema_version,
            'metadata': {
                'profile': profile,
                'region': region or 'default',
                'account_id': scanner.account_id,
                'scan_timestamp': datetime.now(UTC).isoformat(),
                'heimdall_version': __version__,
                'analysis_type': 'permission_privesc',
                'indirect_detection_enabled': include_indirect,
                'max_depth': max_depth if include_indirect else None,
                'resource_enrichment_enabled': enrich_resources,
                'ec2_instances_scanned': len(ec2_instances) if enrich_resources else 0,
                'lambda_functions_scanned': len(lambda_functions) if enrich_resources else 0,
                's3_buckets_scanned': len(s3_buckets) if enrich_resources and s3_client else 0,
                'rds_instances_scanned': len(rds_instances) if enrich_resources and rds_client else 0,
                'secrets_scanned': len(secrets) if enrich_resources and secrets_client else 0,
                'ssm_parameters_scanned': len(ssm_parameters) if enrich_resources and ssm_client else 0,
                # Truncation flags (v0.9.1 guardrails)
                's3_buckets_truncated': (len(s3_buckets) >= 1000) if enrich_resources and s3_client else False,
                'rds_instances_truncated': (len(rds_instances) >= 1000) if enrich_resources and rds_client else False,
                'secrets_truncated': (len(secrets) >= 1000) if enrich_resources and secrets_client else False,
                'ssm_parameters_truncated': (len(ssm_parameters) >= 1000) if enrich_resources and ssm_client else False,
                # Resource impact summary (v0.9.1)
                'resources_with_impact': resources_with_impact,
                # v1.0.0: Cross-account + SCP metadata
                'scp_evaluation_enabled': scan_scp,
                'scp_policies_scanned': len(scp_policies) if scan_scp else 0,
                # v1.1.0: EKS metadata
                'eks_enrichment_enabled': enrich_eks,
                'eks_clusters_scanned': len(eks_data.get('clusters', [])) if eks_data else 0,
                'eks_irsa_roles_found': sum(len(roles) for roles in eks_data.get('irsa_roles', {}).values()) if eks_data else 0,
                # v1.2.0: Secrets metadata
                'secrets_enrichment_enabled': enrich_secrets,
                'secrets_manager_scanned': len(secrets_data.get('secrets', [])) if secrets_data else 0,
                'ssm_parameters_scanned_v2': len(secrets_data.get('parameters', [])) if secrets_data else 0,
                'high_value_secrets_found': secrets_data['statistics']['high_value_secrets'] + secrets_data['statistics']['high_value_parameters'] if secrets_data else 0,
                **llm_metadata
            },
            'findings': findings,
            'indirect_findings': indirect_findings if include_indirect else [],
            'trust_graph': trust_graph,
            'eks_data': eks_data if enrich_eks and eks_data else None,
            'secrets_data': secrets_data if enrich_secrets and secrets_data else None,
            'summary': {
                'total_findings': len(all_findings),
                'direct_findings': len(findings),
                'indirect_findings': len(indirect_findings),
                'critical_count': sum(1 for f in all_findings if f['severity'] == 'CRITICAL'),
                'high_count': sum(1 for f in all_findings if f['severity'] == 'HIGH'),
                'principals_with_privesc': len(set(f.get('principal', f.get('start_principal')) for f in all_findings)),
                'explained_findings': len(explanations) if explanations else 0
            }
        }
        
        # Save in requested format
        if output_format == 'sarif':
            from heimdall.exporters.sarif import SARIFExporter
            sarif_output = str(output_path).replace('.json', '.sarif') if str(output_path).endswith('.json') else str(output_path) + '.sarif'
            SARIFExporter.save(all_findings, sarif_output, 
                              scan_info={'profile': profile, 'region': region or 'default'})
            console.print(f"[green]✓[/green] Exported to {sarif_output} (SARIF format for GitHub Security)")
            console.print(f"[dim]Upload to GitHub: gh api repos/OWNER/REPO/code-scanning/sarifs -f sarif=@{sarif_output}[/dim]\n")
        
        elif output_format == 'csv':
            from heimdall.exporters.csv_export import CSVExporter
            csv_output = str(output_path).replace('.json', '.csv') if str(output_path).endswith('.json') else str(output_path) + '.csv'
            CSVExporter.save(all_findings, csv_output)
            console.print(f"[green]✓[/green] Exported to {csv_output} (CSV format for Excel)\n")
        
        elif output_format == 'markdown':
            from heimdall.exporters import MarkdownExporter
            exporter = MarkdownExporter()
            markdown_content = exporter.export(full_data)
            # Change extension to .md
            md_output = str(output_path).replace('.json', '.md') if str(output_path).endswith('.json') else str(output_path) + '.md'
            with open(md_output, 'w') as f:
                f.write(markdown_content)
            console.print(f"[green]✓[/green] Exported to {md_output} (Markdown format)\n")
        
        else:  # json (default)
            with open(output_path, 'w') as f:
                json.dump(full_data, f, indent=2)
            console.print(f"[green]✓[/green] Exported to {output}\n")
        
        # Display findings
        if findings:
            console.print("[bold yellow]⚠️  Privilege Escalation Opportunities:[/bold yellow]\n")
            
            # Parse severity filter
            severity_filter = severity.lower().split(',') if ',' in severity else [severity.lower()]
            if 'all' in severity_filter:
                severity_filter = ['critical', 'high', 'medium', 'low']
            
            # Group by severity
            critical = [f for f in findings if f['severity'] == 'CRITICAL']
            high = [f for f in findings if f['severity'] == 'HIGH']
            medium = [f for f in findings if f['severity'] == 'MEDIUM']
            low = [f for f in findings if f['severity'] == 'LOW']
            
            if critical and 'critical' in severity_filter:
                console.print(f"[bold red]CRITICAL ({len(critical)}):[/bold red]")
                for finding in critical[:5]:  # Top 5
                    console.print(f"  [red]•[/red] {finding['principal_type']}/{finding['principal_name']}")
                    console.print(f"    [dim]Method:[/dim] [bold]{finding['privesc_method']}[/bold]")
                    console.print(f"    [dim]{finding['description']}[/dim]")
                    
                    # Show source policies if available
                    if finding.get('source_policies'):
                        policies = finding['source_policies']
                        if len(policies) == 1:
                            console.print(f"    [dim]Policy:[/dim] {policies[0]}")
                        elif len(policies) > 0:
                            console.print(f"    [dim]Policies:[/dim] {', '.join(policies[:3])}")
                            if len(policies) > 3:
                                console.print(f"    [dim]          ... and {len(policies) - 3} more[/dim]")
                    
                    # Show AI explanation if available
                    if 'explanation' in finding:
                        exp = finding['explanation']
                        # Skip if explanation is a string (fallback)
                        if isinstance(exp, str):
                            continue
                        
                        console.print(f"\n    [bold cyan]🤖 AI Analysis:[/bold cyan]")
                        console.print(f"    [cyan]{exp.get('summary', 'N/A')}[/cyan]")
                        
                        if exp.get('attack_steps'):
                            console.print(f"\n    [bold yellow]Attack Steps:[/bold yellow]")
                            for i, step in enumerate(exp['attack_steps'][:3], 1):
                                console.print(f"      {i}. {step}")
                        
                        if exp.get('remediation', {}).get('immediate'):
                            console.print(f"\n    [bold green]Immediate Actions:[/bold green]")
                            for action in exp['remediation']['immediate'][:2]:
                                console.print(f"      • {action}")
                        
                        if exp.get('exploitability_score'):
                            score = exp['exploitability_score']
                            color = "red" if score >= 8 else "yellow" if score >= 5 else "green"
                            console.print(f"\n    [dim]Exploitability:[/dim] [{color}]{score}/10[/{color}]  [dim]Confidence:[/dim] {int(exp.get('confidence', 0) * 100)}%")
                        
                        if exp.get('mitre_attack'):
                            mitre_ids = ', '.join(exp['mitre_attack'])
                            console.print(f"    [dim]MITRE ATT&CK:[/dim] [blue]{mitre_ids}[/blue]")
                    
                    console.print()
                
                if len(critical) > 5:
                    console.print(f"  [dim]... and {len(critical) - 5} more critical findings[/dim]\n")
            
            if high and 'high' in severity_filter:
                console.print(f"[bold yellow]HIGH ({len(high)}):[/bold yellow]")
                for finding in high[:3]:  # Top 3
                    console.print(f"  [yellow]•[/yellow] {finding['principal_type']}/{finding['principal_name']}")
                    console.print(f"    [dim]Method:[/dim] [bold]{finding['privesc_method']}[/bold]")
                    console.print(f"    [dim]{finding['description']}[/dim]")
                    
                    # Show source policies
                    if finding.get('source_policies'):
                        policies = finding['source_policies']
                        if len(policies) == 1:
                            console.print(f"    [dim]Policy:[/dim] {policies[0]}")
                        elif len(policies) > 0:
                            console.print(f"    [dim]Policies:[/dim] {', '.join(policies[:3])}")
                    
                    # Show AI explanation if available (condensed for HIGH)
                    if 'explanation' in finding:
                        exp = finding['explanation']
                        # Skip if explanation is a string (fallback)
                        if isinstance(exp, str):
                            continue
                        
                        console.print(f"\n    [cyan]🤖 {exp.get('summary', 'N/A')}[/cyan]")
                        if exp.get('exploitability_score'):
                            score = exp['exploitability_score']
                            color = "red" if score >= 8 else "yellow" if score >= 5 else "green"
                            console.print(f"    [dim]Exploitability:[/dim] [{color}]{score}/10[/{color}]")
                    
                    console.print()
                
                if len(high) > 3:
                    console.print(f"  [dim]... and {len(high) - 3} more high findings[/dim]\n")
            
            if medium and 'medium' in severity_filter:
                console.print(f"[bold blue]MEDIUM ({len(medium)}):[/bold blue]")
                for finding in medium[:3]:  # Top 3
                    console.print(f"  [blue]•[/blue] {finding['principal_type']}/{finding['principal_name']}")
                    console.print(f"    [dim]Method:[/dim] [bold]{finding['privesc_method']}[/bold]")
                    console.print(f"    [dim]{finding['description']}[/dim]")
                    
                    # Show source policies
                    if finding.get('source_policies'):
                        policies = finding['source_policies']
                        if len(policies) == 1:
                            console.print(f"    [dim]Policy:[/dim] {policies[0]}")
                        elif len(policies) > 0:
                            console.print(f"    [dim]Policies:[/dim] {', '.join(policies[:3])}")
                    console.print()
                
                if len(medium) > 3:
                    console.print(f"  [dim]... and {len(medium) - 3} more medium findings[/dim]\n")
            
            if low and 'low' in severity_filter:
                console.print(f"[bold green]LOW ({len(low)}):[/bold green]")
                for finding in low[:3]:  # Top 3
                    console.print(f"  [green]•[/green] {finding['principal_type']}/{finding['principal_name']}")
                    console.print(f"    [dim]Method:[/dim] [bold]{finding['privesc_method']}[/bold]")
                    console.print(f"    [dim]{finding['description']}[/dim]")
                    
                    # Show source policies
                    if finding.get('source_policies'):
                        policies = finding['source_policies']
                        if len(policies) == 1:
                            console.print(f"    [dim]Policy:[/dim] {policies[0]}")
                        elif len(policies) > 0:
                            console.print(f"    [dim]Policies:[/dim] {', '.join(policies[:3])}")
                    console.print()
                
                if len(low) > 3:
                    console.print(f"  [dim]... and {len(low) - 3} more low findings[/dim]\n")
            
            console.print(f"[dim]Full details in {output}[/dim]\n")
        else:
            console.print("[green]✓ No direct privilege escalation opportunities found![/green]\n")
        
        # Display indirect findings if any
        if indirect_findings:
            console.print("[bold cyan]🔗 Indirect Privilege Escalation Paths (Multi-Hop):[/bold cyan]\n")
            
            # Group by severity
            critical_indirect = [f for f in indirect_findings if f['severity'] == 'CRITICAL']
            high_indirect = [f for f in indirect_findings if f['severity'] == 'HIGH']
            
            if critical_indirect:
                console.print(f"[bold red]CRITICAL ({len(critical_indirect)}):[/bold red]")
                for finding in critical_indirect[:3]:  # Top 3
                    # Format path
                    path_str = finding['start_principal_name']
                    for hop in finding['path']:
                        to_name = hop['to'].split('/')[-1]
                        path_str += f" → {to_name}"
                    
                    console.print(f"  [red]•[/red] {path_str}")
                    console.print(f"    [dim]Start:[/dim] {finding['start_principal_type']}/{finding['start_principal_name']}")
                    console.print(f"    [dim]Path length:[/dim] {finding['path_length']} hops")
                    console.print(f"    [dim]Target pattern:[/dim] [bold]{finding['privesc_method']}[/bold] ({finding['severity']})")
                    console.print(f"    [dim]{finding['description']}[/dim]")
                    console.print()
                
                if len(critical_indirect) > 3:
                    console.print(f"  [dim]... and {len(critical_indirect) - 3} more critical indirect paths[/dim]\n")
            
            if high_indirect:
                console.print(f"[bold yellow]HIGH ({len(high_indirect)}):[/bold yellow]")
                for finding in high_indirect[:2]:  # Top 2
                    # Format path
                    path_str = finding['start_principal_name']
                    for hop in finding['path']:
                        to_name = hop['to'].split('/')[-1]
                        path_str += f" → {to_name}"
                    
                    console.print(f"  [yellow]•[/yellow] {path_str}")
                    console.print(f"    [dim]Target:[/dim] [bold]{finding['privesc_method']}[/bold]")
                    console.print()
                
                if len(high_indirect) > 2:
                    console.print(f"  [dim]... and {len(high_indirect) - 2} more high indirect paths[/dim]\n")
            
            console.print(f"[dim]Full indirect paths in {output}[/dim]\n")
        
    except Exception as e:
        logger.error("Detect-privesc command failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        import traceback
        traceback.print_exc()
        raise SystemExit(1)


# List-Paths Command - Logic moved to commands/list_paths.py
@iam.command('list-paths')
@click.option('--graph', required=True, type=click.Path(exists=True), help='Path to graph JSON file')
@click.option('--from-type', type=click.Choice(['user', 'role', 'service', 'federated', 'all']), default='user', help='Source type')
@click.option('--to-type', type=click.Choice(['role', 'user', 'all']), default='role', help='Target type')
@click.option('--direct-only', is_flag=True, help='Show only direct paths')
@click.option('--output-format', type=click.Choice(['table', 'csv', 'json']), default='table', help='Output format')
@click.option('--output-file', type=click.Path(), default=None, help='Save to file')
@click.option('--no-color', is_flag=True, help='Disable colored output')
def list_paths(graph: str, from_type: str, to_type: str, direct_only: bool, output_format: str, output_file: Optional[str], no_color: bool) -> None:
    """List assume-role paths. Example: heimdall iam list-paths --graph g.json --from-type user"""
    try:
        from heimdall.commands.list_paths import run_list_paths
        run_list_paths(graph, from_type, to_type, direct_only, output_format, output_file, no_color)
    except Exception as e:
        logger.error("List-paths command failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise click.Abort()


# TUI Command - Interactive Terminal UI (v1.3.0)
@iam.command()
@click.option(
    '--graph',
    type=click.Path(exists=True),
    help='Path to graph JSON file from scan command'
)
def tui(graph: Optional[str]) -> None:
    """
    Launch interactive Terminal UI (TUI).
    
    Beautiful, interactive terminal interface for exploring IAM security data.
    
    Example:
        heimdall iam tui --graph scan.json
    """
    try:
        from heimdall.tui import run_tui
        console.print("[bold cyan]🚀 Launching Heimdall TUI...[/bold cyan]\n")
        run_tui(graph_file=graph)
    except ImportError as e:
        logger.error("TUI dependencies not installed: %s", e)
        console.print("[red]✗ Error:[/red] TUI dependencies not found.")
        console.print("[yellow]Install with:[/yellow] pip install 'heimdall-aws[all]'")
        raise click.Abort()
    except Exception as e:
        logger.error("TUI failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise click.Abort()


# AI Commands - Intelligent Analysis (v1.3.0)
@iam.command()
@click.argument('question', type=str)
@click.option(
    '--graph',
    type=click.Path(exists=True),
    required=True,
    help='Path to graph JSON file from scan command'
)
@click.option(
    '--ai',
    default='openai',
    type=click.Choice(['openai', 'anthropic']),
    help='AI provider to use'
)
@click.option(
    '--model',
    default=None,
    help='Specific model to use (optional)'
)
def ask(question: str, graph: str, ai: str, model: Optional[str]) -> None:
    """
    Ask natural language questions about IAM security.
    
    Examples:
        heimdall iam ask "Can contractor access production?" --graph scan.json
        heimdall iam ask "What's the easiest path to admin?" --graph scan.json --ai anthropic
    """
    try:
        from heimdall.ai_analyzer import AIAnalyzer
        
        console.print(f"[bold cyan]🤖 AI Analysis ({ai})[/bold cyan]\n")
        console.print(f"[dim]Question:[/dim] {question}\n")
        
        # Load graph
        with open(graph, 'r') as f:
            data = json.load(f)
        
        graph_data = data.get('graph', {})
        
        # Initialize AI
        analyzer = AIAnalyzer(provider=ai, model=model)
        
        # Get answer
        console.print("[dim]Analyzing...[/dim]\n")
        answer = analyzer.ask_question(question, graph_data)
        
        # Display answer
        console.print("[bold green]Answer:[/bold green]")
        console.print(answer)
        
    except ImportError as e:
        logger.error("AI dependencies not installed: %s", e)
        console.print("[red]✗ Error:[/red] AI dependencies not found.")
        console.print("[yellow]Install with:[/yellow] pip install 'heimdall-aws[llm]'")
        console.print("[yellow]Set API key:[/yellow] export OPENAI_API_KEY=sk-...")
        raise click.Abort()
    except Exception as e:
        logger.error("AI ask failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise click.Abort()


@iam.command()
@click.option(
    '--graph',
    type=click.Path(exists=True),
    default='heimdall-privesc.json',
    help='Path to JSON file from detect-privesc (default: heimdall-privesc.json)'
)
@click.option(
    '--ai',
    default='openai',
    type=click.Choice(['openai', 'anthropic']),
    help='AI provider to use'
)
@click.option(
    '--model',
    default=None,
    help='Specific model to use (optional)'
)
@click.option(
    '--top',
    default=5,
    type=int,
    help='Analyze top N critical findings'
)
def analyze(graph: str, ai: str, model: Optional[str], top: int) -> None:
    """
    AI-powered analysis of privilege escalation findings.
    
    Provides detailed explanations, attack scenarios, and remediation guidance.
    
    Example:
        heimdall iam analyze --graph privesc.json --top 10
    """
    try:
        from heimdall.ai_analyzer import AIAnalyzer
        
        console.print(f"[bold cyan]🤖 AI-Powered Analysis ({ai})[/bold cyan]\n")
        
        # Load findings
        with open(graph, 'r') as f:
            data = json.load(f)
        
        findings = data.get('findings', [])
        metadata = data.get('metadata', {})
        
        if not findings:
            console.print("[yellow]No findings to analyze.[/yellow]")
            return
        
        # Filter critical findings
        critical_findings = [f for f in findings if f.get('severity') == 'CRITICAL'][:top]
        
        console.print(f"[dim]Analyzing top {len(critical_findings)} CRITICAL findings...[/dim]\n")
        
        # Initialize AI
        analyzer = AIAnalyzer(provider=ai, model=model)
        
        # Analyze findings
        context = {'account_id': metadata.get('account_id', 'Unknown')}
        analyses = analyzer.analyze_batch(critical_findings, context=context)
        
        # Display results
        for i, (finding, analysis) in enumerate(zip(critical_findings, analyses), 1):
            console.print(f"[bold]{'='*70}[/bold]")
            console.print(f"[bold cyan]Finding {i}: {finding.get('principal_name', 'Unknown')}[/bold cyan]")
            console.print(f"[dim]Method:[/dim] {finding.get('privesc_method', 'Unknown')}")
            console.print(f"[dim]Risk Score:[/dim] {analysis.risk_score}/100\n")
            
            console.print(f"[bold green]Explanation:[/bold green]")
            console.print(f"{analysis.explanation}\n")
            
            console.print(f"[bold yellow]Attack Scenario:[/bold yellow]")
            console.print(f"{analysis.attack_scenario}\n")
            
            console.print(f"[bold red]Business Impact:[/bold red]")
            console.print(f"{analysis.business_impact}\n")
            
            console.print(f"[bold]Detection Difficulty:[/bold] {analysis.detection_difficulty}\n")
            
            console.print(f"[bold blue]Remediation Steps:[/bold blue]")
            for step in analysis.remediation_steps:
                console.print(f"  • {step}")
            
            if analysis.commands:
                console.print(f"\n[bold]Commands:[/bold]")
                for cmd in analysis.commands:
                    console.print(f"  [cyan]$ {cmd}[/cyan]")
            
            console.print()
        
        console.print(f"[bold green]✓ Analysis complete![/bold green]")
        
    except ImportError as e:
        logger.error("AI dependencies not installed: %s", e)
        console.print("[red]✗ Error:[/red] AI dependencies not found.")
        console.print("[yellow]Install with:[/yellow] pip install 'heimdall-aws[llm]'")
        raise click.Abort()
    except Exception as e:
        logger.error("AI analyze failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise click.Abort()


@iam.command()
@click.option(
    '--from',
    'from_principal',
    required=True,
    help='Starting principal (e.g., user/contractor)'
)
@click.option(
    '--goal',
    required=True,
    help='Attack goal (e.g., "admin access", "database")'
)
@click.option(
    '--graph',
    type=click.Path(exists=True),
    default='heimdall-privesc.json',
    help='Path to JSON file from detect-privesc (default: heimdall-privesc.json)'
)
@click.option(
    '--ai',
    default=None,
    type=click.Choice(['openai', 'anthropic']),
    help='AI provider (optional - uses graph analysis if not set)'
)
def simulate_attack(from_principal: str, goal: str, graph: str, ai: str) -> None:
    """
    Simulate a realistic attack scenario.
    
    Shows step-by-step how an attacker could achieve their goal.
    Works with or without AI - uses graph-based analysis by default.
    
    Example:
        heimdall iam simulate-attack --from denizparlak --goal AdminRole
        heimdall iam simulate-attack --from user/contractor --goal admin --ai openai
    """
    try:
        console.print(f"[bold red]🎮 Attack Simulation[/bold red]\n")
        
        # Load graph
        with open(graph, 'r') as f:
            data = json.load(f)
        
        # Support both graph and trust_graph keys
        graph_data = data.get('trust_graph', data.get('graph', {}))
        findings = data.get('findings', [])
        
        # Resolve principal name (support with or without prefix)
        nodes = graph_data.get('nodes', [])
        resolved_principal = None
        
        for node in nodes:
            node_name = node.get('name', '')
            node_id = node.get('id', '')
            # Match by name (without prefix) or full id (with prefix)
            if (node_name.lower() == from_principal.lower() or 
                from_principal.lower() in node_id.lower() or
                node_id.lower().endswith(f'/{from_principal.lower()}')):
                resolved_principal = node
                break
        
        if resolved_principal:
            console.print(f"[dim]Starting from:[/dim] {resolved_principal.get('name')} ({resolved_principal.get('type')})")
            console.print(f"[dim]ARN:[/dim] {resolved_principal.get('id')}")
        else:
            console.print(f"[dim]Starting from:[/dim] {from_principal}")
            console.print(f"[yellow]⚠ Principal not found in graph, using as-is[/yellow]")
        
        console.print(f"[dim]Goal:[/dim] {goal}\n")
        
        # Find relevant findings for this principal
        principal_findings = [
            f for f in findings 
            if from_principal.lower() in f.get('principal', '').lower() or
               from_principal.lower() in f.get('principal_name', '').lower()
        ]
        
        if ai:
            # Use AI for advanced simulation
            try:
                from heimdall.ai_analyzer import AIAnalyzer
                console.print("[dim]Using AI-powered simulation...[/dim]\n")
                analyzer = AIAnalyzer(provider=ai)
                simulation = analyzer.simulate_attack(from_principal, goal, graph_data)
                console.print(simulation)
            except ValueError as e:
                if 'API_KEY' in str(e):
                    console.print(f"[yellow]⚠ {e}[/yellow]")
                    console.print("[dim]Falling back to graph-based analysis...[/dim]\n")
                    ai = None  # Fall back to graph analysis
                else:
                    raise
        
        if not ai:
            # Graph-based analysis (no AI needed)
            console.print("[bold cyan]📊 Graph-Based Attack Path Analysis[/bold cyan]\n")
            
            if not principal_findings:
                console.print(f"[green]✓ No privilege escalation paths found for {from_principal}[/green]")
                console.print("[dim]This principal cannot escalate privileges based on current permissions.[/dim]")
                return
            
            # Group by severity
            by_severity = {}
            for f in principal_findings:
                sev = f.get('severity', 'UNKNOWN')
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(f)
            
            console.print(f"[bold]Found {len(principal_findings)} attack paths:[/bold]\n")
            
            # Show attack paths by severity
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            severity_icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
            
            for sev in severity_order:
                if sev in by_severity:
                    console.print(f"{severity_icons.get(sev, '⚪')} [bold]{sev}[/bold] ({len(by_severity[sev])} paths)")
                    for i, f in enumerate(by_severity[sev][:3], 1):  # Show top 3 per severity
                        method = f.get('privesc_method', 'unknown')
                        target = f.get('target_role_name', 'N/A')
                        actions = f.get('required_actions', [])
                        
                        console.print(f"   {i}. [cyan]{method}[/cyan]")
                        if target and target != 'N/A':
                            console.print(f"      → Target: [magenta]{target}[/magenta]")
                        if actions:
                            console.print(f"      → Actions: [dim]{', '.join(actions[:3])}[/dim]")
                    
                    if len(by_severity[sev]) > 3:
                        console.print(f"      [dim]... and {len(by_severity[sev]) - 3} more[/dim]")
                    console.print()
            
            # Exploit command examples for each method
            EXPLOIT_EXAMPLES = {
                'passrole_lambda': '''aws lambda create-function \\
  --function-name privesc-function \\
  --role {role_arn} \\
  --runtime python3.9 \\
  --handler index.handler \\
  --zip-file fileb://exploit.zip

# exploit.zip contains: import boto3; print(boto3.client('sts').get_caller_identity())''',
                
                'passrole_ec2': '''aws ec2 run-instances \\
  --image-id ami-0abcdef1234567890 \\
  --instance-type t2.micro \\
  --iam-instance-profile Name={role_name} \\
  --user-data '#!/bin/bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}' ''',
                
                'attach_user_policy': '''aws iam attach-user-policy \\
  --user-name {principal_name} \\
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess''',
                
                'attach_role_policy': '''aws iam attach-role-policy \\
  --role-name {role_name} \\
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess''',
                
                'put_user_policy': '''aws iam put-user-policy \\
  --user-name {principal_name} \\
  --policy-name privesc-policy \\
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' ''',
                
                'create_policy_version': '''aws iam create-policy-version \\
  --policy-arn {policy_arn} \\
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \\
  --set-as-default''',
                
                'update_assume_role_policy': '''aws iam update-assume-role-policy \\
  --role-name {role_name} \\
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::{account_id}:user/{principal_name}"},"Action":"sts:AssumeRole"}]}' 

# Then assume the role:
aws sts assume-role --role-arn {role_arn} --role-session-name privesc''',
                
                'create_access_key': '''aws iam create-access-key --user-name {target_user}

# Use the new credentials:
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...''',
                
                'update_login_profile': '''aws iam update-login-profile \\
  --user-name {target_user} \\
  --password "NewPassword123!" \\
  --no-password-reset-required

# Now login to AWS Console as that user''',
                
                'secretsmanager_get_value': '''aws secretsmanager get-secret-value \\
  --secret-id production/database/credentials

# Extract credentials from JSON response''',
                
                'ssm_get_parameter': '''aws ssm get-parameter \\
  --name /production/api/secret-key \\
  --with-decryption''',
                
                'passrole_glue': '''aws glue create-job \\
  --name privesc-job \\
  --role {role_arn} \\
  --command '{"Name":"pythonshell","ScriptLocation":"s3://bucket/exploit.py"}' ''',
                
                'passrole_cloudformation': '''aws cloudformation create-stack \\
  --stack-name privesc-stack \\
  --template-body file://privesc-template.yaml \\
  --role-arn {role_arn} \\
  --capabilities CAPABILITY_IAM''',
            }
            
            # Goal matching
            goal_matches = [
                f for f in principal_findings
                if goal.lower() in f.get('target_role_name', '').lower() or
                   goal.lower() in f.get('privesc_method', '').lower()
            ]
            
            if goal_matches:
                console.print(f"[bold green]🎯 Direct path to '{goal}' found![/bold green]")
                for f in goal_matches[:2]:
                    method = f.get('privesc_method')
                    target_role = f.get('target_role_name', 'TargetRole')
                    console.print(f"   Method: [cyan]{method}[/cyan]")
                    console.print(f"   Target: [magenta]{target_role}[/magenta]")
                
                # Show exploit example for the first matching method
                console.print(f"\n[bold red]💀 Exploit Command Example:[/bold red]")
                first_method = goal_matches[0].get('privesc_method', '')
                target_role = goal_matches[0].get('target_role_name', 'TargetRole')
                
                if first_method in EXPLOIT_EXAMPLES:
                    # Get account ID from resolved principal
                    account_id = '123456789012'
                    if resolved_principal:
                        arn = resolved_principal.get('id', '')
                        if 'arn:aws:iam::' in arn:
                            account_id = arn.split(':')[4]
                    
                    example = EXPLOIT_EXAMPLES[first_method].format(
                        role_arn=f'arn:aws:iam::{account_id}:role/{target_role}',
                        role_name=target_role,
                        principal_name=from_principal,
                        account_id=account_id,
                        policy_arn=f'arn:aws:iam::{account_id}:policy/SomePolicy',
                        target_user='target-user'
                    )
                    console.print(f"[dim]{example}[/dim]")
                else:
                    console.print(f"[dim]# No specific exploit example for {first_method}[/dim]")
                    console.print(f"[dim]# Check: https://github.com/RhinoSecurityLabs/pacu[/dim]")
                
                console.print(f"\n[yellow]⚠️  For educational/authorized testing only![/yellow]")
            else:
                console.print(f"[yellow]⚠ No direct path to '{goal}' found[/yellow]")
                console.print("[dim]Try --ai openai for advanced multi-hop analysis[/dim]")
        
    except ImportError as e:
        logger.error("AI dependencies not installed: %s", e)
        console.print("[red]✗ Error:[/red] AI dependencies not found.")
        console.print("[yellow]Install with:[/yellow] pip install 'heimdall-aws[llm]'")
        raise click.Abort()
    except Exception as e:
        logger.error("Attack simulation failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise click.Abort()


# Summary Command - Quick Risk Posture Overview (v1.3.0)
# Logic moved to commands/summary.py
@iam.command()
@click.option('--graph', type=click.Path(exists=True), default='heimdall-privesc.json', help='Path to JSON file from detect-privesc')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'compact']), default='table', help='Output format')
def summary(graph: str, output_format: str) -> None:
    """
    Show quick security posture summary.
    
    Displays key metrics, risk distribution, and account overview.
    Perfect for CI/CD dashboards and quick security checks.
    
    Example:
        heimdall iam summary
        heimdall iam summary --format compact
    """
    try:
        from heimdall.commands.summary import run_summary
        run_summary(graph, output_format)
    except Exception as e:
        logger.error("Summary command failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise click.Abort()


# Show-Principal Command - Principal Deep Dive (v1.3.0)
# Logic moved to commands/show_principal.py
@iam.command()
@click.option('--graph', type=click.Path(exists=True), default='heimdall-privesc.json', help='Path to JSON file from detect-privesc')
@click.option('--name', required=True, help='Principal name (e.g., denizparlak or arn:aws:iam::...)')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']), default='table', help='Output format')
def show_principal(graph: str, name: str, output_format: str) -> None:
    """
    Deep dive into a specific IAM principal.
    
    Shows all privilege escalation paths, permissions, and attack surface.
    
    Example:
        heimdall iam show-principal --name denizparlak
    """
    try:
        from heimdall.commands.show_principal import run_show_principal
        run_show_principal(graph, name, output_format)
    except Exception as e:
        logger.error("Show-principal command failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise click.Abort()


# Diff Command - Compare Two Scans (v1.3.0 - PR Simulator Foundation!)
# Logic moved to commands/diff.py
@iam.command()
@click.option('--before', 'baseline', type=click.Path(exists=True), required=True, help='Baseline scan (older)')
@click.option('--after', 'current', type=click.Path(exists=True), required=True, help='Current scan (newer)')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'github']), default='table', help='Output format')
@click.option('--output', 'output_file', type=click.Path(), default=None, help='Save output to file')
@click.option('--fail-on-new-critical', is_flag=True, help='Exit with code 2 if new CRITICAL findings (CI/CD mode)')
@click.option('--fail-on-new-high', is_flag=True, help='Exit with code 2 if new HIGH+ findings (CI/CD mode)')
def diff(baseline: str, current: str, output_format: str, output_file: Optional[str], 
         fail_on_new_critical: bool, fail_on_new_high: bool) -> None:
    """
    Compare two IAM scans and show security changes.
    
    Foundation for PR Attack Simulator. Shows new/resolved findings,
    risk score changes, and principal modifications.
    
    Example:
        heimdall iam diff --before baseline.json --after current.json
        heimdall iam diff --before old.json --after new.json --format github
    """
    try:
        from heimdall.commands.diff import run_diff
        run_diff(baseline, current, output_format, output_file, fail_on_new_critical, fail_on_new_high)
    except SystemExit:
        raise
    except Exception as e:
        logger.error("Diff command failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise click.Abort()


# Report Command - HTML Report Generator (v1.3.0)
# Logic moved to commands/report.py
@iam.command()
@click.option('--graph', type=click.Path(exists=True), required=True, help='Path to graph JSON file')
@click.option('--output', default='heimdall-report.html', help='Output HTML file path')
@click.option('--open', 'open_browser', is_flag=True, help='Open report in browser')
def report(graph: str, output: str, open_browser: bool) -> None:
    """Generate HTML security report. Example: heimdall iam report --graph scan.json --open"""
    try:
        from heimdall.commands.report import run_report
        run_report(graph, output, open_browser)
    except Exception as e:
        logger.error("Report generation failed: %s", e, exc_info=True)
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        raise click.Abort()


# Cross-Service Command - Cross-service privilege escalation analysis
from heimdall.commands.cross_service import cross_service
iam.add_command(cross_service)


# Dashboard Command - Security posture overview
from heimdall.commands.dashboard import dashboard
main.add_command(dashboard)


# Terraform Attack Path Engine
from heimdall.commands.terraform import terraform
main.add_command(terraform)


# ═══════════════════════════════════════════════════════════════════════════════
# Optional Command Registration
# ═══════════════════════════════════════════════════════════════════════════════
if PR_SIMULATOR_AVAILABLE:
    main.add_command(pr_simulate)


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    main()
