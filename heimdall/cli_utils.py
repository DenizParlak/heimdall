# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                            ᚱᚢᚾᛁᚱ • THE RUNES
#                    Sacred Symbols of Power and Knowledge
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "Odin hung nine nights from Yggdrasil, pierced by his own spear,
#    to gain the wisdom of the runes - tools of creation and power."
#
#   These utilities are the runes of Heimdall - fundamental symbols
#   that empower all commands with their ancient magic.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import json
import logging
from typing import Dict, Any

import click
from rich.console import Console

# ᚠᛖᚺᚢ • Fehu - The Rune of Wealth (Type Definitions)
GraphData = Dict[str, Any]
Finding = Dict[str, Any]
PathInfo = Dict[str, Any]

# ᚢᚱᚢᛉ • Uruz - The Rune of Strength (Constants)
DEFAULT_OUTPUT_FILE = 'heimdall-graph.json'
DEFAULT_PRIVESC_OUTPUT = 'heimdall-privesc.json'
DEFAULT_MAX_DEPTH = 5
DEFAULT_TABLE_LIMIT = 50
SCAN_TIMEOUT_SECONDS = 300

# ᛏᛁᚹᚨᛉ • Tiwaz - Exit Codes for CI/CD Integration
class ExitCode:
    """
    Standardized exit codes for CI/CD integration.
    
    Usage:
        sys.exit(ExitCode.CRITICAL_FINDINGS)
    
    CI/CD Example:
        heimdall iam detect-privesc
        if [ $? -eq 2 ]; then echo "Critical findings!"; fi
    """
    SUCCESS = 0              # No issues found
    ERROR = 1                # General error (invalid args, file not found, etc.)
    CRITICAL_FINDINGS = 2    # Critical severity findings detected
    HIGH_FINDINGS = 3        # High severity findings detected
    MEDIUM_FINDINGS = 4      # Medium severity findings detected
    AWS_ERROR = 10           # AWS API/credential error
    TIMEOUT = 11             # Operation timeout

# Severity levels in order of criticality
SEVERITY_ORDER = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN')

# Rich console color mapping for severity levels
SEVERITY_COLORS: Dict[str, str] = {
    'CRITICAL': 'red',
    'HIGH': 'orange1',
    'MEDIUM': 'yellow',
    'LOW': 'blue',
    'INFO': 'dim',
    'UNKNOWN': 'white',
}

# Severity emoji indicators
SEVERITY_EMOJI: Dict[str, str] = {
    'CRITICAL': '🔴',
    'HIGH': '🟠',
    'MEDIUM': '🟡',
    'LOW': '🟢',
    'INFO': '⚪',
    'UNKNOWN': '⚫',
}

# ═══════════════════════════════════════════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════════════════════════════════════════
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# Console Configuration
# ═══════════════════════════════════════════════════════════════════════════════
console = Console()


def set_console_theme(*, no_color: bool = False) -> None:
    """
    Configure global console instance with theme settings.
    
    Args:
        no_color: If True, disable all colored/styled output (useful for CI/CD)
    """
    global console
    console = Console(force_terminal=not no_color, no_color=no_color)


# ═══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════════
def truncate(text: str, max_length: int, suffix: str = '..') -> str:
    """
    Truncate text to max_length, adding suffix if truncated.
    
    Args:
        text: Input string to truncate
        max_length: Maximum allowed length including suffix
        suffix: String to append when truncated (default: '..')
    
    Returns:
        Truncated string with suffix, or original if within limit
    """
    text = str(text) if text else ''
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def get_severity_color(severity: str) -> str:
    """Get Rich color name for a severity level."""
    return SEVERITY_COLORS.get(severity.upper(), 'white')


def get_severity_emoji(severity: str) -> str:
    """Get emoji indicator for a severity level."""
    return SEVERITY_EMOJI.get(severity.upper(), '⚫')


def format_severity(severity: str, *, with_emoji: bool = False) -> str:
    """
    Format severity level with Rich markup for colored display.
    
    Args:
        severity: Severity level string (CRITICAL, HIGH, etc.)
        with_emoji: If True, prepend emoji indicator
    
    Returns:
        Rich-formatted severity string
    """
    color = get_severity_color(severity)
    prefix = f"{get_severity_emoji(severity)} " if with_emoji else ""
    return f"{prefix}[{color}]{severity.upper()}[/{color}]"


def load_graph_file(filepath: str) -> GraphData:
    """
    Load and parse a Heimdall graph JSON file.
    
    Supports both 'graph' and 'trust_graph' keys for backward compatibility.
    
    Args:
        filepath: Path to JSON file
    
    Returns:
        Parsed graph data dictionary
    
    Raises:
        click.ClickException: If file cannot be read or parsed
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        raise click.ClickException(f"File not found: {filepath}")
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in {filepath}: {e}")


def extract_graph_data(data: GraphData) -> GraphData:
    """
    Extract trust graph from loaded data, supporting multiple key formats.
    
    Args:
        data: Loaded JSON data from graph file
    
    Returns:
        Trust graph dictionary (nodes, links, stats)
    """
    return data.get('trust_graph', data.get('graph', {}))


# ᚨᛊᚲᛁᛁ • ASCII Art Banner
HEIMDALL_BANNER = """
[bold cyan]
    ██╗  ██╗███████╗██╗███╗   ███╗██████╗  █████╗ ██╗     ██╗     
    ██║  ██║██╔════╝██║████╗ ████║██╔══██╗██╔══██╗██║     ██║     
    ███████║█████╗  ██║██╔████╔██║██║  ██║███████║██║     ██║     
    ██╔══██║██╔══╝  ██║██║╚██╔╝██║██║  ██║██╔══██║██║     ██║     
    ██║  ██║███████╗██║██║ ╚═╝ ██║██████╔╝██║  ██║███████╗███████╗
    ╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
[/bold cyan]
[dim]                 ᛒᛁᚠᚱᛟᛊᛏ • The Rainbow Bridge Guardian 🌈[/dim]
"""

HEIMDALL_BANNER_SMALL = "[bold cyan]⚔️  HEIMDALL[/bold cyan] [dim]• The Bifröst Guardian[/dim]"


def print_banner(*, small: bool = False) -> None:
    """Print the Heimdall ASCII banner."""
    if small:
        console.print(HEIMDALL_BANNER_SMALL)
    else:
        console.print(HEIMDALL_BANNER)


def print_version_info() -> None:
    """Print detailed version and system information."""
    import platform
    import sys
    from heimdall import __version__
    
    console.print(HEIMDALL_BANNER)
    console.print(f"[bold cyan]Version:[/bold cyan]     {__version__}")
    console.print(f"[bold cyan]Python:[/bold cyan]      {sys.version.split()[0]}")
    console.print(f"[bold cyan]Platform:[/bold cyan]    {platform.system()} {platform.release()}")
    console.print(f"[bold cyan]Machine:[/bold cyan]     {platform.machine()}")
    console.print()
    
    # Check AWS credentials
    try:
        import boto3
        session = boto3.Session()
        creds = session.get_credentials()
        if creds:
            console.print("[bold cyan]AWS Status:[/bold cyan]  [green]✓ Credentials configured[/green]")
            if session.profile_name:
                console.print(f"[bold cyan]AWS Profile:[/bold cyan] {session.profile_name}")
        else:
            console.print("[bold cyan]AWS Status:[/bold cyan]  [yellow]⚠ No credentials found[/yellow]")
    except Exception:
        console.print("[bold cyan]AWS Status:[/bold cyan]  [red]✗ boto3 not available[/red]")
    
    console.print()
    console.print("[dim]Run 'heimdall doctor' to check system health[/dim]")
    console.print("[dim]Run 'heimdall iam --help' for available commands[/dim]")
