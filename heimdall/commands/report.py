# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                              ᛊᚨᚷᚨ • SAGA
#                    Goddess of Poetry and History
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "Saga dwells in Sökkvabekkr, where she and Odin drink together daily,
#    and she records the great tales in eternal scrolls."
#
#   This module weaves your security findings into illuminated manuscripts,
#   transforming raw data into chronicles worthy of the Æsir.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import json
import logging

from heimdall.cli_utils import console

logger = logging.getLogger(__name__)


def run_report(graph: str, output: str, open_browser: bool) -> None:
    """
    Generate HTML security report.
    
    Args:
        graph: Path to graph JSON file
        output: Output HTML file path
        open_browser: Open report in browser after generation
    """
    from heimdall.report_generator import generate_html_report
    
    console.print("[bold cyan]📊 Generating HTML Report...[/bold cyan]\n")
    
    # Load data
    with open(graph, 'r') as f:
        data = json.load(f)
    
    # Generate report
    generate_html_report(data, output)
    
    console.print(f"[bold green]✓ Report generated:[/bold green] {output}")
    
    # Open in browser if requested
    if open_browser:
        import webbrowser
        import os
        abs_path = os.path.abspath(output)
        webbrowser.open(f'file://{abs_path}')
        console.print(f"[dim]Opened in browser[/dim]")
