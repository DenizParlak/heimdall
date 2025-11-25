# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                     ᛒᛁᚠᚱᛟᛊᛏ ᚠᛖᚱᛞ • BIFRÖST JOURNEY
#                       A Crossing Between Two Realms
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "The rainbow bridge trembles as travelers seek passage from one
#    realm to another, watched always by Heimdall's unblinking eyes."
#
#   This command traces the path between two principals - revealing
#   every step of the journey across the bridge of trust.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import json
import logging

from rich.tree import Tree

from heimdall.cli_utils import (
    console, set_console_theme, format_severity, get_severity_color
)
from heimdall.graph.analyzer import PathAnalyzer

logger = logging.getLogger(__name__)


def run_path(
    graph: str,
    source: str,
    target: str,
    max_depth: int,
    tree_view: bool,
    no_color: bool
) -> None:
    """
    Find privilege escalation path between two principals.
    
    Args:
        graph: Path to graph JSON file
        source: Source principal
        target: Target principal
        max_depth: Maximum path length
        tree_view: Display as tree structure
        no_color: Disable colored output
    """
    set_console_theme(no_color=no_color)
    
    logger.info("Finding path: source=%s, target=%s, max_depth=%d", source, target, max_depth)
    console.print("\n[bold cyan]🛤️  Heimdall Path Finder[/bold cyan]\n")
    
    # Load graph
    with open(graph) as f:
        data = json.load(f)
    
    graph_data = data.get('trust_graph', data.get('graph', {}))
    
    # Analyze paths
    analyzer = PathAnalyzer(graph_data)
    paths = analyzer.find_paths(source, target, max_depth=max_depth)
    
    if not paths:
        console.print(f"[yellow]No path found from {source} to {target}[/yellow]\n")
        return
    
    console.print(f"[green]Found {len(paths)} path(s):[/green]\n")
    
    for i, path_data in enumerate(paths[:10], 1):
        if tree_view:
            _display_path_tree(i, path_data)
        else:
            _display_path_linear(i, path_data)
    
    if len(paths) > 10:
        console.print(f"[dim]... and {len(paths) - 10} more paths[/dim]\n")


def _display_path_tree(index: int, path_data: dict) -> None:
    """Display path as tree structure."""
    path = path_data['path']
    risk_level = path_data.get('risk', 'UNKNOWN')
    
    console.print(f"[bold]Path {index}[/bold] ({len(path) - 1} hops) - {format_severity(risk_level)}")
    
    tree = Tree(f"[cyan]{path[0]}[/cyan]")
    current = tree
    
    for j in range(1, len(path)):
        color_map = {0: 'green', 1: 'yellow', 2: 'orange1', 3: 'red'}
        hop_color = color_map.get(min(j, 3), 'white')
        current = current.add(f"[{hop_color}]↓ AssumeRole[/{hop_color}]")
        current = current.add(f"[cyan]{path[j]}[/cyan]")
    
    console.print(tree)
    
    if 'reason' in path_data:
        console.print(f"  [dim]Reason: {path_data['reason']}[/dim]")
    console.print()


def _display_path_linear(index: int, path_data: dict) -> None:
    """Display path in linear format."""
    path = path_data['path']
    risk_level = path_data.get('risk', 'UNKNOWN')
    
    console.print(f"[bold]Path {index}[/bold] ({len(path) - 1} hops):")
    
    for j, node in enumerate(path):
        if j < len(path) - 1:
            console.print(f"  {node}")
            console.print(f"  [dim]↓ AssumeRole[/dim]")
        else:
            console.print(f"  {node}")
    
    console.print(f"\n  Risk: {format_severity(risk_level)}")
    
    if 'reason' in path_data:
        console.print(f"  Reason: {path_data['reason']}")
    
    console.print()
