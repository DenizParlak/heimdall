# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                       ᛁᚷᚷᛞᚱᚨᛊᛁᛚ • YGGDRASIL'S BRANCHES
#                         The World Tree's Many Paths
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "Yggdrasil's branches spread across all existence, connecting the
#    Nine Realms with countless hidden pathways."
#
#   This command reveals all the branches - every trust relationship
#   and assume-role path that connects your principals.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import csv
import json
import logging
import sys
from typing import Optional, List, Dict

from rich.table import Table

from heimdall.cli_utils import console, set_console_theme, SEVERITY_COLORS

logger = logging.getLogger(__name__)


def run_list_paths(
    graph: str,
    from_type: str,
    to_type: str,
    direct_only: bool,
    output_format: str,
    output_file: Optional[str],
    no_color: bool
) -> None:
    """
    List all assume-role paths between principal types.
    
    Args:
        graph: Path to graph JSON file
        from_type: Source principal type
        to_type: Target principal type
        direct_only: Show only direct paths
        output_format: Output format (table/csv/json)
        output_file: Save to file
        no_color: Disable colored output
    """
    set_console_theme(no_color=no_color)
    
    logger.info("Listing paths: graph=%s, from=%s, to=%s", graph, from_type, to_type)
    
    if output_format == 'table':
        console.print("\n[bold cyan]📋 Heimdall Path Lister[/bold cyan]\n")
    
    # Load graph
    with open(graph) as f:
        data = json.load(f)
    
    graph_data = data.get('trust_graph', data.get('graph', {}))
    
    # Find paths
    paths_found = _find_paths(graph_data, from_type, to_type)
    
    if not paths_found:
        if output_format == 'table':
            console.print(f"[yellow]No paths found from {from_type} to {to_type}[/yellow]\n")
        return
    
    # Output based on format
    if output_format == 'json':
        _output_json(paths_found, from_type, to_type, output_file)
    elif output_format == 'csv':
        _output_csv(paths_found, output_file)
    else:
        _output_table(paths_found)


def _find_paths(graph_data: Dict, from_type: str, to_type: str) -> List[Dict]:
    """Find paths matching criteria using NetworkX."""
    import networkx as nx
    G = nx.node_link_graph(graph_data, edges='links')
    
    paths_found = []
    
    for node in G.nodes():
        node_data = G.nodes[node]
        source_type = node_data.get('type')
        
        if from_type != 'all' and source_type != from_type:
            continue
        
        for neighbor in G.neighbors(node):
            neighbor_data = G.nodes[neighbor]
            target_type = neighbor_data.get('type')
            
            if to_type != 'all' and target_type != to_type:
                continue
            
            edge_data = G.get_edge_data(node, neighbor)
            paths_found.append({
                'source': node,
                'source_name': node_data.get('name', 'unknown'),
                'source_type': source_type,
                'target': neighbor,
                'target_name': neighbor_data.get('name', 'unknown'),
                'target_type': target_type,
                'relationship': edge_data.get('type', 'unknown'),
                'risk': edge_data.get('risk', 'UNKNOWN')
            })
    
    return paths_found


def _output_json(paths: List[Dict], from_type: str, to_type: str, output_file: Optional[str]) -> None:
    """Output paths as JSON."""
    output_data = {
        'total_paths': len(paths),
        'filters': {'from_type': from_type, 'to_type': to_type},
        'paths': paths
    }
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        console.print(f"[green]✓[/green] Exported {len(paths)} paths to {output_file}")
    else:
        console.print_json(data=output_data)


def _output_csv(paths: List[Dict], output_file: Optional[str]) -> None:
    """Output paths as CSV."""
    fieldnames = ['source_type', 'source_name', 'target_type', 'target_name', 'relationship', 'risk']
    
    if output_file:
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for path in paths:
                writer.writerow({k: path.get(k, '') for k in fieldnames})
        console.print(f"[green]✓[/green] Exported {len(paths)} paths to {output_file}")
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        for path in paths:
            writer.writerow({k: path.get(k, '') for k in fieldnames})


def _output_table(paths: List[Dict]) -> None:
    """Output paths as rich table."""
    console.print(f"[green]Found {len(paths)} path(s):[/green]\n")
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Source", style="dim", width=30)
    table.add_column("Target", style="dim", width=30)
    table.add_column("Type", width=20)
    table.add_column("Risk", width=10)
    
    for path in paths:
        risk_color = SEVERITY_COLORS.get(path['risk'], 'white')
        
        table.add_row(
            f"{path['source_type']}/{path['source_name']}",
            f"{path['target_type']}/{path['target_name']}",
            path['relationship'],
            f"[{risk_color}]{path['risk']}[/{risk_color}]"
        )
    
    console.print(table)
    console.print(f"\n[dim]Total: {len(paths)} paths[/dim]\n")
    
    # Summary stats
    type_summary = {}
    for path in paths:
        key = f"{path['source_type']} → {path['target_type']}"
        type_summary[key] = type_summary.get(key, 0) + 1
    
    console.print("[bold]Path Type Summary:[/bold]")
    for path_type, count in sorted(type_summary.items(), key=lambda x: -x[1]):
        console.print(f"  {path_type}: {count}")
    console.print()
