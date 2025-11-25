# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                           ᚷᛚᛖᛁᛈᚾᛁᚱ • GLEIPNIR
#                    The Unbreakable Chain That Binds Fenrir
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "Forged by the dwarves from six impossible things: the sound of a
#    cat's footsteps, the beard of a woman, the roots of a mountain,
#    the sinews of a bear, the breath of a fish, and the spittle of a bird."
#
#   Like Gleipnir binding the great wolf, this module chains together
#   isolated findings into unbreakable attack narratives.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import json
import logging
from typing import Optional, List, Dict

from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.text import Text

from heimdall.cli_utils import console, SEVERITY_COLORS

logger = logging.getLogger(__name__)


def run_attack_chain(
    graph: str,
    from_principal: Optional[str],
    output_format: str,
    top_n: int,
    show_steps: bool,
) -> None:
    """
    Analyze and display attack chains.
    
    Args:
        graph: Path to graph JSON file
        from_principal: Optional filter for specific principal
        output_format: Output format (table/json/tree)
        top_n: Number of top chains to show
        show_steps: Show detailed steps
    """
    from heimdall.attack_chain import AttackChainBuilder
    
    console.print("\n[bold cyan]🔗 Attack Chain Analysis[/bold cyan]\n")
    
    # Load data
    with open(graph) as f:
        data = json.load(f)
    
    findings = data.get('findings', data.get('risky_paths', []))
    
    if not findings:
        console.print("[yellow]No findings to analyze[/yellow]")
        return
    
    # Build chains
    builder = AttackChainBuilder(graph_data=data.get('trust_graph', {}))
    
    if from_principal:
        chains = builder.build_for_principal(findings, from_principal)
        console.print(f"[dim]Analyzing chains for: {from_principal}[/dim]\n")
    else:
        chains = builder.build_from_findings(findings)
    
    if not chains:
        console.print("[yellow]No attack chains found[/yellow]")
        return
    
    # Limit results
    chains = chains[:top_n]
    
    # Output
    if output_format == 'json':
        _output_json(chains)
    elif output_format == 'tree':
        _output_tree(chains, show_steps)
    else:
        _output_table(chains, show_steps)
    
    # Summary
    _show_summary(chains)


def _output_json(chains: List) -> None:
    """Output as JSON."""
    output = {
        'total_chains': len(chains),
        'chains': [c.to_dict() for c in chains]
    }
    console.print_json(data=output)


def _output_tree(chains: List, show_steps: bool) -> None:
    """Output as tree visualization."""
    for chain in chains:
        color = SEVERITY_COLORS.get(str(chain.severity), 'white')
        
        # Create tree
        tree = Tree(f"[bold {color}]{chain.title}[/bold {color}]")
        tree.add(f"[dim]ID:[/dim] {chain.chain_id}")
        tree.add(f"[dim]Category:[/dim] {chain.category}")
        tree.add(f"[dim]Risk Score:[/dim] [{color}]{chain.risk_score}/100[/{color}]")
        tree.add(f"[dim]Complexity:[/dim] {chain.complexity} ({chain.total_steps} steps)")
        
        # Source → Target
        path_branch = tree.add("[bold]Attack Path[/bold]")
        path_branch.add(f"📍 Source: [cyan]{chain.source_principal}[/cyan]")
        path_branch.add(f"🎯 Target: [red]{chain.target_objective}[/red]")
        
        # Steps
        if show_steps and chain.steps:
            steps_branch = tree.add("[bold]Steps[/bold]")
            for step in chain.steps:
                step_color = SEVERITY_COLORS.get(str(step.severity), 'white')
                step_text = f"[{step_color}]Step {step.step_number}:[/{step_color}] {step.description}"
                step_node = steps_branch.add(step_text)
                step_node.add(f"[dim]Action: {step.action}[/dim]")
                if step.assumed_role:
                    step_node.add(f"[dim]Executing as: {step.assumed_role}[/dim]")
        
        # Blast radius
        if chain.blast_radius:
            br = chain.blast_radius
            br_branch = tree.add(f"[bold]💥 Blast Radius: {br.total_score}/100[/bold]")
            if br.admin_path_exists:
                br_branch.add("[red]⚠️ Admin access path exists![/red]")
            if br.services_affected:
                services = ", ".join(s.service for s in br.services_affected[:5])
                br_branch.add(f"Services: {services}")
        
        # Quick win
        if chain.quick_win:
            tree.add(f"[green]🎯 Quick Fix:[/green] {chain.quick_win[:80]}...")
        
        console.print(tree)
        console.print()


def _output_table(chains: List, show_steps: bool) -> None:
    """Output as table."""
    # Summary table
    table = Table(title="Attack Chains", show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Title", width=35)
    table.add_column("Source", width=20)
    table.add_column("Target", width=20)
    table.add_column("Steps", width=6, justify="center")
    table.add_column("Risk", width=8, justify="center")
    table.add_column("Blast", width=8, justify="center")
    
    for i, chain in enumerate(chains, 1):
        color = SEVERITY_COLORS.get(str(chain.severity), 'white')
        blast = chain.blast_radius.total_score if chain.blast_radius else 0
        
        table.add_row(
            str(i),
            chain.title[:33] + ".." if len(chain.title) > 35 else chain.title,
            chain.source_principal[:18] + ".." if len(chain.source_principal) > 20 else chain.source_principal,
            chain.target_objective[:18] + ".." if len(chain.target_objective) > 20 else chain.target_objective,
            str(chain.total_steps),
            f"[{color}]{chain.risk_score}[/{color}]",
            f"[{'red' if blast > 70 else 'yellow' if blast > 40 else 'green'}]{blast}[/]",
        )
    
    console.print(table)
    console.print()
    
    # Show detailed steps if requested
    if show_steps:
        console.print("[bold]Detailed Attack Steps:[/bold]\n")
        for chain in chains[:3]:  # Show top 3 in detail
            _show_chain_detail(chain)


def _show_chain_detail(chain) -> None:
    """Show detailed chain steps."""
    color = SEVERITY_COLORS.get(str(chain.severity), 'white')
    
    # Header panel
    header = f"""[bold]{chain.title}[/bold]
[dim]Category:[/dim] {chain.category} | [dim]Risk:[/dim] [{color}]{chain.risk_score}/100[/{color}] | [dim]Complexity:[/dim] {chain.complexity}

[dim]Source:[/dim] [cyan]{chain.source_principal}[/cyan]
[dim]Target:[/dim] [red]{chain.target_objective}[/red]"""
    
    console.print(Panel(header, border_style=color))
    
    # Steps
    for step in chain.steps:
        step_color = SEVERITY_COLORS.get(str(step.severity), 'white')
        prefix = "├─" if step.step_number < len(chain.steps) else "└─"
        
        console.print(f"  {prefix} [bold]Step {step.step_number}:[/bold] {step.description}")
        console.print(f"  │   [dim]Action:[/dim] [{step_color}]{step.action}[/{step_color}]")
        if step.target:
            console.print(f"  │   [dim]Target:[/dim] {step.target}")
        if step.assumed_role:
            console.print(f"  │   [dim]Executing as:[/dim] [yellow]{step.assumed_role}[/yellow]")
        console.print()
    
    # Quick win
    if chain.quick_win:
        console.print(f"  [green]🎯 Quick Fix:[/green] {chain.quick_win}\n")
    
    console.print("─" * 60 + "\n")


def _show_summary(chains: List) -> None:
    """Show summary statistics."""
    if not chains:
        return
    
    total = len(chains)
    critical = sum(1 for c in chains if str(c.severity) == 'CRITICAL')
    high = sum(1 for c in chains if str(c.severity) == 'HIGH')
    avg_blast = sum(c.blast_radius.total_score for c in chains if c.blast_radius) // max(len(chains), 1)
    admin_paths = sum(1 for c in chains if c.blast_radius and c.blast_radius.admin_path_exists)
    
    # Categories
    categories = {}
    for c in chains:
        cat = str(c.category)
        categories[cat] = categories.get(cat, 0) + 1
    
    console.print(Panel(f"""[bold]Summary[/bold]
    
Total Chains: [cyan]{total}[/cyan]
Critical: [red]{critical}[/red] | High: [orange1]{high}[/orange1]
Avg Blast Radius: [yellow]{avg_blast}/100[/yellow]
Admin Access Paths: [red]{admin_paths}[/red]

[bold]By Category:[/bold]
{chr(10).join(f'  • {k}: {v}' for k, v in sorted(categories.items(), key=lambda x: -x[1]))}
""", title="🔗 Attack Chain Analysis", border_style="cyan"))
