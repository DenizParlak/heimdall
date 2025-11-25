"""
PR Simulator CLI

Main command-line interface for PR security simulation.

Usage:
    heimdall pr-simulate --current scan.json --terraform tfplan.json --output result.json
"""

import click
import json
import sys
from pathlib import Path
from .terraform_parser import TerraformParser
from .state_diff import StateDiffEngine
from .attack_simulator import AttackPathSimulator


@click.command(name='pr-simulate')
@click.option(
    '--current-state',
    '-c',
    required=True,
    type=click.Path(exists=True),
    help='Path to current state Heimdall scan output (JSON)'
)
@click.option(
    '--terraform-plan',
    '-t',
    type=click.Path(exists=True),
    help='Path to Terraform plan JSON file'
)
@click.option(
    '--cloudformation-template',
    '-cf',
    type=click.Path(exists=True),
    help='Path to CloudFormation template file (not yet implemented)'
)
@click.option(
    '--output',
    '-o',
    type=click.Path(),
    help='Output file for analysis results (JSON)'
)
@click.option(
    '--format',
    '-f',
    type=click.Choice(['json', 'text', 'github'], case_sensitive=False),
    default='text',
    help='Output format'
)
@click.option(
    '--threshold',
    type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
    default='HIGH',
    help='Block threshold - block PR if new paths at this severity or above'
)
@click.option(
    '--verbose',
    '-v',
    is_flag=True,
    help='Verbose output'
)
def pr_simulate(
    current_state,
    terraform_plan,
    cloudformation_template,
    output,
    format,
    threshold,
    verbose
):
    """
    Simulate security impact of infrastructure changes (Terraform/CloudFormation).
    
    Analyzes proposed IAM changes and detects new privilege escalation paths
    before they're deployed to production.
    
    Example:
        heimdall pr-simulate -c current-scan.json -t tfplan.json
    """
    
    try:
        # Validate inputs
        if not terraform_plan and not cloudformation_template:
            click.echo("Error: Must specify either --terraform-plan or --cloudformation-template", err=True)
            sys.exit(1)
        
        if cloudformation_template:
            click.echo("Error: CloudFormation support coming soon!", err=True)
            sys.exit(1)
        
        if verbose:
            click.echo("🚀 Starting PR security simulation...")
            click.echo(f"  Current state: {current_state}")
            click.echo(f"  Terraform plan: {terraform_plan}")
            click.echo("")
        
        # Step 1: Parse Terraform plan
        if verbose:
            click.echo("📋 Parsing Terraform plan...")
        
        parser = TerraformParser()
        tf_summary = parser.parse_plan_file(terraform_plan)
        
        if verbose:
            click.echo(f"  Found {tf_summary.total_changes} IAM changes")
            click.echo("")
        
        # Step 2: Calculate state diff
        if verbose:
            click.echo("🔄 Calculating state diff...")
        
        diff_engine = StateDiffEngine()
        diff_engine.load_current_state(current_state)
        proposed_state = diff_engine.apply_terraform_changes(tf_summary)
        diff = diff_engine.calculate_diff()
        
        if verbose:
            click.echo(f"  {diff.summary}")
            click.echo("")
        
        # Step 3: Simulate attack paths
        if verbose:
            click.echo("🛡️  Simulating attack paths...")
        
        simulator = AttackPathSimulator()
        analysis = simulator.analyze_pr_impact(current_state, proposed_state, tf_summary)
        
        if verbose:
            click.echo(f"  Current: {analysis.current_total_paths} paths")
            click.echo(f"  Proposed: {analysis.proposed_total_paths} paths")
            click.echo(f"  Delta: {analysis.risk_delta}")
            click.echo("")
        
        # Step 4: Format output
        if format == 'json':
            result = _format_json(analysis, diff, tf_summary)
            
            if output:
                with open(output, 'w') as f:
                    json.dump(result, f, indent=2)
                click.echo(f"✅ Results written to {output}")
            else:
                click.echo(json.dumps(result, indent=2))
        
        elif format == 'github':
            result = _format_github_comment(analysis, diff, tf_summary)
            
            if output:
                with open(output, 'w') as f:
                    f.write(result)
                click.echo(f"✅ GitHub comment written to {output}")
            else:
                click.echo(result)
        
        else:  # text
            result = simulator.format_analysis(analysis)
            
            if output:
                with open(output, 'w') as f:
                    f.write(result)
                click.echo(f"✅ Report written to {output}")
            else:
                click.echo(result)
        
        # Exit code based on threshold
        should_block = _should_block(analysis, threshold)
        
        if should_block:
            click.echo("")
            click.echo(f"❌ BLOCKED: New {threshold}+ severity paths detected", err=True)
            sys.exit(1)
        else:
            click.echo("")
            click.echo(f"✅ APPROVED: No new {threshold}+ severity paths")
            sys.exit(0)
    
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)


def _should_block(analysis, threshold):
    """Determine if PR should be blocked based on threshold"""
    severity_levels = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
    threshold_level = severity_levels[threshold]
    
    for path in analysis.new_paths:
        path_level = severity_levels.get(path.severity, 0)
        if path_level >= threshold_level:
            return True
    
    return False


def _format_json(analysis, diff, tf_summary):
    """Format output as JSON"""
    return {
        'timestamp': analysis.analysis_timestamp,
        'summary': {
            'terraform_changes': tf_summary.total_changes,
            'current_paths': analysis.current_total_paths,
            'proposed_paths': analysis.proposed_total_paths,
            'new_paths_count': len(analysis.new_paths),
            'removed_paths_count': len(analysis.removed_paths),
            'risk_delta': analysis.risk_delta,
            'recommendation': analysis.recommendation,
            'should_block': analysis.should_block_merge
        },
        'new_paths': [
            {
                'principal': path.principal_name,
                'severity': path.severity,
                'method': path.method,
                'description': path.description,
                'remediation': path.remediation,
                'required_actions': path.required_actions
            }
            for path in analysis.new_paths
        ],
        'removed_paths': [
            {
                'principal': path.principal_name,
                'method': path.method
            }
            for path in analysis.removed_paths
        ],
        'diff': {
            'new_principals': diff.new_principals,
            'deleted_principals': diff.deleted_principals,
            'modified_principals': len(diff.modified_principals)
        }
    }


def _format_github_comment(analysis, diff, tf_summary):
    """Format output as GitHub PR comment (Markdown)"""
    lines = []
    
    # Header
    lines.append("## 🛡️ Heimdall PR Security Analysis")
    lines.append("")
    
    # Status badge
    if analysis.should_block_merge:
        lines.append("**Status:** ❌ MERGE BLOCKED")
    else:
        lines.append("**Status:** ✅ SAFE TO MERGE")
    lines.append("")
    
    # Summary table
    lines.append("### 📊 Summary")
    lines.append("")
    lines.append("| Metric | Current | Proposed | Delta |")
    lines.append("|--------|---------|----------|-------|")
    lines.append(f"| CRITICAL paths | {analysis.current_critical_paths} | {analysis.proposed_critical_paths} | {analysis.proposed_critical_paths - analysis.current_critical_paths:+d} |")
    lines.append(f"| HIGH paths | {analysis.current_high_paths} | {analysis.proposed_high_paths} | {analysis.proposed_high_paths - analysis.current_high_paths:+d} |")
    lines.append(f"| Total paths | {analysis.current_total_paths} | {analysis.proposed_total_paths} | {analysis.proposed_total_paths - analysis.current_total_paths:+d} |")
    lines.append("")
    lines.append(f"**Risk Delta:** {analysis.risk_delta}")
    lines.append("")
    
    # New paths (collapsible)
    if analysis.new_paths:
        lines.append(f"### ⚠️ New Attack Paths ({len(analysis.new_paths)})")
        lines.append("")
        
        for i, path in enumerate(analysis.new_paths[:5], 1):  # Show first 5
            lines.append(f"<details>")
            lines.append(f"<summary>{i}. [{path.severity}] {path.principal_name} - {path.method}</summary>")
            lines.append("")
            lines.append(f"**Impact:** {path.description}")
            lines.append("")
            lines.append(f"**Explanation:** {path.explanation}")
            lines.append("")
            lines.append(f"**Required Actions:**")
            for action in path.required_actions:
                lines.append(f"- `{action}`")
            lines.append("")
            lines.append(f"**Remediation:**")
            lines.append(f"```")
            lines.append(path.remediation)
            lines.append(f"```")
            lines.append("")
            lines.append("</details>")
            lines.append("")
        
        if len(analysis.new_paths) > 5:
            lines.append(f"*... and {len(analysis.new_paths) - 5} more paths*")
            lines.append("")
    
    # Removed paths
    if analysis.removed_paths:
        lines.append(f"### ✅ Closed Paths ({len(analysis.removed_paths)})")
        lines.append("")
        for path in analysis.removed_paths[:3]:
            lines.append(f"- {path.principal_name}: {path.method}")
        if len(analysis.removed_paths) > 3:
            lines.append(f"- *... and {len(analysis.removed_paths) - 3} more*")
        lines.append("")
    
    # Recommendation
    lines.append("### 🎯 Recommendation")
    lines.append("")
    lines.append(analysis.recommendation)
    lines.append("")
    
    # Footer
    lines.append("---")
    lines.append("*🛡️ Analysis by [Heimdall](https://github.com/yourusername/heimdall) - IAM Security Scanner*")
    
    return "\n".join(lines)


if __name__ == '__main__':
    pr_simulate()
