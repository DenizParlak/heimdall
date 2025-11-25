"""
Heimdall Diff Engine

Compares two IAM scan results and identifies security changes.
Foundation for PR Attack Simulator.
"""

import json
from typing import Dict, Any, List, Tuple, Set
from dataclasses import dataclass
from datetime import datetime


@dataclass
class FindingChange:
    """Represents a change in findings"""
    finding: Dict[str, Any]
    change_type: str  # 'added', 'removed', 'unchanged'
    
    def __hash__(self):
        # Make it hashable for set operations
        return hash((
            self.finding.get('principal'),
            self.finding.get('privesc_method'),
            self.finding.get('target_role')
        ))


@dataclass
class DiffResult:
    """Result of comparing two scans"""
    # Metadata
    baseline_timestamp: str
    current_timestamp: str
    baseline_account: str
    current_account: str
    
    # Changes
    new_findings: List[Dict[str, Any]]
    resolved_findings: List[Dict[str, Any]]
    unchanged_findings: List[Dict[str, Any]]
    
    # Metrics
    new_principals: List[str]
    removed_principals: List[str]
    
    # Risk scores
    baseline_score: int
    current_score: int
    score_delta: int
    
    # Severity changes
    new_critical: int
    new_high: int
    new_medium: int
    new_low: int
    
    resolved_critical: int
    resolved_high: int
    resolved_medium: int
    resolved_low: int


class DiffEngine:
    """Engine for comparing IAM scan results"""
    
    def __init__(self):
        pass
    
    def compare(self, baseline: Dict[str, Any], current: Dict[str, Any]) -> DiffResult:
        """
        Compare two scan results
        
        Args:
            baseline: Older scan result
            current: Newer scan result
        
        Returns:
            DiffResult with all changes
        """
        # Extract metadata
        baseline_meta = baseline.get('metadata', {})
        current_meta = current.get('metadata', {})
        
        baseline_timestamp = baseline_meta.get('scan_timestamp', 'Unknown')
        current_timestamp = current_meta.get('scan_timestamp', 'Unknown')
        baseline_account = baseline_meta.get('account_id', 'Unknown')
        current_account = current_meta.get('account_id', 'Unknown')
        
        # Extract findings
        baseline_findings = baseline.get('findings', [])
        current_findings = current.get('findings', [])
        
        # Compare findings
        new_findings, resolved_findings, unchanged_findings = self._compare_findings(
            baseline_findings, current_findings
        )
        
        # Compare principals
        new_principals, removed_principals = self._compare_principals(baseline, current)
        
        # Calculate risk scores
        baseline_score = self._calculate_risk_score(baseline_findings)
        current_score = self._calculate_risk_score(current_findings)
        score_delta = current_score - baseline_score
        
        # Count by severity
        new_critical = len([f for f in new_findings if f.get('severity') == 'CRITICAL'])
        new_high = len([f for f in new_findings if f.get('severity') == 'HIGH'])
        new_medium = len([f for f in new_findings if f.get('severity') == 'MEDIUM'])
        new_low = len([f for f in new_findings if f.get('severity') == 'LOW'])
        
        resolved_critical = len([f for f in resolved_findings if f.get('severity') == 'CRITICAL'])
        resolved_high = len([f for f in resolved_findings if f.get('severity') == 'HIGH'])
        resolved_medium = len([f for f in resolved_findings if f.get('severity') == 'MEDIUM'])
        resolved_low = len([f for f in resolved_findings if f.get('severity') == 'LOW'])
        
        return DiffResult(
            baseline_timestamp=baseline_timestamp,
            current_timestamp=current_timestamp,
            baseline_account=baseline_account,
            current_account=current_account,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            unchanged_findings=unchanged_findings,
            new_principals=new_principals,
            removed_principals=removed_principals,
            baseline_score=baseline_score,
            current_score=current_score,
            score_delta=score_delta,
            new_critical=new_critical,
            new_high=new_high,
            new_medium=new_medium,
            new_low=new_low,
            resolved_critical=resolved_critical,
            resolved_high=resolved_high,
            resolved_medium=resolved_medium,
            resolved_low=resolved_low
        )
    
    def _compare_findings(
        self, 
        baseline_findings: List[Dict[str, Any]], 
        current_findings: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Compare findings lists"""
        
        # Create unique keys for findings
        def make_key(finding: Dict[str, Any]) -> str:
            """Create unique key for a finding"""
            return f"{finding.get('principal', 'unknown')}|{finding.get('privesc_method', 'unknown')}|{finding.get('target_role', 'none')}"
        
        # Create sets of keys
        baseline_keys = {make_key(f): f for f in baseline_findings}
        current_keys = {make_key(f): f for f in current_findings}
        
        # Find new, resolved, and unchanged
        new_findings = [current_keys[k] for k in current_keys if k not in baseline_keys]
        resolved_findings = [baseline_keys[k] for k in baseline_keys if k not in current_keys]
        unchanged_keys = set(baseline_keys.keys()) & set(current_keys.keys())
        unchanged_findings = [current_keys[k] for k in unchanged_keys]
        
        return new_findings, resolved_findings, unchanged_findings
    
    def _compare_principals(
        self, 
        baseline: Dict[str, Any], 
        current: Dict[str, Any]
    ) -> Tuple[List[str], List[str]]:
        """Compare principals between scans"""
        
        baseline_graph = baseline.get('graph', {})
        current_graph = current.get('graph', {})
        
        baseline_nodes = baseline_graph.get('nodes', [])
        current_nodes = current_graph.get('nodes', [])
        
        # Get principal ARNs
        baseline_principals = {n.get('id') for n in baseline_nodes if n.get('type') in ['user', 'role']}
        current_principals = {n.get('id') for n in current_nodes if n.get('type') in ['user', 'role']}
        
        # Find new and removed
        new_principals = list(current_principals - baseline_principals)
        removed_principals = list(baseline_principals - current_principals)
        
        return new_principals, removed_principals
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> int:
        """Calculate risk score from findings"""
        critical_count = len([f for f in findings if f.get('severity') == 'CRITICAL'])
        high_count = len([f for f in findings if f.get('severity') == 'HIGH'])
        
        # Score: 100 - (criticals * 10) - (highs * 5), minimum 0
        score = max(0, 100 - (critical_count * 10) - (high_count * 5))
        return score
    
    def format_diff_table(self, diff: DiffResult) -> str:
        """Format diff result as rich table (returns string for rendering)"""
        # This will be used by CLI to display
        pass
    
    def format_diff_json(self, diff: DiffResult) -> Dict[str, Any]:
        """Format diff result as JSON"""
        return {
            'comparison': {
                'baseline_timestamp': diff.baseline_timestamp,
                'current_timestamp': diff.current_timestamp,
                'baseline_account': diff.baseline_account,
                'current_account': diff.current_account
            },
            'risk_score': {
                'baseline': diff.baseline_score,
                'current': diff.current_score,
                'delta': diff.score_delta,
                'improved': diff.score_delta > 0
            },
            'findings_summary': {
                'new': {
                    'total': len(diff.new_findings),
                    'critical': diff.new_critical,
                    'high': diff.new_high,
                    'medium': diff.new_medium,
                    'low': diff.new_low
                },
                'resolved': {
                    'total': len(diff.resolved_findings),
                    'critical': diff.resolved_critical,
                    'high': diff.resolved_high,
                    'medium': diff.resolved_medium,
                    'low': diff.resolved_low
                },
                'unchanged': len(diff.unchanged_findings)
            },
            'principals': {
                'new': diff.new_principals,
                'removed': diff.removed_principals
            },
            'new_findings': diff.new_findings[:50],  # Limit to 50
            'resolved_findings': diff.resolved_findings[:50]
        }
    
    def format_diff_github(self, diff: DiffResult) -> str:
        """Format diff result as GitHub-flavored markdown for PR comments"""
        
        # Emoji indicators
        trend_emoji = "📈" if diff.score_delta < 0 else "📉" if diff.score_delta > 0 else "➡️"
        status_emoji = "🚨" if diff.new_critical > 0 else "⚠️" if diff.new_high > 0 else "✅"
        
        md = f"""## {status_emoji} Heimdall Security Analysis

### Security Score
- **Baseline:** {diff.baseline_score}/100
- **Current:** {diff.current_score}/100
- **Change:** {trend_emoji} {diff.score_delta:+d} {'(WORSE)' if diff.score_delta < 0 else '(BETTER)' if diff.score_delta > 0 else '(NO CHANGE)'}

### Changes Summary
"""
        
        # New findings
        if diff.new_findings:
            md += f"\n#### 🆕 New Findings ({len(diff.new_findings)})\n\n"
            if diff.new_critical > 0:
                md += f"- 🔴 **CRITICAL**: {diff.new_critical}\n"
            if diff.new_high > 0:
                md += f"- 🟠 **HIGH**: {diff.new_high}\n"
            if diff.new_medium > 0:
                md += f"- 🟡 **MEDIUM**: {diff.new_medium}\n"
            if diff.new_low > 0:
                md += f"- 🟢 **LOW**: {diff.new_low}\n"
            
            # Show top 5 critical new findings
            critical_new = [f for f in diff.new_findings if f.get('severity') == 'CRITICAL'][:5]
            if critical_new:
                md += f"\n**Top Critical New Findings:**\n\n"
                for i, finding in enumerate(critical_new, 1):
                    principal = finding.get('principal_name', 'Unknown')
                    method = finding.get('privesc_method', 'unknown')
                    target = finding.get('target_role_name', '')
                    md += f"{i}. `{principal}` → `{method}`"
                    if target:
                        md += f" → `{target}`"
                    md += "\n"
        else:
            md += "\n#### ✅ No New Findings\n\n"
        
        # Resolved findings
        if diff.resolved_findings:
            md += f"\n#### ✅ Resolved Findings ({len(diff.resolved_findings)})\n\n"
            if diff.resolved_critical > 0:
                md += f"- 🔴 **CRITICAL**: {diff.resolved_critical}\n"
            if diff.resolved_high > 0:
                md += f"- 🟠 **HIGH**: {diff.resolved_high}\n"
        
        # Recommendation
        md += "\n### 🎯 Recommendation\n\n"
        if diff.new_critical > 0:
            md += f"**❌ BLOCK THIS PR** - Introduces {diff.new_critical} CRITICAL security issues\n"
        elif diff.new_high > 0:
            md += f"**⚠️ REVIEW REQUIRED** - Introduces {diff.new_high} HIGH severity issues\n"
        elif len(diff.new_findings) > 0:
            md += f"**⚠️ CAUTION** - Introduces {len(diff.new_findings)} new findings (review recommended)\n"
        else:
            md += "**✅ APPROVED** - No new security issues detected\n"
        
        # Footer
        md += f"\n---\n*Analysis by [Heimdall](https://github.com/yourusername/heimdall) | "
        md += f"Baseline: {diff.baseline_timestamp} | Current: {diff.current_timestamp}*\n"
        
        return md
