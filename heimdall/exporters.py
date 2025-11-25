"""
Heimdall Export Formats

Support for various output formats: SARIF, Markdown, etc.
"""

import json
from typing import Dict, Any, List
from datetime import datetime


class SARIFExporter:
    """Export findings to SARIF format for GitHub Security"""
    
    def __init__(self):
        self.sarif_version = "2.1.0"
        self.tool_name = "Heimdall"
        self.tool_version = "1.3.0"
    
    def export(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert Heimdall findings to SARIF format
        
        Args:
            data: Heimdall scan/detect-privesc output
        
        Returns:
            SARIF-formatted dictionary
        """
        metadata = data.get('metadata', {})
        findings = data.get('findings', [])
        
        # Build SARIF structure
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": self.sarif_version,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/yourusername/heimdall",
                            "rules": self._build_rules(findings)
                        }
                    },
                    "results": self._build_results(findings),
                    "properties": {
                        "account_id": metadata.get('account_id', 'unknown'),
                        "scan_timestamp": metadata.get('scan_timestamp', datetime.now().isoformat())
                    }
                }
            ]
        }
        
        return sarif
    
    def _build_rules(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build SARIF rules from findings"""
        # Get unique privesc methods
        methods = {}
        for finding in findings:
            method = finding.get('privesc_method', 'unknown')
            if method not in methods:
                methods[method] = {
                    "id": method,
                    "name": method.replace('_', ' ').title(),
                    "shortDescription": {
                        "text": finding.get('description', 'Privilege escalation opportunity')
                    },
                    "fullDescription": {
                        "text": finding.get('description', 'Privilege escalation opportunity')
                    },
                    "help": {
                        "text": finding.get('remediation', 'Review and restrict permissions'),
                        "markdown": f"**Remediation:**\n\n{finding.get('remediation', 'Review and restrict permissions')}"
                    },
                    "properties": {
                        "tags": ["security", "iam", "privilege-escalation"],
                        "precision": "high"
                    }
                }
        
        return list(methods.values())
    
    def _build_results(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build SARIF results from findings"""
        results = []
        
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            method = finding.get('privesc_method', 'unknown')
            principal = finding.get('principal_name', 'Unknown')
            principal_arn = finding.get('principal', 'unknown')
            
            # Map severity to SARIF level
            level_map = {
                'CRITICAL': 'error',
                'HIGH': 'error',
                'MEDIUM': 'warning',
                'LOW': 'note'
            }
            level = level_map.get(severity, 'warning')
            
            result = {
                "ruleId": method,
                "level": level,
                "message": {
                    "text": f"{principal} can escalate privileges via {method}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "iam://principals",
                                "uriBaseId": "AWS_ACCOUNT"
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                                "endLine": 1,
                                "endColumn": 1
                            }
                        },
                        "logicalLocations": [
                            {
                                "name": principal,
                                "fullyQualifiedName": principal_arn,
                                "kind": finding.get('principal_type', 'unknown')
                            }
                        ]
                    }
                ],
                "properties": {
                    "severity": severity,
                    "principal": principal_arn,
                    "principal_name": principal,
                    "principal_type": finding.get('principal_type', 'unknown'),
                    "target_role": finding.get('target_role', ''),
                    "required_actions": finding.get('required_actions', []),
                    "source_policies": finding.get('source_policies', [])
                }
            }
            
            results.append(result)
        
        return results


class MarkdownExporter:
    """Export findings to Markdown format"""
    
    def export(self, data: Dict[str, Any]) -> str:
        """
        Convert Heimdall findings to Markdown
        
        Args:
            data: Heimdall scan/detect-privesc output
        
        Returns:
            Markdown-formatted string
        """
        metadata = data.get('metadata', {})
        findings = data.get('findings', [])
        graph_stats = data.get('graph', {}).get('stats', {})
        
        account_id = metadata.get('account_id', 'Unknown')
        scan_time = metadata.get('scan_timestamp', 'Unknown')
        
        # Count by severity
        critical = [f for f in findings if f.get('severity') == 'CRITICAL']
        high = [f for f in findings if f.get('severity') == 'HIGH']
        medium = [f for f in findings if f.get('severity') == 'MEDIUM']
        low = [f for f in findings if f.get('severity') == 'LOW']
        
        # Build markdown
        md = f"""# 🛡️ Heimdall IAM Security Report

## Account Information
- **Account ID:** `{account_id}`
- **Scan Timestamp:** {scan_time}
- **Total Findings:** {len(findings)}

## Executive Summary

### Security Score
"""
        
        # Calculate score
        security_score = max(0, 100 - (len(critical) * 10) - (len(high) * 5))
        if security_score >= 90:
            md += f"🟢 **{security_score}/100** - Excellent\n"
        elif security_score >= 70:
            md += f"🟡 **{security_score}/100** - Good\n"
        elif security_score >= 50:
            md += f"🟠 **{security_score}/100** - Fair\n"
        else:
            md += f"🔴 **{security_score}/100** - Poor\n"
        
        md += f"""
### Findings by Severity
| Severity | Count | Percentage |
|----------|------:|----------:|
| 🔴 CRITICAL | {len(critical)} | {len(critical)/len(findings)*100:.1f}% |
| 🟠 HIGH | {len(high)} | {len(high)/len(findings)*100:.1f}% |
| 🟡 MEDIUM | {len(medium)} | {len(medium)/len(findings)*100:.1f}% |
| 🟢 LOW | {len(low)} | {len(low)/len(findings)*100:.1f}% |
| **Total** | **{len(findings)}** | **100%** |

"""
        
        # IAM Statistics
        if graph_stats:
            md += f"""## IAM Environment
- **Roles:** {graph_stats.get('role_count', 0)}
- **Users:** {graph_stats.get('user_count', 0)}
- **Service Principals:** {graph_stats.get('service_count', 0)}
- **Trust Relationships:** {graph_stats.get('edge_count', 0)}

"""
        
        # Critical Findings
        if critical:
            md += f"""## 🔴 Critical Findings ({len(critical)})

These findings represent the highest risk and require immediate attention.

| # | Principal | Method | Target |
|---|-----------|--------|--------|
"""
            for i, finding in enumerate(critical[:20], 1):
                principal = finding.get('principal_name', 'Unknown')
                method = finding.get('privesc_method', 'unknown')
                target = finding.get('target_role_name', 'N/A')
                md += f"| {i} | `{principal}` | `{method}` | `{target}` |\n"
            
            if len(critical) > 20:
                md += f"\n*... and {len(critical) - 20} more critical findings*\n"
            
            md += "\n"
        
        # High Findings
        if high:
            md += f"""## 🟠 High Severity Findings ({len(high)})

| # | Principal | Method | Target |
|---|-----------|--------|--------|
"""
            for i, finding in enumerate(high[:10], 1):
                principal = finding.get('principal_name', 'Unknown')
                method = finding.get('privesc_method', 'unknown')
                target = finding.get('target_role_name', 'N/A')
                md += f"| {i} | `{principal}` | `{method}` | `{target}` |\n"
            
            if len(high) > 10:
                md += f"\n*... and {len(high) - 10} more high findings*\n"
            
            md += "\n"
        
        # Recommendations
        md += """## 🎯 Recommendations

### Immediate Actions
"""
        
        if critical:
            md += f"""
1. **Review and remediate {len(critical)} CRITICAL findings immediately**
   - These represent direct paths to privilege escalation
   - Priority: Principals with administrative policy attachment capabilities
   - Timeline: Within 24 hours
"""
        
        if high:
            md += f"""
2. **Address {len(high)} HIGH severity findings**
   - Review role trust policies
   - Implement least privilege principles
   - Timeline: Within 1 week
"""
        
        md += """
### Best Practices
- Implement MFA for all users with console access
- Use role-based access instead of long-term credentials
- Enable CloudTrail logging for all API calls
- Regularly review and rotate credentials
- Use AWS Organizations SCPs for guardrails

---

*Generated by [Heimdall](https://github.com/yourusername/heimdall) - AWS IAM Security Scanner*
"""
        
        return md
