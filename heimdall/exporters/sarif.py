# ᛊᚨᚱᛁᚠ • SARIF Exporter - GitHub Security Bridge
"""
Export findings to SARIF format for GitHub Security integration.

Like Gjallarhorn's call that echoes across realms, SARIF carries
Heimdall's warnings to GitHub's security dashboard.

SARIF (Static Analysis Results Interchange Format) is an OASIS standard
for representing static analysis results. GitHub Code Scanning uses SARIF.

Usage:
    sarif_data = SARIFExporter.export(findings)
    SARIFExporter.save(findings, 'heimdall.sarif')
    
    # Upload to GitHub:
    # gh api repos/{owner}/{repo}/code-scanning/sarifs -f sarif=@heimdall.sarif
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime


class SARIFExporter:
    """Export findings to SARIF 2.1.0 format."""
    
    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    
    # Severity mapping to SARIF levels
    SEVERITY_MAP = {
        "CRITICAL": "error",
        "HIGH": "error", 
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    
    # Security severity for GitHub (1.0 = critical, 0.0 = informational)
    SECURITY_SEVERITY_MAP = {
        "CRITICAL": "9.0",
        "HIGH": "7.0",
        "MEDIUM": "5.0",
        "LOW": "3.0",
        "INFO": "1.0",
    }
    
    @classmethod
    def export(cls, 
               findings: List[Dict[str, Any]], 
               tool_name: str = "Heimdall",
               tool_version: str = "1.0.0",
               scan_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Export findings to SARIF format.
        
        Args:
            findings: List of privilege escalation findings
            tool_name: Name of the tool
            tool_version: Version of the tool
            scan_info: Optional scan metadata
            
        Returns:
            SARIF document as dict
        """
        # Build rules from unique privesc methods
        rules = cls._build_rules(findings)
        
        # Build results
        results = cls._build_results(findings, rules)
        
        sarif = {
            "$schema": cls.SARIF_SCHEMA,
            "version": cls.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": tool_version,
                            "informationUri": "https://github.com/DenizParlak/Heimdall",
                            "rules": list(rules.values()),
                            "properties": {
                                "tags": ["security", "iam", "aws", "privilege-escalation"]
                            }
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                            "properties": scan_info or {}
                        }
                    ],
                    "properties": {
                        "metrics": {
                            "totalFindings": len(findings),
                            "criticalCount": sum(1 for f in findings if f.get('severity') == 'CRITICAL'),
                            "highCount": sum(1 for f in findings if f.get('severity') == 'HIGH'),
                            "mediumCount": sum(1 for f in findings if f.get('severity') == 'MEDIUM'),
                            "lowCount": sum(1 for f in findings if f.get('severity') == 'LOW'),
                        }
                    }
                }
            ]
        }
        
        return sarif
    
    @classmethod
    def _build_rules(cls, findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Build SARIF rules from unique privesc methods."""
        rules = {}
        
        for finding in findings:
            method = finding.get('privesc_method', 'unknown')
            
            if method not in rules:
                severity = finding.get('severity', 'MEDIUM')
                
                rules[method] = {
                    "id": f"HEIMDALL-{method.upper().replace('_', '-')}",
                    "name": cls._format_method_name(method),
                    "shortDescription": {
                        "text": f"IAM Privilege Escalation: {cls._format_method_name(method)}"
                    },
                    "fullDescription": {
                        "text": finding.get('description', finding.get('explanation', f"Detected {method} privilege escalation pattern"))
                    },
                    "helpUri": f"https://github.com/DenizParlak/Heimdall#privesc-{method}",
                    "help": {
                        "text": finding.get('remediation', f"Review and restrict {method} permissions"),
                        "markdown": f"## {cls._format_method_name(method)}\n\n{finding.get('explanation', '')}\n\n### Remediation\n\n{finding.get('remediation', 'Review permissions')}"
                    },
                    "defaultConfiguration": {
                        "level": cls.SEVERITY_MAP.get(severity, "warning")
                    },
                    "properties": {
                        "tags": ["security", "iam", "privilege-escalation", "aws"],
                        "security-severity": cls.SECURITY_SEVERITY_MAP.get(severity, "5.0"),
                        "precision": "high"
                    }
                }
        
        return rules
    
    @classmethod
    def _build_results(cls, findings: List[Dict[str, Any]], rules: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build SARIF results from findings."""
        results = []
        
        for i, finding in enumerate(findings):
            method = finding.get('privesc_method', 'unknown')
            severity = finding.get('severity', 'MEDIUM')
            principal = finding.get('principal_arn', finding.get('principal', ''))
            principal_name = finding.get('principal_name', principal.split('/')[-1] if '/' in principal else principal)
            
            result = {
                "ruleId": f"HEIMDALL-{method.upper().replace('_', '-')}",
                "ruleIndex": list(rules.keys()).index(method) if method in rules else 0,
                "level": cls.SEVERITY_MAP.get(severity, "warning"),
                "message": {
                    "text": f"Principal '{principal_name}' has {method} privilege escalation capability",
                    "markdown": cls._build_markdown_message(finding)
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"iam://{principal}",
                                "uriBaseId": "AWS_ACCOUNT"
                            }
                        },
                        "logicalLocations": [
                            {
                                "name": principal_name,
                                "fullyQualifiedName": principal,
                                "kind": finding.get('principal_type', 'principal')
                            }
                        ]
                    }
                ],
                "fingerprints": {
                    "primaryLocationLineHash": cls._generate_fingerprint(finding)
                },
                "partialFingerprints": {
                    "principalArn": principal,
                    "privescMethod": method
                },
                "properties": {
                    "severity": severity,
                    "principalName": principal_name,
                    "principalArn": principal,
                    "principalType": finding.get('principal_type', 'unknown'),
                    "requiredActions": finding.get('required_actions', []),
                    "targetRole": finding.get('target_role_name', ''),
                }
            }
            
            # Add fixes if remediation is available
            if finding.get('remediation'):
                result["fixes"] = [
                    {
                        "description": {
                            "text": finding['remediation']
                        }
                    }
                ]
            
            results.append(result)
        
        return results
    
    @classmethod
    def _format_method_name(cls, method: str) -> str:
        """Format method name for display."""
        return method.replace('_', ' ').title()
    
    @classmethod
    def _build_markdown_message(cls, finding: Dict[str, Any]) -> str:
        """Build rich markdown message for finding."""
        severity = finding.get('severity', 'MEDIUM')
        method = finding.get('privesc_method', 'unknown')
        principal = finding.get('principal_name', 'Unknown')
        
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }.get(severity, "⚪")
        
        md = f"## {severity_emoji} {severity}: {method}\n\n"
        md += f"**Principal:** `{principal}`\n\n"
        
        if finding.get('explanation'):
            md += f"### Description\n{finding['explanation']}\n\n"
        
        actions = finding.get('required_actions', [])
        if actions:
            md += "### Required Permissions\n"
            for action in actions[:5]:
                md += f"- `{action}`\n"
            if len(actions) > 5:
                md += f"- ... and {len(actions) - 5} more\n"
            md += "\n"
        
        if finding.get('remediation'):
            md += f"### Remediation\n{finding['remediation']}\n"
        
        return md
    
    @classmethod
    def _generate_fingerprint(cls, finding: Dict[str, Any]) -> str:
        """Generate stable fingerprint for finding."""
        import hashlib
        key = f"{finding.get('principal', '')}|{finding.get('privesc_method', '')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    @classmethod
    def to_json(cls, findings: List[Dict[str, Any]], **kwargs) -> str:
        """Export to JSON string."""
        sarif = cls.export(findings, **kwargs)
        return json.dumps(sarif, indent=2)
    
    @classmethod
    def save(cls, findings: List[Dict[str, Any]], output_path: str, **kwargs) -> None:
        """Save SARIF to file."""
        sarif = cls.export(findings, **kwargs)
        with open(output_path, 'w') as f:
            json.dump(sarif, f, indent=2)
