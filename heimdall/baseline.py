# ᛒᚨᛊᛖᛚᛁᚾᛖ • Baseline - Known Risk Management
"""
Baseline system for ignoring known/accepted risks.

Like Odin's ravens Huginn and Muninn, this module remembers
which findings have been reviewed and accepted.

Supports .heimdall-ignore file with patterns to exclude findings.

Usage:
    baseline = Baseline.load('.heimdall-ignore')
    filtered, ignored, stats = baseline.filter_findings(findings)
"""

import os
import re
import json
import fnmatch
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import hashlib


@dataclass
class IgnoreRule:
    """A single ignore rule from baseline file."""
    pattern: str
    reason: str = ""
    expires: Optional[str] = None  # ISO date
    added_by: str = ""
    added_at: str = ""
    
    # Match criteria
    principal: Optional[str] = None
    method: Optional[str] = None
    severity: Optional[str] = None
    finding_hash: Optional[str] = None
    
    def is_expired(self) -> bool:
        """Check if this rule has expired."""
        if not self.expires:
            return False
        try:
            expire_date = datetime.fromisoformat(self.expires)
            return datetime.now() > expire_date
        except:
            return False
    
    def matches(self, finding: Dict[str, Any]) -> bool:
        """Check if this rule matches a finding."""
        if self.is_expired():
            return False
        
        # Hash match (exact finding)
        if self.finding_hash:
            finding_hash = generate_finding_hash(finding)
            if finding_hash == self.finding_hash:
                return True
        
        # Pattern matching
        if self.principal:
            principal_name = finding.get('principal_name', '')
            principal_arn = finding.get('principal_arn', finding.get('principal', ''))
            if not (fnmatch.fnmatch(principal_name, self.principal) or 
                    fnmatch.fnmatch(principal_arn, self.principal)):
                return False
        
        if self.method:
            method = finding.get('privesc_method', '')
            if not fnmatch.fnmatch(method, self.method):
                return False
        
        if self.severity:
            severity = finding.get('severity', '')
            if severity.upper() != self.severity.upper():
                return False
        
        # If we have criteria and all matched, return True
        if self.principal or self.method or self.severity:
            return True
        
        # Generic pattern match against full finding string
        if self.pattern:
            finding_str = json.dumps(finding, default=str)
            if self.pattern in finding_str or fnmatch.fnmatch(finding_str, f"*{self.pattern}*"):
                return True
        
        return False


@dataclass
class Baseline:
    """Manages baseline/ignore rules."""
    rules: List[IgnoreRule] = field(default_factory=list)
    file_path: Optional[str] = None
    
    @classmethod
    def load(cls, file_path: str = None) -> 'Baseline':
        """Load baseline from file."""
        baseline = cls()
        
        # Try multiple locations
        search_paths = []
        if file_path:
            search_paths.append(file_path)
        search_paths.extend([
            '.heimdall-ignore',
            '.heimdall-baseline',
            'heimdall-ignore.json',
            'heimdall-baseline.json',
            os.path.expanduser('~/.heimdall-ignore'),
        ])
        
        for path in search_paths:
            if os.path.exists(path):
                baseline.file_path = path
                baseline._load_file(path)
                break
        
        return baseline
    
    def _load_file(self, path: str) -> None:
        """Load rules from file."""
        with open(path, 'r') as f:
            content = f.read().strip()
        
        # JSON format
        if path.endswith('.json') or content.startswith('{') or content.startswith('['):
            self._load_json(content)
        else:
            # Simple text format
            self._load_text(content)
    
    def _load_json(self, content: str) -> None:
        """Load JSON format baseline."""
        data = json.loads(content)
        
        if isinstance(data, list):
            rules_data = data
        else:
            rules_data = data.get('rules', data.get('ignore', []))
        
        for rule_data in rules_data:
            if isinstance(rule_data, str):
                self.rules.append(IgnoreRule(pattern=rule_data))
            else:
                self.rules.append(IgnoreRule(
                    pattern=rule_data.get('pattern', ''),
                    reason=rule_data.get('reason', ''),
                    expires=rule_data.get('expires'),
                    added_by=rule_data.get('added_by', ''),
                    added_at=rule_data.get('added_at', ''),
                    principal=rule_data.get('principal'),
                    method=rule_data.get('method'),
                    severity=rule_data.get('severity'),
                    finding_hash=rule_data.get('hash'),
                ))
    
    def _load_text(self, content: str) -> None:
        """Load simple text format baseline."""
        for line in content.split('\n'):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Parse line: pattern [# reason]
            if '#' in line:
                pattern, reason = line.split('#', 1)
                pattern = pattern.strip()
                reason = reason.strip()
            else:
                pattern = line
                reason = ''
            
            # Parse special prefixes
            rule = IgnoreRule(pattern=pattern, reason=reason)
            
            if pattern.startswith('principal:'):
                rule.principal = pattern[10:].strip()
                rule.pattern = ''
            elif pattern.startswith('method:'):
                rule.method = pattern[7:].strip()
                rule.pattern = ''
            elif pattern.startswith('severity:'):
                rule.severity = pattern[9:].strip()
                rule.pattern = ''
            elif pattern.startswith('hash:'):
                rule.finding_hash = pattern[5:].strip()
                rule.pattern = ''
            
            self.rules.append(rule)
    
    def filter_findings(self, findings: List[Dict[str, Any]]) -> tuple:
        """
        Filter findings based on baseline rules.
        
        Returns:
            (filtered_findings, ignored_findings, ignore_stats)
        """
        filtered = []
        ignored = []
        stats = {
            'total': len(findings),
            'ignored': 0,
            'by_rule': {},
        }
        
        for finding in findings:
            matched_rule = None
            for rule in self.rules:
                if rule.matches(finding):
                    matched_rule = rule
                    break
            
            if matched_rule:
                ignored.append({
                    'finding': finding,
                    'rule': matched_rule.pattern or matched_rule.principal or matched_rule.method,
                    'reason': matched_rule.reason,
                })
                stats['ignored'] += 1
                rule_key = matched_rule.pattern or matched_rule.principal or matched_rule.method or 'unknown'
                stats['by_rule'][rule_key] = stats['by_rule'].get(rule_key, 0) + 1
            else:
                filtered.append(finding)
        
        return filtered, ignored, stats
    
    def save(self, file_path: str = None) -> None:
        """Save baseline to JSON file."""
        path = file_path or self.file_path or '.heimdall-ignore'
        
        data = {
            'version': '1.0',
            'updated_at': datetime.now().isoformat(),
            'rules': [
                {
                    'pattern': r.pattern,
                    'reason': r.reason,
                    'expires': r.expires,
                    'added_by': r.added_by,
                    'added_at': r.added_at,
                    'principal': r.principal,
                    'method': r.method,
                    'severity': r.severity,
                    'hash': r.finding_hash,
                }
                for r in self.rules
            ]
        }
        
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add_rule(self, 
                 pattern: str = '',
                 principal: str = None,
                 method: str = None,
                 severity: str = None,
                 finding_hash: str = None,
                 reason: str = '',
                 expires: str = None) -> None:
        """Add a new ignore rule."""
        self.rules.append(IgnoreRule(
            pattern=pattern,
            reason=reason,
            expires=expires,
            added_at=datetime.now().isoformat(),
            principal=principal,
            method=method,
            severity=severity,
            finding_hash=finding_hash,
        ))
    
    def add_finding(self, finding: Dict[str, Any], reason: str = '') -> str:
        """Add a finding to ignore list by hash."""
        finding_hash = generate_finding_hash(finding)
        self.add_rule(
            finding_hash=finding_hash,
            reason=reason or f"Ignored: {finding.get('principal_name', '')} - {finding.get('privesc_method', '')}",
        )
        return finding_hash


def generate_finding_hash(finding: Dict[str, Any]) -> str:
    """Generate unique hash for a finding."""
    # Use stable fields for hash
    key_parts = [
        finding.get('principal_arn', finding.get('principal', '')),
        finding.get('privesc_method', ''),
        finding.get('severity', ''),
    ]
    key_str = '|'.join(str(p) for p in key_parts)
    return hashlib.sha256(key_str.encode()).hexdigest()[:16]


def create_sample_baseline(path: str = '.heimdall-ignore') -> None:
    """Create a sample baseline file."""
    sample = """# Heimdall Baseline - Ignore known/accepted risks
# Format: pattern # reason
# 
# Special prefixes:
#   principal:pattern  - Match principal name/ARN
#   method:pattern     - Match privesc method
#   severity:LEVEL     - Match severity level
#   hash:abc123        - Match specific finding by hash

# Example rules:
# principal:service-*           # Service accounts are expected
# method:passrole_lambda        # Lambda passrole is approved
# severity:LOW                  # Ignore all LOW severity
# hash:a1b2c3d4e5f6             # Specific approved finding

# Add your rules below:
"""
    with open(path, 'w') as f:
        f.write(sample)
