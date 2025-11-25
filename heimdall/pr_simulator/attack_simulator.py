"""
Attack Path Simulator

The CORE of PR simulation - runs privilege escalation detection on proposed state
and compares it with current state to find NEW attack paths.

This is what makes Heimdall unique - "What-if" analysis for IAM changes.
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AttackPath:
    """Represents a single privilege escalation path"""
    path_id: str
    principal: str
    principal_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    method: str  # passrole_lambda, attach_user_policy, etc.
    description: str
    explanation: str
    remediation: str
    required_actions: List[str]
    
    def __hash__(self):
        return hash(self.path_id)
    
    def __eq__(self, other):
        if not isinstance(other, AttackPath):
            return False
        return self.path_id == other.path_id


@dataclass
class PRImpactAnalysis:
    """Complete analysis of PR's security impact"""
    pr_id: Optional[str] = None
    analysis_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Current state
    current_critical_paths: int = 0
    current_high_paths: int = 0
    current_total_paths: int = 0
    
    # Proposed state
    proposed_critical_paths: int = 0
    proposed_high_paths: int = 0
    proposed_total_paths: int = 0
    
    # Delta (what's new)
    new_paths: List[AttackPath] = field(default_factory=list)
    removed_paths: List[AttackPath] = field(default_factory=list)
    unchanged_paths: int = 0
    
    # Risk assessment
    risk_delta: str = ""
    recommendation: str = ""
    should_block_merge: bool = False
    
    @property
    def new_critical_count(self) -> int:
        return sum(1 for p in self.new_paths if p.severity == 'CRITICAL')
    
    @property
    def new_high_count(self) -> int:
        return sum(1 for p in self.new_paths if p.severity == 'HIGH')
    
    @property
    def risk_increased(self) -> bool:
        return len(self.new_paths) > len(self.removed_paths)
    
    def calculate_risk_delta(self):
        """Calculate human-readable risk delta"""
        new_critical = self.new_critical_count
        new_high = self.new_high_count
        removed_critical = sum(1 for p in self.removed_paths if p.severity == 'CRITICAL')
        
        if new_critical > 0:
            self.risk_delta = f"+{new_critical} CRITICAL"
            self.should_block_merge = True
            self.recommendation = "BLOCK: Critical privilege escalation paths detected"
        elif new_high > 0:
            self.risk_delta = f"+{new_high} HIGH"
            self.should_block_merge = True
            self.recommendation = "REVIEW REQUIRED: High-risk paths detected"
        elif len(self.new_paths) > len(self.removed_paths):
            self.risk_delta = f"+{len(self.new_paths) - len(self.removed_paths)} paths"
            self.recommendation = "CAUTION: Net increase in attack surface"
        elif len(self.removed_paths) > 0:
            self.risk_delta = f"-{len(self.removed_paths)} paths"
            self.recommendation = "APPROVED: Reduced attack surface"
        else:
            self.risk_delta = "No change"
            self.recommendation = "APPROVED: No new attack paths"


class AttackPathSimulator:
    """
    Simulates attack paths on proposed IAM state and compares with current state.
    
    This is the magic that makes PR simulation work!
    """
    
    def __init__(self):
        self.current_findings = []
        self.proposed_findings = []
    
    def analyze_pr_impact(
        self,
        current_scan_path: str,
        proposed_state: Dict[str, Any],
        terraform_summary
    ) -> PRImpactAnalysis:
        """
        Main entry point - analyze the security impact of a PR.
        
        Steps:
        1. Load current findings
        2. Simulate proposed state
        3. Calculate delta
        4. Generate recommendations
        """
        
        analysis = PRImpactAnalysis()
        
        # Load current findings
        self.current_findings = self._load_findings(current_scan_path)
        current_paths = self._findings_to_attack_paths(self.current_findings)
        
        # Simulate proposed state (run detection on it)
        self.proposed_findings = self._simulate_proposed_state(proposed_state)
        proposed_paths = self._findings_to_attack_paths(self.proposed_findings)
        
        # Calculate statistics
        analysis.current_critical_paths = sum(1 for p in current_paths if p.severity == 'CRITICAL')
        analysis.current_high_paths = sum(1 for p in current_paths if p.severity == 'HIGH')
        analysis.current_total_paths = len(current_paths)
        
        analysis.proposed_critical_paths = sum(1 for p in proposed_paths if p.severity == 'CRITICAL')
        analysis.proposed_high_paths = sum(1 for p in proposed_paths if p.severity == 'HIGH')
        analysis.proposed_total_paths = len(proposed_paths)
        
        # Calculate delta
        current_path_set = set(current_paths)
        proposed_path_set = set(proposed_paths)
        
        analysis.new_paths = list(proposed_path_set - current_path_set)
        analysis.removed_paths = list(current_path_set - proposed_path_set)
        analysis.unchanged_paths = len(current_path_set & proposed_path_set)
        
        # Risk assessment
        analysis.calculate_risk_delta()
        
        return analysis
    
    def _load_findings(self, scan_path: str) -> List[Dict]:
        """Load findings from Heimdall scan output"""
        with open(scan_path, 'r') as f:
            data = json.load(f)
        
        return data.get('findings', [])
    
    def _simulate_proposed_state(self, proposed_state: Dict[str, Any]) -> List[Dict]:
        """
        Run privilege escalation detection on proposed state.
        
        HYBRID APPROACH:
        1. Inherit current findings (ground truth)
        2. Only re-scan principals that were CHANGED by Terraform
        3. Scan NEW principals
        
        This prevents false positives from incomplete permission data
        while still detecting real changes.
        """
        
        findings = []
        
        # Build map of current principals and their findings
        current_principal_arns = {f.get('principal') for f in self.current_findings}
        current_findings_map = {}
        for finding in self.current_findings:
            principal = finding.get('principal')
            if principal not in current_findings_map:
                current_findings_map[principal] = []
            current_findings_map[principal].append(finding)
        
        # Track which principals were modified by Terraform
        changed_principals = set()
        for principal_arn, principal_data in proposed_state.get('principals', {}).items():
            # Check if this principal was modified (has 'terraform_modified' flag)
            if principal_data.get('terraform_modified', False):
                changed_principals.add(principal_arn)
        
        # Process each principal
        for principal_arn, principal_data in proposed_state.get('principals', {}).items():
            if principal_arn in changed_principals:
                # CHANGED: Re-scan with new permissions AND filter old findings
                permissions = principal_data.get('permissions', [])
                
                # Get NEW findings from re-scan
                new_findings = []
                if permissions:
                    new_findings.extend(self._check_passrole_patterns(principal_arn, principal_data, permissions))
                    new_findings.extend(self._check_policy_manipulation(principal_arn, principal_data, permissions))
                    new_findings.extend(self._check_credential_access(principal_arn, principal_data, permissions))
                    new_findings.extend(self._check_trust_policy_manipulation(principal_arn, principal_data, permissions))
                    new_findings.extend(self._check_secret_access(principal_arn, principal_data, permissions))
                    new_findings.extend(self._check_data_access(principal_arn, principal_data, permissions))
                
                # Also keep OLD findings that still have required permissions
                # BUT EXCLUDE findings whose required actions were removed by Terraform
                removed_perms = principal_data.get('removed_permissions', [])
                
                if principal_arn in current_findings_map:
                    for old_finding in current_findings_map[principal_arn]:
                        required = old_finding.get('required_actions', [])
                        
                        # Check if ANY required action was removed by Terraform
                        # If so, this finding should be CLOSED
                        if required and any(req in removed_perms for req in required):
                            continue  # Skip - this finding is closed
                        
                        # If all required actions still present, keep the finding
                        if required and all(any(req in perm for perm in permissions) for req in required):
                            # Check if this finding already found in new scan (avoid duplicates)
                            finding_key = f"{old_finding.get('privesc_method')}"
                            if not any(f.get('privesc_method') == finding_key for f in new_findings):
                                findings.append(old_finding)
                
                findings.extend(new_findings)
            
            elif principal_arn not in current_principal_arns:
                # NEW: Scan for patterns
                permissions = principal_data.get('permissions', [])
                if permissions:
                    findings.extend(self._check_passrole_patterns(principal_arn, principal_data, permissions))
                    findings.extend(self._check_policy_manipulation(principal_arn, principal_data, permissions))
                    findings.extend(self._check_credential_access(principal_arn, principal_data, permissions))
                    findings.extend(self._check_trust_policy_manipulation(principal_arn, principal_data, permissions))
                    findings.extend(self._check_secret_access(principal_arn, principal_data, permissions))
                    findings.extend(self._check_data_access(principal_arn, principal_data, permissions))
            
            else:
                # UNCHANGED: Inherit current findings
                if principal_arn in current_findings_map:
                    findings.extend(current_findings_map[principal_arn])
        
        return findings
    
    def _check_passrole_patterns(self, principal_arn: str, principal_data: Dict, permissions: List[str]) -> List[Dict]:
        """Check for PassRole-based privilege escalation"""
        findings = []
        
        has_passrole = any('iam:PassRole' in p or 'iam:*' in p for p in permissions)
        
        if has_passrole:
            # Check for PassRole + Lambda
            if any('lambda:CreateFunction' in p or 'lambda:*' in p for p in permissions):
                findings.append({
                    'type': 'direct_privesc',
                    'principal': principal_arn,
                    'principal_name': principal_data.get('name', principal_arn),
                    'principal_type': principal_data.get('type', 'unknown'),
                    'severity': 'CRITICAL',
                    'privesc_method': 'passrole_lambda',
                    'description': 'Create Lambda function with privileged role, execute code with elevated permissions',
                    'explanation': 'User can create Lambda with privileged role and execute arbitrary code',
                    'remediation': 'Restrict iam:PassRole to specific roles or remove lambda:CreateFunction',
                    'required_actions': ['iam:PassRole', 'lambda:CreateFunction']
                })
            
            # Check for PassRole + EC2
            if any('ec2:RunInstances' in p or 'ec2:*' in p for p in permissions):
                findings.append({
                    'type': 'direct_privesc',
                    'principal': principal_arn,
                    'principal_name': principal_data.get('name', principal_arn),
                    'principal_type': principal_data.get('type', 'unknown'),
                    'severity': 'CRITICAL',
                    'privesc_method': 'passrole_ec2',
                    'description': 'Launch EC2 instance with privileged role, SSH and execute commands',
                    'explanation': 'User can launch EC2 with admin role and gain full access via IMDS',
                    'remediation': 'Restrict iam:PassRole or remove ec2:RunInstances',
                    'required_actions': ['iam:PassRole', 'ec2:RunInstances']
                })
        
        return findings
    
    def _check_policy_manipulation(self, principal_arn: str, principal_data: Dict, permissions: List[str]) -> List[Dict]:
        """Check for policy manipulation attacks"""
        findings = []
        
        # AttachUserPolicy
        if any('iam:AttachUserPolicy' in p or 'iam:*' in p for p in permissions):
            findings.append({
                'type': 'direct_privesc',
                'principal': principal_arn,
                'principal_name': principal_data.get('name', principal_arn),
                'principal_type': principal_data.get('type', 'unknown'),
                'severity': 'CRITICAL',
                'privesc_method': 'attach_user_policy',
                'description': 'Attach AdministratorAccess policy to self or other user',
                'explanation': 'User can attach admin policy to themselves for full access',
                'remediation': 'Remove iam:AttachUserPolicy or add policy constraints',
                'required_actions': ['iam:AttachUserPolicy']
            })
        
        # PutUserPolicy
        if any('iam:PutUserPolicy' in p or 'iam:*' in p for p in permissions):
            findings.append({
                'type': 'direct_privesc',
                'principal': principal_arn,
                'principal_name': principal_data.get('name', principal_arn),
                'principal_type': principal_data.get('type', 'unknown'),
                'severity': 'CRITICAL',
                'privesc_method': 'put_user_policy',
                'description': 'Create/update inline policy with admin permissions',
                'explanation': 'User can create inline policy granting themselves full permissions',
                'remediation': 'Remove iam:PutUserPolicy or add resource constraints',
                'required_actions': ['iam:PutUserPolicy']
            })
        
        return findings
    
    def _check_credential_access(self, principal_arn: str, principal_data: Dict, permissions: List[str]) -> List[Dict]:
        """Check for credential access patterns"""
        findings = []
        
        # CreateAccessKey
        if any('iam:CreateAccessKey' in p or 'iam:*' in p for p in permissions):
            findings.append({
                'type': 'direct_privesc',
                'principal': principal_arn,
                'principal_name': principal_data.get('name', principal_arn),
                'principal_type': principal_data.get('type', 'unknown'),
                'severity': 'CRITICAL',
                'privesc_method': 'create_access_key',
                'description': 'Create programmatic access keys for other users',
                'explanation': 'User can create access keys for admin users and steal their credentials',
                'remediation': 'Restrict iam:CreateAccessKey to self only',
                'required_actions': ['iam:CreateAccessKey']
            })
        
        return findings
    
    def _check_trust_policy_manipulation(self, principal_arn: str, principal_data: Dict, permissions: List[str]) -> List[Dict]:
        """Check for trust policy manipulation (HIGH severity)"""
        findings = []
        
        # UpdateAssumeRolePolicy - allows changing who can assume a role
        if any('iam:UpdateAssumeRolePolicy' in p or 'iam:*' in p for p in permissions):
            findings.append({
                'type': 'direct_privesc',
                'principal': principal_arn,
                'principal_name': principal_data.get('name', principal_arn),
                'principal_type': principal_data.get('type', 'unknown'),
                'severity': 'HIGH',
                'privesc_method': 'update_assume_role_policy',
                'description': 'Modify role trust policy to allow unauthorized principals to assume privileged roles',
                'explanation': 'User can modify trust relationships of roles, potentially adding themselves or other principals to assume privileged roles',
                'remediation': 'Remove iam:UpdateAssumeRolePolicy or restrict to specific roles with resource constraints',
                'required_actions': ['iam:UpdateAssumeRolePolicy']
            })
        
        # SetDefaultPolicyVersion - can activate old policy versions
        if any('iam:SetDefaultPolicyVersion' in p or 'iam:*' in p for p in permissions):
            findings.append({
                'type': 'direct_privesc',
                'principal': principal_arn,
                'principal_name': principal_data.get('name', principal_arn),
                'principal_type': principal_data.get('type', 'unknown'),
                'severity': 'HIGH',
                'privesc_method': 'set_default_policy_version',
                'description': 'Revert policy to previous version that may have broader permissions',
                'explanation': 'User can activate older policy versions that may contain excessive permissions',
                'remediation': 'Remove iam:SetDefaultPolicyVersion or add policy version constraints',
                'required_actions': ['iam:SetDefaultPolicyVersion']
            })
        
        return findings
    
    def _check_secret_access(self, principal_arn: str, principal_data: Dict, permissions: List[str]) -> List[Dict]:
        """Check for secret/parameter access (MEDIUM severity)"""
        findings = []
        
        # Secrets Manager access
        if any('secretsmanager:GetSecretValue' in p or 'secretsmanager:*' in p for p in permissions):
            findings.append({
                'type': 'data_access',
                'principal': principal_arn,
                'principal_name': principal_data.get('name', principal_arn),
                'principal_type': principal_data.get('type', 'unknown'),
                'severity': 'MEDIUM',
                'privesc_method': 'secretsmanager_access',
                'description': 'Access to AWS Secrets Manager secrets (may contain credentials)',
                'explanation': 'User can read secrets from Secrets Manager which may contain database passwords, API keys, or other credentials',
                'remediation': 'Restrict secretsmanager:GetSecretValue to specific secret ARNs with resource constraints',
                'required_actions': ['secretsmanager:GetSecretValue']
            })
        
        # SSM Parameter Store access
        if any('ssm:GetParameter' in p or 'ssm:*' in p for p in permissions):
            findings.append({
                'type': 'data_access',
                'principal': principal_arn,
                'principal_name': principal_data.get('name', principal_arn),
                'principal_type': principal_data.get('type', 'unknown'),
                'severity': 'MEDIUM',
                'privesc_method': 'ssm_parameter_access',
                'description': 'Access to SSM Parameter Store parameters (may contain sensitive data)',
                'explanation': 'User can read parameters from SSM Parameter Store which may contain configuration secrets',
                'remediation': 'Restrict ssm:GetParameter to specific parameter paths with resource constraints',
                'required_actions': ['ssm:GetParameter']
            })
        
        return findings
    
    def _check_data_access(self, principal_arn: str, principal_data: Dict, permissions: List[str]) -> List[Dict]:
        """Check for data access patterns (LOW severity)"""
        findings = []
        
        # S3 read access
        has_s3_get = any('s3:GetObject' in p or 's3:*' in p for p in permissions)
        has_s3_list = any('s3:ListBucket' in p or 's3:*' in p for p in permissions)
        
        if has_s3_get and has_s3_list:
            findings.append({
                'type': 'data_access',
                'principal': principal_arn,
                'principal_name': principal_data.get('name', principal_arn),
                'principal_type': principal_data.get('type', 'unknown'),
                'severity': 'LOW',
                'privesc_method': 's3_read_access',
                'description': 'Read access to S3 buckets (data exfiltration risk)',
                'explanation': 'User can list and read objects from S3 buckets which may contain sensitive data',
                'remediation': 'Restrict S3 access to specific buckets with resource constraints and consider bucket policies',
                'required_actions': ['s3:GetObject', 's3:ListBucket']
            })
        
        # DynamoDB read access
        if any('dynamodb:GetItem' in p or 'dynamodb:Scan' in p or 'dynamodb:*' in p for p in permissions):
            findings.append({
                'type': 'data_access',
                'principal': principal_arn,
                'principal_name': principal_data.get('name', principal_arn),
                'principal_type': principal_data.get('type', 'unknown'),
                'severity': 'LOW',
                'privesc_method': 'dynamodb_read_access',
                'description': 'Read access to DynamoDB tables (data exfiltration risk)',
                'explanation': 'User can read data from DynamoDB tables which may contain sensitive information',
                'remediation': 'Restrict DynamoDB access to specific tables with resource constraints',
                'required_actions': ['dynamodb:GetItem']
            })
        
        return findings
    
    def _findings_to_attack_paths(self, findings: List[Dict]) -> List[AttackPath]:
        """Convert findings to AttackPath objects for comparison"""
        paths = []
        
        for finding in findings:
            path_id = f"{finding.get('principal', '')}:{finding.get('privesc_method', '')}"
            
            path = AttackPath(
                path_id=path_id,
                principal=finding.get('principal', ''),
                principal_name=finding.get('principal_name', ''),
                severity=finding.get('severity', 'UNKNOWN'),
                method=finding.get('privesc_method', ''),
                description=finding.get('description', ''),
                explanation=finding.get('explanation', ''),
                remediation=finding.get('remediation', ''),
                required_actions=finding.get('required_actions', [])
            )
            
            paths.append(path)
        
        return paths
    
    def format_analysis(self, analysis: PRImpactAnalysis) -> str:
        """Format analysis as human-readable report"""
        lines = []
        lines.append("🛡️  PR SECURITY IMPACT ANALYSIS")
        lines.append("=" * 70)
        lines.append("")
        
        # Summary
        lines.append("📊 SUMMARY")
        lines.append("-" * 70)
        lines.append(f"Current State:  {analysis.current_critical_paths} CRITICAL, "
                    f"{analysis.current_high_paths} HIGH ({analysis.current_total_paths} total)")
        lines.append(f"Proposed State: {analysis.proposed_critical_paths} CRITICAL, "
                    f"{analysis.proposed_high_paths} HIGH ({analysis.proposed_total_paths} total)")
        lines.append("")
        lines.append(f"Risk Delta: {analysis.risk_delta}")
        lines.append("")
        
        # New paths
        if analysis.new_paths:
            lines.append(f"⚠️  NEW ATTACK PATHS ({len(analysis.new_paths)})")
            lines.append("-" * 70)
            
            for path in analysis.new_paths[:10]:  # Show first 10
                lines.append(f"")
                lines.append(f"[{path.severity}] {path.principal_name}")
                lines.append(f"  Method: {path.method}")
                lines.append(f"  Impact: {path.description}")
                lines.append(f"  Fix: {path.remediation[:100]}...")
            
            if len(analysis.new_paths) > 10:
                lines.append(f"")
                lines.append(f"... and {len(analysis.new_paths) - 10} more")
            
            lines.append("")
        
        # Removed paths
        if analysis.removed_paths:
            lines.append(f"✅ CLOSED PATHS ({len(analysis.removed_paths)})")
            lines.append("-" * 70)
            for path in analysis.removed_paths[:5]:
                lines.append(f"  - {path.principal_name}: {path.method}")
            lines.append("")
        
        # Recommendation
        lines.append("🎯 RECOMMENDATION")
        lines.append("-" * 70)
        lines.append(analysis.recommendation)
        
        if analysis.should_block_merge:
            lines.append("")
            lines.append("❌ MERGE BLOCKED - Critical security issues detected")
        else:
            lines.append("")
            lines.append("✅ SAFE TO MERGE - No new critical paths detected")
        
        lines.append("")
        lines.append("=" * 70)
        
        return "\n".join(lines)


# CLI test
def main():
    """Test the simulator"""
    import sys
    from .terraform_parser import TerraformParser
    from .state_diff import StateDiffEngine
    
    if len(sys.argv) < 3:
        print("Usage: python attack_simulator.py <current-scan.json> <tfplan.json>")
        sys.exit(1)
    
    # Parse Terraform
    parser = TerraformParser()
    tf_summary = parser.parse_plan_file(sys.argv[2])
    
    # Calculate state diff
    diff_engine = StateDiffEngine()
    diff_engine.load_current_state(sys.argv[1])
    proposed_state = diff_engine.apply_terraform_changes(tf_summary)
    
    # Run simulation
    simulator = AttackPathSimulator()
    analysis = simulator.analyze_pr_impact(sys.argv[1], proposed_state, tf_summary)
    
    # Print results
    print(simulator.format_analysis(analysis))
    
    # Exit code based on result
    sys.exit(1 if analysis.should_block_merge else 0)


if __name__ == '__main__':
    main()
