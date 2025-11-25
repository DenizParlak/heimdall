# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                          ᚹᛟᛚᚢᛊᛈᚨ • VÖLUSPÁ
#                    The Prophecy of the Seeress
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "I know that an ash-tree stands called Yggdrasil,
#    a high tree, soaked with shining loam..."
#
#   The Völva speaks of structures and fates. These schemas are the
#   prophetic forms that give shape to attack chain visions.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any, Set
from datetime import datetime


class ChainCategory(str, Enum):
    """Categories of attack chains based on technique."""
    
    PASSROLE_EXECUTION = "passrole_execution"      # PassRole + service execution
    POLICY_MANIPULATION = "policy_manipulation"    # Create/modify IAM policies
    CREDENTIAL_EXPOSURE = "credential_exposure"    # Access to secrets/credentials
    RESOURCE_HIJACK = "resource_hijack"            # Take over existing resources
    DATA_EXFILTRATION = "data_exfil"               # Access to data stores
    LATERAL_MOVEMENT = "lateral_movement"          # Cross-account/cross-service
    PERSISTENCE = "persistence"                     # Maintain access
    
    def __str__(self) -> str:
        return self.value


class Severity(str, Enum):
    """Risk severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    @property
    def score(self) -> int:
        """Numeric score for calculations."""
        return {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 0}[self.value]
    
    def __str__(self) -> str:
        return self.value


@dataclass
class ServiceImpact:
    """Impact on a specific AWS service."""
    
    service: str                          # e.g., "s3", "secretsmanager", "rds"
    actions: List[str]                    # Actions attacker can perform
    resources: List[str]                  # Affected resource ARNs/patterns
    data_access: bool = False             # Can access data?
    write_access: bool = False            # Can modify?
    delete_access: bool = False           # Can destroy?
    
    @property
    def impact_score(self) -> int:
        """Calculate impact score (0-100)."""
        score = len(self.actions) * 5
        if self.data_access:
            score += 30
        if self.write_access:
            score += 20
        if self.delete_access:
            score += 25
        return min(score, 100)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackStep:
    """Single step in an attack chain."""
    
    step_number: int
    action: str                           # AWS action (e.g., "iam:PassRole")
    service: str                          # AWS service (e.g., "iam", "lambda")
    description: str                      # Human-readable description
    principal: str                        # Who performs this step
    target: Optional[str] = None          # Target resource/principal
    severity: Severity = Severity.MEDIUM
    requires: List[str] = field(default_factory=list)  # Required permissions
    
    # Execution context
    execution_type: str = "direct"        # direct, assumed_role, service_execution
    assumed_role: Optional[str] = None    # If executing via assumed role
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['severity'] = str(self.severity)
        return result


@dataclass
class BlastRadius:
    """Impact assessment when a principal is compromised."""
    
    principal_arn: str
    total_score: int                      # 0-100 overall risk score
    
    # Categorized impacts
    services_affected: List[ServiceImpact] = field(default_factory=list)
    principals_reachable: List[str] = field(default_factory=list)  # Roles that can be assumed
    data_stores_exposed: List[str] = field(default_factory=list)   # S3, RDS, DynamoDB, etc.
    secrets_accessible: List[str] = field(default_factory=list)    # Secrets Manager, SSM
    
    # Risk factors
    cross_account_access: bool = False
    admin_path_exists: bool = False       # Can reach admin?
    production_impact: bool = False       # Affects prod resources?
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'principal_arn': self.principal_arn,
            'total_score': self.total_score,
            'services_affected': [s.to_dict() for s in self.services_affected],
            'principals_reachable': self.principals_reachable,
            'data_stores_exposed': self.data_stores_exposed,
            'secrets_accessible': self.secrets_accessible,
            'cross_account_access': self.cross_account_access,
            'admin_path_exists': self.admin_path_exists,
            'production_impact': self.production_impact,
        }
        return result


@dataclass
class AttackChain:
    """Complete multi-step attack path."""
    
    chain_id: str
    category: ChainCategory
    title: str                            # Short title (e.g., "Lambda Code Injection")
    description: str                      # Detailed narrative
    
    # Path details
    source_principal: str                 # Starting point (e.g., "user/intern")
    target_objective: str                 # End goal (e.g., "admin access", "data exfil")
    steps: List[AttackStep] = field(default_factory=list)
    
    # Risk assessment
    severity: Severity = Severity.HIGH
    blast_radius: Optional[BlastRadius] = None
    
    # Metadata
    privesc_methods: List[str] = field(default_factory=list)  # Related pattern IDs
    mitre_techniques: List[str] = field(default_factory=list) # MITRE ATT&CK mapping
    
    # Remediation
    remediation_steps: List[str] = field(default_factory=list)
    quick_win: Optional[str] = None       # Single most impactful fix
    
    @property
    def total_steps(self) -> int:
        return len(self.steps)
    
    @property
    def risk_score(self) -> int:
        """Calculate overall risk score based on multiple factors."""
        # Start with category-based base score (lower to allow more variance)
        category_scores = {
            ChainCategory.PASSROLE_EXECUTION: 60,
            ChainCategory.POLICY_MANIPULATION: 75,
            ChainCategory.CREDENTIAL_EXPOSURE: 70,
            ChainCategory.RESOURCE_HIJACK: 55,
            ChainCategory.DATA_EXFILTRATION: 65,
            ChainCategory.LATERAL_MOVEMENT: 72,
            ChainCategory.PERSISTENCE: 58,
        }
        base = category_scores.get(self.category, 55)
        
        # Factor 1: Complexity (fewer steps = easier = higher risk)
        if len(self.steps) <= 2:
            base += 12  # Very easy to execute
        elif len(self.steps) <= 3:
            base += 6   # Easy
        elif len(self.steps) == 4:
            base += 0   # Medium
        elif len(self.steps) >= 5:
            base -= 5   # Complex
        if len(self.steps) >= 6:
            base -= 5   # Very complex
        
        # Factor 2: Admin path exists (+8)
        if self.blast_radius and self.blast_radius.admin_path_exists:
            base += 8
        
        # Factor 3: Cross-account access (+5)
        if self.blast_radius and self.blast_radius.cross_account_access:
            base += 5
        
        # Factor 4: Production impact (+5)
        if self.blast_radius and self.blast_radius.production_impact:
            base += 5
        
        # Factor 5: Data exposure (+3)
        if self.blast_radius and self.blast_radius.data_stores_exposed:
            base += 3
        
        # Factor 6: Secrets accessible (+4)
        if self.blast_radius and self.blast_radius.secrets_accessible:
            base += 4
        
        return min(max(base, 0), 100)
    
    @property
    def complexity(self) -> str:
        """Attack complexity rating."""
        if self.total_steps <= 2:
            return "LOW"
        elif self.total_steps <= 4:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            'chain_id': self.chain_id,
            'category': str(self.category),
            'title': self.title,
            'description': self.description,
            'source_principal': self.source_principal,
            'target_objective': self.target_objective,
            'steps': [s.to_dict() for s in self.steps],
            'total_steps': self.total_steps,
            'severity': str(self.severity),
            'risk_score': self.risk_score,
            'complexity': self.complexity,
            'blast_radius': self.blast_radius.to_dict() if self.blast_radius else None,
            'privesc_methods': self.privesc_methods,
            'mitre_techniques': self.mitre_techniques,
            'remediation_steps': self.remediation_steps,
            'quick_win': self.quick_win,
        }
    
    def to_narrative(self) -> str:
        """Generate human-readable attack narrative."""
        lines = [
            f"# {self.title}",
            f"",
            f"**Category:** {self.category}",
            f"**Severity:** {self.severity} (Score: {self.risk_score}/100)",
            f"**Complexity:** {self.complexity} ({self.total_steps} steps)",
            f"",
            f"## Attack Narrative",
            f"",
            f"Starting from `{self.source_principal}`, an attacker can achieve `{self.target_objective}`:",
            f"",
        ]
        
        for step in self.steps:
            lines.append(f"**Step {step.step_number}:** {step.description}")
            lines.append(f"  - Action: `{step.action}`")
            if step.target:
                lines.append(f"  - Target: `{step.target}`")
            lines.append("")
        
        if self.quick_win:
            lines.extend([
                f"## Quick Fix",
                f"",
                f"🎯 {self.quick_win}",
            ])
        
        return "\n".join(lines)


# Type aliases for clarity
ChainList = List[AttackChain]
StepList = List[AttackStep]
FindingDict = Dict[str, Any]


# MITRE ATT&CK Technique Mappings
MITRE_MAPPINGS = {
    "passrole_lambda": ["T1078.004", "T1059"],      # Valid Accounts: Cloud, Command Execution
    "passrole_ec2": ["T1078.004", "T1098"],         # Valid Accounts, Account Manipulation
    "create_policy": ["T1098.001"],                  # Additional Cloud Credentials
    "assume_role": ["T1550.001"],                    # Use Alternate Auth Material
    "secrets_access": ["T1552.005"],                 # Cloud Instance Metadata API
    "s3_exfil": ["T1537"],                           # Transfer Data to Cloud Account
    "credential_exposure": ["T1552"],                # Unsecured Credentials
}
