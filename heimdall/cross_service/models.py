# ᚱᚢᚾᛖᛊ • Runes - Data Models for Cross-Service Analysis
"""
Data models for cross-service privilege escalation analysis.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import Enum
from datetime import datetime


class ServiceType(Enum):
    """AWS service types supported for cross-service analysis."""
    IAM = "iam"
    S3 = "s3"
    LAMBDA = "lambda"
    KMS = "kms"
    STS = "sts"
    SNS = "sns"
    SQS = "sqs"
    SECRETS_MANAGER = "secretsmanager"
    ECR = "ecr"
    EC2 = "ec2"
    ECS = "ecs"
    DYNAMODB = "dynamodb"
    RDS = "rds"
    CLOUDFORMATION = "cloudformation"
    CODEBUILD = "codebuild"
    GLUE = "glue"
    SAGEMAKER = "sagemaker"


class VectorType(Enum):
    """Types of attack vectors in cross-service escalation."""
    # Direct escalation
    DIRECT_POLICY = "direct_policy"              # Direct IAM policy grant
    RESOURCE_POLICY = "resource_policy"          # Resource-based policy
    
    # Role assumption
    ASSUME_ROLE = "assume_role"                  # sts:AssumeRole
    ASSUME_ROLE_WITH_SAML = "assume_role_saml"   # sts:AssumeRoleWithSAML
    ASSUME_ROLE_WITH_OIDC = "assume_role_oidc"   # sts:AssumeRoleWithWebIdentity
    
    # Service-linked
    PASSROLE = "passrole"                        # iam:PassRole to service
    SERVICE_LINKED = "service_linked"            # Service-linked role
    
    # Data access
    DATA_EXFILTRATION = "data_exfil"             # S3/DynamoDB data access
    SECRET_ACCESS = "secret_access"              # Secrets Manager/SSM
    KEY_ACCESS = "key_access"                    # KMS key usage
    
    # Code execution
    LAMBDA_INVOKE = "lambda_invoke"              # Lambda invocation
    LAMBDA_UPDATE = "lambda_update"              # Lambda code modification
    EC2_INSTANCE = "ec2_instance"                # EC2 instance profile
    CONTAINER_ESCAPE = "container_escape"        # ECS/EKS container
    
    # Persistence
    BACKDOOR_USER = "backdoor_user"              # Create IAM user/access key
    BACKDOOR_ROLE = "backdoor_role"              # Modify trust policy
    BACKDOOR_POLICY = "backdoor_policy"          # Modify IAM policy


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ServicePermission:
    """Represents a permission granted through a service."""
    service: ServiceType
    action: str
    resource: str
    effect: str = "Allow"
    conditions: Dict[str, Any] = field(default_factory=dict)
    source_policy: str = ""  # ARN of policy granting this
    source_type: str = ""    # "identity" or "resource"
    
    @property
    def is_wildcard_action(self) -> bool:
        return "*" in self.action
    
    @property
    def is_wildcard_resource(self) -> bool:
        return self.resource == "*" or self.resource.endswith("*")
    
    @property 
    def is_admin_action(self) -> bool:
        """Check if this is an administrative action."""
        admin_patterns = [
            "*:*", "iam:*", "sts:*",
            "iam:Create*", "iam:Put*", "iam:Attach*", "iam:Update*",
            "lambda:Update*", "lambda:Create*",
            "s3:Put*Policy", "s3:Delete*",
            "kms:*", "secretsmanager:*",
        ]
        return any(
            self._matches_pattern(self.action, p) 
            for p in admin_patterns
        )
    
    def _matches_pattern(self, action: str, pattern: str) -> bool:
        """Check if action matches a pattern with wildcards."""
        if pattern == "*" or pattern == "*:*":
            return True
        if "*" not in pattern:
            return action.lower() == pattern.lower()
        # Simple wildcard matching
        prefix = pattern.replace("*", "")
        return action.lower().startswith(prefix.lower())


@dataclass
class ResourcePolicy:
    """Represents a resource-based policy."""
    resource_arn: str
    resource_type: ServiceType
    policy_document: Dict[str, Any]
    resource_name: str = ""
    account_id: str = ""
    region: str = ""
    
    # Parsed data
    allowed_principals: List[str] = field(default_factory=list)
    allowed_actions: List[str] = field(default_factory=list)
    denied_principals: List[str] = field(default_factory=list)
    denied_actions: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)
    
    # Flags
    is_public: bool = False
    allows_cross_account: bool = False
    has_dangerous_conditions: bool = False
    
    def parse_policy(self) -> None:
        """Parse the policy document and extract key information."""
        if not self.policy_document:
            return
            
        statements = self.policy_document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
            
        for stmt in statements:
            effect = stmt.get("Effect", "Allow")
            principals = self._extract_principals(stmt.get("Principal", {}))
            actions = self._normalize_list(stmt.get("Action", []))
            resources = self._normalize_list(stmt.get("Resource", []))
            conditions = stmt.get("Condition", {})
            
            if effect == "Allow":
                self.allowed_principals.extend(principals)
                self.allowed_actions.extend(actions)
            else:
                self.denied_principals.extend(principals)
                self.denied_actions.extend(actions)
            
            if conditions:
                self.conditions.update(conditions)
            
            # Check for public access (principals list contains ARNs or "*", never "AWS" key)
            if "*" in principals:
                if not self._has_restrictive_conditions(conditions):
                    self.is_public = True
            
            # Check for cross-account access
            for p in principals:
                if self._is_cross_account(p):
                    self.allows_cross_account = True
    
    def _extract_principals(self, principal: Any) -> List[str]:
        """Extract principals from policy principal field."""
        if principal == "*":
            return ["*"]
        if isinstance(principal, str):
            return [principal]
        if isinstance(principal, dict):
            result = []
            for key, val in principal.items():
                if isinstance(val, list):
                    result.extend(val)
                else:
                    result.append(val)
            return result
        return []
    
    def _normalize_list(self, value: Any) -> List[str]:
        """Normalize a value to a list."""
        if isinstance(value, str):
            return [value]
        return list(value) if value else []
    
    def _has_restrictive_conditions(self, conditions: Dict) -> bool:
        """Check if conditions restrict access."""
        restrictive_keys = [
            "aws:SourceAccount", "aws:SourceArn", "aws:SourceVpc",
            "aws:SourceVpce", "aws:PrincipalOrgID", "aws:PrincipalAccount"
        ]
        for key in restrictive_keys:
            if key in str(conditions):
                return True
        return False
    
    def _is_cross_account(self, principal: str) -> bool:
        """Check if principal is from a different account."""
        if not self.account_id:
            return False
        if principal == "*":
            return True
        # Extract account ID from ARN
        if "::" in principal:
            parts = principal.split(":")
            if len(parts) >= 5:
                return parts[4] != self.account_id
        return False


@dataclass
class AttackVector:
    """Represents a single attack vector in a cross-service chain."""
    vector_id: str
    vector_type: VectorType
    source_service: ServiceType
    target_service: ServiceType
    
    # Principal info
    source_principal: str       # ARN of attacking principal
    target_resource: str        # ARN of target resource
    
    # Permissions required
    required_permissions: List[ServicePermission] = field(default_factory=list)
    
    # Risk assessment
    severity: Severity = Severity.MEDIUM
    risk_score: int = 50
    
    # Description
    title: str = ""
    description: str = ""
    technique: str = ""         # MITRE ATT&CK technique
    
    # Evidence
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vector_id": self.vector_id,
            "vector_type": self.vector_type.value,
            "source_service": self.source_service.value,
            "target_service": self.target_service.value,
            "source_principal": self.source_principal,
            "target_resource": self.target_resource,
            "severity": self.severity.value,
            "risk_score": self.risk_score,
            "title": self.title,
            "description": self.description,
            "technique": self.technique,
            "required_permissions": [
                {
                    "action": p.action,
                    "resource": p.resource,
                    "effect": p.effect,
                }
                for p in self.required_permissions
            ],
            "evidence": self.evidence,
        }


@dataclass
class CrossServiceChain:
    """Represents a complete cross-service attack chain."""
    chain_id: str
    title: str
    description: str
    
    # Chain components
    vectors: List[AttackVector] = field(default_factory=list)
    
    # Source and target
    initial_principal: str = ""
    final_target: str = ""
    services_involved: Set[ServiceType] = field(default_factory=set)
    
    # Risk assessment
    severity: Severity = Severity.MEDIUM
    total_risk_score: int = 0
    complexity: str = "medium"  # low, medium, high
    
    # MITRE ATT&CK mapping
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    # Remediation
    remediation_steps: List[str] = field(default_factory=list)
    quick_win: str = ""
    
    # Metadata
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    
    def add_vector(self, vector: AttackVector) -> None:
        """Add a vector to the chain."""
        self.vectors.append(vector)
        self.services_involved.add(vector.source_service)
        self.services_involved.add(vector.target_service)
        self._recalculate_risk()
    
    def _recalculate_risk(self) -> None:
        """Recalculate total risk score based on vectors."""
        if not self.vectors:
            self.total_risk_score = 0
            return
        
        # Base score from vectors
        base = sum(v.risk_score for v in self.vectors) / len(self.vectors)
        
        # Multipliers
        multiplier = 1.0
        
        # More services = higher risk
        multiplier += len(self.services_involved) * 0.1
        
        # Critical severity vectors
        critical_count = sum(1 for v in self.vectors if v.severity == Severity.CRITICAL)
        multiplier += critical_count * 0.2
        
        # Cross-account access
        if any("arn:aws" in v.target_resource and "::" in v.target_resource 
               for v in self.vectors):
            multiplier += 0.15
        
        self.total_risk_score = min(100, int(base * multiplier))
        
        # Set overall severity
        if self.total_risk_score >= 85:
            self.severity = Severity.CRITICAL
        elif self.total_risk_score >= 70:
            self.severity = Severity.HIGH
        elif self.total_risk_score >= 50:
            self.severity = Severity.MEDIUM
        else:
            self.severity = Severity.LOW
        
        # Set complexity
        if len(self.vectors) >= 4 or len(self.services_involved) >= 4:
            self.complexity = "high"
        elif len(self.vectors) >= 2 or len(self.services_involved) >= 2:
            self.complexity = "medium"
        else:
            self.complexity = "low"
    
    @property
    def path_summary(self) -> str:
        """Get a summary of the attack path."""
        if not self.vectors:
            return "No path"
        
        services = [self.vectors[0].source_service.value]
        for v in self.vectors:
            services.append(v.target_service.value)
        
        return " → ".join(services)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "description": self.description,
            "initial_principal": self.initial_principal,
            "final_target": self.final_target,
            "path_summary": self.path_summary,
            "services_involved": [s.value for s in self.services_involved],
            "severity": self.severity.value,
            "total_risk_score": self.total_risk_score,
            "complexity": self.complexity,
            "vectors": [v.to_dict() for v in self.vectors],
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "remediation_steps": self.remediation_steps,
            "quick_win": self.quick_win,
            "discovered_at": self.discovered_at.isoformat(),
        }


@dataclass
class CrossServiceFinding:
    """A complete cross-service privilege escalation finding."""
    finding_id: str
    title: str
    description: str
    
    # The attack chain
    chain: CrossServiceChain
    
    # Affected resources
    affected_principals: List[str] = field(default_factory=list)
    affected_resources: List[str] = field(default_factory=list)
    
    # Risk
    severity: Severity = Severity.MEDIUM
    risk_score: int = 50
    
    # Context
    account_id: str = ""
    region: str = ""
    
    # Categorization
    category: str = ""          # e.g., "data_exfiltration", "persistence"
    attack_surface: str = ""    # e.g., "external", "internal", "cross_account"
    
    # Recommendations
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "chain": self.chain.to_dict(),
            "affected_principals": self.affected_principals,
            "affected_resources": self.affected_resources,
            "severity": self.severity.value,
            "risk_score": self.risk_score,
            "account_id": self.account_id,
            "region": self.region,
            "category": self.category,
            "attack_surface": self.attack_surface,
            "remediation": self.remediation,
            "references": self.references,
        }
