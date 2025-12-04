# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                         TERRAFORM MODELS
#                    Data structures for IaC analysis
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Set


class ChangeAction(Enum):
    """Terraform resource change actions."""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"  # delete + create
    READ = "read"
    NO_OP = "no-op"


class ImplicationType(Enum):
    """Type of IAM implication from a resource change."""
    GAINS_PERMISSION = "gains_permission"
    LOSES_PERMISSION = "loses_permission"
    CAN_ASSUME = "can_assume"
    CAN_BE_ASSUMED = "can_be_assumed"
    PASSROLE_TO = "passrole_to"
    ATTACHES_POLICY = "attaches_policy"
    CREATES_PRINCIPAL = "creates_principal"
    MODIFIES_TRUST = "modifies_trust"


@dataclass
class IAMImplication:
    """
    Represents an IAM security implication from a Terraform resource change.
    
    Example:
        A new Lambda function with a role creates:
        - ImplicationType.PASSROLE_TO from creator to the role
        - ImplicationType.CAN_ASSUME from Lambda service to the role
    """
    implication_type: ImplicationType
    source_principal: str  # ARN or identifier of the source
    target: str  # ARN of target resource/role/policy
    permissions: List[str] = field(default_factory=list)  # List of actions
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    description: str = ""
    terraform_resource: str = ""  # e.g., "aws_iam_role.lambda_exec"
    terraform_file: str = ""  # e.g., "iam.tf"
    terraform_line: int = 0


@dataclass
class ResourceChange:
    """
    Represents a single Terraform resource change with IAM implications.
    
    Attributes:
        address: Full resource address (e.g., "aws_iam_role.lambda_exec")
        resource_type: AWS resource type (e.g., "aws_iam_role")
        resource_name: Resource name in Terraform (e.g., "lambda_exec")
        action: Change action (create, update, delete, etc.)
        before_state: Resource state before the change (None for create)
        after_state: Resource state after the change (None for delete)
        iam_implications: List of IAM security implications
    """
    address: str
    resource_type: str
    resource_name: str
    action: ChangeAction
    before_state: Optional[Dict[str, Any]] = None
    after_state: Optional[Dict[str, Any]] = None
    iam_implications: List[IAMImplication] = field(default_factory=list)
    
    # Source tracking
    module_address: str = ""  # For module resources
    provider: str = "aws"
    
    # Computed properties
    is_iam_related: bool = False
    is_compute_resource: bool = False
    
    def __post_init__(self):
        """Compute derived properties."""
        iam_types = {
            "aws_iam_role", "aws_iam_policy", "aws_iam_user", "aws_iam_group",
            "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy",
            "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
            "aws_iam_group_policy_attachment", "aws_iam_instance_profile",
            "aws_iam_group_membership",
        }
        compute_types = {
            "aws_lambda_function", "aws_instance", "aws_ecs_task_definition",
            "aws_ecs_service", "aws_eks_cluster", "aws_eks_node_group",
            "aws_codebuild_project", "aws_glue_job", "aws_sagemaker_notebook_instance",
            "aws_batch_job_definition", "aws_emr_cluster", "aws_sfn_state_machine",
        }
        
        self.is_iam_related = self.resource_type in iam_types
        self.is_compute_resource = self.resource_type in compute_types
    
    @property
    def creates_new_principal(self) -> bool:
        """Check if this change creates a new IAM principal."""
        principal_types = {"aws_iam_role", "aws_iam_user"}
        return self.resource_type in principal_types and self.action == ChangeAction.CREATE
    
    @property
    def modifies_permissions(self) -> bool:
        """Check if this change modifies IAM permissions."""
        permission_types = {
            "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy",
            "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
            "aws_iam_group_policy_attachment", "aws_iam_policy",
        }
        return self.resource_type in permission_types
    
    def get_role_arn(self) -> Optional[str]:
        """Extract role ARN from the resource if applicable."""
        state = self.after_state or self.before_state or {}
        
        # Direct role resources
        if self.resource_type == "aws_iam_role":
            return state.get("arn")
        
        # Compute resources with role references
        role_fields = ["role", "role_arn", "execution_role_arn", "task_role_arn", "iam_role_arn"]
        for field in role_fields:
            if field in state:
                return state[field]
        
        # Instance profile
        if self.resource_type == "aws_instance":
            profile = state.get("iam_instance_profile")
            if profile:
                return profile  # This is actually the profile name, need to resolve
        
        return None


@dataclass
class TerraformImpactReport:
    """
    Complete analysis report of Terraform plan's security impact.
    """
    # Counts
    before_path_count: int = 0
    after_path_count: int = 0
    new_critical_count: int = 0
    new_high_count: int = 0
    removed_path_count: int = 0
    
    # Detailed paths
    before_paths: List[Any] = field(default_factory=list)  # AttackChain objects
    after_paths: List[Any] = field(default_factory=list)
    new_paths: List[Any] = field(default_factory=list)
    removed_paths: List[Any] = field(default_factory=list)
    
    # Resource changes
    resource_changes: List[ResourceChange] = field(default_factory=list)
    iam_changes: List[ResourceChange] = field(default_factory=list)
    compute_changes: List[ResourceChange] = field(default_factory=list)
    
    # Risk metrics
    risk_score_before: int = 0
    risk_score_after: int = 0
    risk_delta: int = 0
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    blocking_issues: List[str] = field(default_factory=list)
    
    @property
    def has_new_critical(self) -> bool:
        """Check if there are new critical attack paths."""
        return self.new_critical_count > 0
    
    @property
    def should_block(self) -> bool:
        """Determine if this change should block the PR."""
        return self.new_critical_count > 0 or len(self.blocking_issues) > 0
    
    @property
    def risk_increased(self) -> bool:
        """Check if overall risk increased."""
        return self.risk_delta > 0
    
    def get_summary(self) -> str:
        """Generate a human-readable summary."""
        lines = []
        lines.append("=" * 60)
        lines.append("TERRAFORM SECURITY IMPACT ANALYSIS")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Attack Paths Before: {self.before_path_count}")
        lines.append(f"Attack Paths After:  {self.after_path_count}")
        lines.append(f"Risk Score Delta:    {self.risk_delta:+d}")
        lines.append("")
        
        if self.new_critical_count > 0:
            lines.append(f"🔴 NEW CRITICAL PATHS: {self.new_critical_count}")
        if self.new_high_count > 0:
            lines.append(f"🟠 NEW HIGH PATHS: {self.new_high_count}")
        if self.removed_path_count > 0:
            lines.append(f"✅ REMOVED PATHS: {self.removed_path_count}")
        
        lines.append("")
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": {
                "before_paths": self.before_path_count,
                "after_paths": self.after_path_count,
                "new_critical": self.new_critical_count,
                "new_high": self.new_high_count,
                "removed": self.removed_path_count,
                "risk_delta": self.risk_delta,
                "should_block": self.should_block,
            },
            "new_paths": [
                {
                    "type": p.get("type", "") if isinstance(p, dict) else (p.chain_id if hasattr(p, 'chain_id') else str(i)),
                    "role": p.get("role", "") if isinstance(p, dict) else "",
                    "severity": p.get("severity", "UNKNOWN") if isinstance(p, dict) else (p.severity.value if hasattr(p, 'severity') else "UNKNOWN"),
                    "actions": p.get("actions", []) if isinstance(p, dict) else [],
                    "description": p.get("description", "") if isinstance(p, dict) else (p.title if hasattr(p, 'title') else str(p)),
                }
                for i, p in enumerate(self.new_paths)
            ],
            "resource_changes": [
                {
                    "address": rc.address,
                    "type": rc.resource_type,
                    "action": rc.action.value,
                    "implications": len(rc.iam_implications),
                }
                for rc in self.resource_changes
            ],
            "recommendations": self.recommendations,
            "blocking_issues": self.blocking_issues,
        }


@dataclass
class MergedState:
    """
    Represents the merged state of current AWS resources + Terraform changes.
    Used to simulate "what will exist after apply".
    """
    # IAM Principals
    roles: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    users: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    groups: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # IAM Policies
    policies: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    role_policies: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    role_attachments: Dict[str, List[str]] = field(default_factory=dict)
    
    # Compute Resources
    lambda_functions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    ec2_instances: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    ecs_tasks: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Instance Profiles
    instance_profiles: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Tracking changes
    new_resources: Set[str] = field(default_factory=set)
    modified_resources: Set[str] = field(default_factory=set)
    deleted_resources: Set[str] = field(default_factory=set)
    
    def mark_new(self, resource_id: str):
        """Mark a resource as newly created by Terraform."""
        self.new_resources.add(resource_id)
    
    def mark_modified(self, resource_id: str):
        """Mark a resource as modified by Terraform."""
        self.modified_resources.add(resource_id)
    
    def mark_deleted(self, resource_id: str):
        """Mark a resource as deleted by Terraform."""
        self.deleted_resources.add(resource_id)
    
    def is_new(self, resource_id: str) -> bool:
        """Check if a resource is newly created."""
        return resource_id in self.new_resources
    
    def copy(self) -> 'MergedState':
        """Create a deep copy of this state."""
        import copy
        return copy.deepcopy(self)
    
    def get_role_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a role by its name."""
        for arn, role in self.roles.items():
            if role.get("RoleName") == name or role.get("name") == name:
                return role
        return None
