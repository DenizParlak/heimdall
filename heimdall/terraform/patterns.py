# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   ATTACK PATTERN DEFINITIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# IAM privilege escalation and cross-service attack pattern definitions.
# Each pattern is a dict with: type, actions, severity, description.
# Patterns are grouped by category for maintainability.

from __future__ import annotations
from typing import Dict, Set, List, Any, NamedTuple
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class PatternDef:
    
    # Immutable pattern definition.
    type: str
    actions: frozenset
    severity: Severity
    description: str
    requires_wildcard: bool = False


# ════════════════════════════════════════════════════════════════════════════
# ADMIN POLICIES - Managed policies that grant admin access
# ════════════════════════════════════════════════════════════════════════════

ADMIN_POLICIES: frozenset = frozenset({
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
})


# ════════════════════════════════════════════════════════════════════════════
# DANGEROUS ACTIONS - Always flag regardless of resource
# ════════════════════════════════════════════════════════════════════════════

ALWAYS_DANGEROUS: frozenset = frozenset({
    # IAM escalation
    "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
    "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
    "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    "iam:UpdateAssumeRolePolicy", "iam:DeleteRolePermissionsBoundary",
    "iam:PassRole",
    # Remote execution
    "ssm:SendCommand", "ssm:StartSession",
    "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
    "ec2:ModifyInstanceAttribute",
    # Audit tampering
    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
    "guardduty:DeleteDetector", "securityhub:DisableSecurityHub",
    # Data destruction
    "s3:DeleteBucket",
    # Organizations
    "organizations:LeaveOrganization", "organizations:DeleteOrganization",
})


# ════════════════════════════════════════════════════════════════════════════
# COMPUTE SERVICES - Services that can execute code with PassRole
# ════════════════════════════════════════════════════════════════════════════

PASSROLE_COMPUTE_ACTIONS: Dict[str, Set[str]] = {
    "lambda": {"lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"},
    "ec2": {"ec2:RunInstances"},
    "ecs": {"ecs:RunTask", "ecs:CreateService", "ecs:RegisterTaskDefinition"},
    "glue": {"glue:CreateJob", "glue:UpdateJob"},
    "sagemaker": {"sagemaker:CreateNotebookInstance", "sagemaker:CreateTrainingJob"},
    "cloudformation": {"cloudformation:CreateStack", "cloudformation:UpdateStack"},
    "codebuild": {"codebuild:CreateProject", "codebuild:UpdateProject"},
    "eks": {"eks:CreateCluster", "eks:CreateNodegroup"},
    "batch": {"batch:SubmitJob", "batch:RegisterJobDefinition"},
    "stepfunctions": {"states:CreateStateMachine", "states:UpdateStateMachine"},
    "datapipeline": {"datapipeline:CreatePipeline"},
    "emr": {"elasticmapreduce:RunJobFlow"},
}

# Flattened set for quick lookup
ALL_COMPUTE_ACTIONS: frozenset = frozenset(
    action for actions in PASSROLE_COMPUTE_ACTIONS.values() for action in actions
)


# ════════════════════════════════════════════════════════════════════════════
# PATTERN DEFINITIONS - Organized by category
# ════════════════════════════════════════════════════════════════════════════

CRITICAL_PATTERNS: tuple[PatternDef, ...] = (
    PatternDef(
        type="policy_version_manipulation",
        actions=frozenset({"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"}),
        severity=Severity.CRITICAL,
        description="Can create new policy versions to escalate privileges.",
    ),
    PatternDef(
        type="trust_policy_hijack",
        actions=frozenset({"iam:UpdateAssumeRolePolicy"}),
        severity=Severity.CRITICAL,
        description="Can modify role trust policies to allow unauthorized principals.",
    ),
    PatternDef(
        type="credential_creation",
        actions=frozenset({"iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"}),
        severity=Severity.CRITICAL,
        description="Can create credentials for IAM users (persistent access).",
    ),
    PatternDef(
        type="ssm_remote_execution",
        actions=frozenset({"ssm:SendCommand", "ssm:StartSession"}),
        severity=Severity.CRITICAL,
        description="Can execute commands on EC2 instances via SSM (remote code execution).",
    ),
    PatternDef(
        type="lambda_code_injection",
        actions=frozenset({"lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration"}),
        severity=Severity.CRITICAL,
        description="Can inject code into Lambda functions.",
    ),
    PatternDef(
        type="permission_boundary_removal",
        actions=frozenset({"iam:DeleteRolePermissionsBoundary"}),
        severity=Severity.CRITICAL,
        description="Can remove permission boundaries, bypassing security controls.",
    ),
    PatternDef(
        type="audit_tampering",
        actions=frozenset({"cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail"}),
        severity=Severity.CRITICAL,
        description="Can disable or modify CloudTrail audit logging.",
    ),
    PatternDef(
        type="security_service_tampering",
        actions=frozenset({
            "guardduty:DeleteDetector", "guardduty:StopMonitoringMembers",
            "securityhub:DisableSecurityHub", "securityhub:DeleteMembers",
            "config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder",
        }),
        severity=Severity.CRITICAL,
        description="Can disable security monitoring services.",
    ),
    PatternDef(
        type="org_manipulation",
        actions=frozenset({"organizations:LeaveOrganization", "organizations:DeleteOrganization", "organizations:*"}),
        severity=Severity.CRITICAL,
        description="Can manipulate AWS Organizations structure.",
    ),
)

HIGH_PATTERNS: tuple[PatternDef, ...] = (
    PatternDef(
        type="ec2_role_hijack",
        actions=frozenset({"ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation"}),
        severity=Severity.HIGH,
        description="Can attach/change IAM roles on EC2 instances.",
    ),
    PatternDef(
        type="secrets_access",
        actions=frozenset({"secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"}),
        severity=Severity.HIGH,
        description="Can access secrets and sensitive parameters.",
    ),
    PatternDef(
        type="kms_broad_access",
        actions=frozenset({"kms:Decrypt", "kms:*"}),
        severity=Severity.HIGH,
        description="Broad KMS access - can decrypt sensitive data.",
        requires_wildcard=True,
    ),
    PatternDef(
        type="ami_backdoor",
        actions=frozenset({"ec2:CreateImage", "ec2:ModifyImageAttribute", "ec2:RegisterImage"}),
        severity=Severity.HIGH,
        description="Can create or backdoor AMIs (supply chain attack).",
    ),
    PatternDef(
        type="network_modification",
        actions=frozenset({"ec2:CreateRoute", "ec2:ReplaceRoute", "ec2:ModifyVpcAttribute", "ec2:CreateVpcPeeringConnection"}),
        severity=Severity.HIGH,
        description="Can modify VPC/network infrastructure.",
    ),
    PatternDef(
        type="snapshot_sharing",
        actions=frozenset({"ec2:ModifySnapshotAttribute"}),
        severity=Severity.HIGH,
        description="Can share EBS snapshots externally (data exfiltration).",
    ),
    PatternDef(
        type="ec2_userdata_injection",
        actions=frozenset({"ec2:ModifyInstanceAttribute"}),
        severity=Severity.HIGH,
        description="Can modify EC2 user data (code injection on restart).",
    ),
    PatternDef(
        type="s3_acl_manipulation",
        actions=frozenset({"s3:PutBucketAcl", "s3:PutObjectAcl", "s3:PutBucketPolicy"}),
        severity=Severity.HIGH,
        description="Can modify S3 ACLs/policies (make public).",
    ),
    PatternDef(
        type="s3_replication_exfil",
        actions=frozenset({"s3:PutReplicationConfiguration"}),
        severity=Severity.HIGH,
        description="Can setup S3 replication to external bucket (data exfiltration).",
    ),
    PatternDef(
        type="s3_lock_bypass",
        actions=frozenset({"s3:BypassGovernanceRetention"}),
        severity=Severity.HIGH,
        description="Can bypass S3 object lock - delete protected data.",
    ),
    PatternDef(
        type="security_group_manipulation",
        actions=frozenset({"ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupIngress"}),
        severity=Severity.HIGH,
        description="Can modify security group rules (firewall bypass).",
    ),
)

MEDIUM_PATTERNS: tuple[PatternDef, ...] = (
    PatternDef(
        type="ebs_snapshot_abuse",
        actions=frozenset({"ec2:CopySnapshot", "ec2:CreateSnapshot"}),
        severity=Severity.MEDIUM,
        description="Broad snapshot permissions - potential data access.",
        requires_wildcard=True,
    ),
    PatternDef(
        type="data_exfiltration_s3",
        actions=frozenset({"s3:GetObject", "s3:*"}),
        severity=Severity.HIGH,
        description="Broad S3 read access - potential data exfiltration.",
        requires_wildcard=True,
    ),
)


# ════════════════════════════════════════════════════════════════════════════
# PATTERN MATCHING HELPERS
# ════════════════════════════════════════════════════════════════════════════

def match_pattern(action_set: Set[str], resources: List[str], pattern: PatternDef) -> bool:
    
    # Check if action_set matches a pattern definition.
    if not (action_set & pattern.actions):
        return False
    if pattern.requires_wildcard:
        return any(r == "*" or "*" in r.split(":::")[1].split("/")[0] if ":::" in r else False for r in resources)
    return True


def detect_patterns(action_set: Set[str], resources: List[str]) -> List[Dict[str, Any]]:
    
    # Detect all matching patterns for given actions and resources.
    detected = []
    all_patterns = CRITICAL_PATTERNS + HIGH_PATTERNS + MEDIUM_PATTERNS
    
    for pattern in all_patterns:
        if match_pattern(action_set, resources, pattern):
            detected.append({
                "type": pattern.type,
                "actions": list(action_set & pattern.actions),
                "severity": pattern.severity.value,
                "description": pattern.description,
            })
    
    # Special case: s3_mass_delete (requires wildcard resource)
    s3_delete = {"s3:DeleteBucket", "s3:DeleteObject"}
    if (action_set & s3_delete) and any(r == "*" for r in resources):
        detected.append({
            "type": "s3_mass_delete",
            "actions": list(action_set & s3_delete),
            "severity": "CRITICAL",
            "description": "Can delete S3 buckets/objects broadly - ransomware/destruction risk.",
        })
    
    return detected


# ════════════════════════════════════════════════════════════════════════════
# CROSS-SERVICE TRIGGER PATTERNS
# ════════════════════════════════════════════════════════════════════════════

CROSS_SERVICE_TRIGGERS: Dict[str, Dict[str, str]] = {
    "s3_lambda": {
        "source": "S3",
        "trigger": "s3:ObjectCreated",
        "risk": "S3 upload can trigger Lambda code execution",
    },
    "sqs_lambda": {
        "source": "SQS",
        "trigger": "sqs:SendMessage",
        "risk": "SQS message can trigger Lambda code execution",
    },
    "sns_lambda": {
        "source": "SNS",
        "trigger": "sns:Publish",
        "risk": "SNS notification can trigger Lambda code execution",
    },
    "dynamodb_lambda": {
        "source": "DynamoDB",
        "trigger": "dynamodb:PutItem",
        "risk": "DynamoDB stream can trigger Lambda code execution",
    },
    "eventbridge_lambda": {
        "source": "EventBridge",
        "trigger": "events:PutEvents",
        "risk": "EventBridge event can trigger Lambda code execution",
    },
    "api_gateway_lambda": {
        "source": "API Gateway",
        "trigger": "HTTP request",
        "risk": "Public API can trigger Lambda code execution",
    },
    "iot_lambda": {
        "source": "IoT",
        "trigger": "iot:Publish",
        "risk": "IoT message can trigger Lambda code execution",
    },
}
