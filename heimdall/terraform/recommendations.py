# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   RECOMMENDATION ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# Generate blocking issues and remediation recommendations for detected attack paths.

from __future__ import annotations
from typing import Dict, List, Any, Callable
from dataclasses import dataclass


@dataclass(slots=True)
class Recommendation:
    
    # A blocking issue with its remediation recommendation.
    issue: str
    recommendation: str


# Type alias for recommendation generator functions
RecommendationFn = Callable[[Dict[str, Any]], Recommendation]


def _fmt_actions(path: Dict[str, Any]) -> str:
    
    # Format actions list as comma-separated string.
    return ", ".join(path.get("actions", []))


# ════════════════════════════════════════════════════════════════════════════
# RECOMMENDATION GENERATORS - One per pattern type
# ════════════════════════════════════════════════════════════════════════════

PATTERN_RECOMMENDATIONS: Dict[str, RecommendationFn] = {
    
    # IAM Core
    "admin_policy_attachment": lambda p: Recommendation(
        f"Admin policy attached to role '{p.get('role')}' - use least-privilege.",
        f"Replace AdministratorAccess on '{p.get('role')}' with specific permissions."
    ),
    "compute_to_admin": lambda p: Recommendation(
        f"Compute service can assume admin role '{p.get('role')}'.",
        f"Restrict permissions on role '{p.get('role')}' or add conditions to trust policy."
    ),
    "lambda_admin_access": lambda p: Recommendation(
        f"Lambda '{p.get('function')}' has admin access via role '{p.get('role')}'.",
        f"Apply least-privilege to Lambda role '{p.get('role')}'."
    ),
    "wildcard_trust_policy": lambda p: Recommendation(
        f"Wildcard trust policy on role '{p.get('role')}' - ANYONE can assume this role!",
        f"Restrict Principal in trust policy of '{p.get('role')}' to specific accounts/roles."
    ),
    "dangerous_permissions": lambda p: Recommendation(
        f"Dangerous permissions on role '{p.get('role')}': {_fmt_actions(p)}.",
        f"Restrict actions and resources on role '{p.get('role')}'."
    ),
    
    # Chains
    "passrole_chain_to_admin": lambda p: Recommendation(
        f"CHAIN: '{p.get('source_role')}' → PassRole → admin role '{p.get('target_role')}'.",
        f"Remove PassRole permission from '{p.get('source_role')}' or restrict to non-admin roles."
    ),
    "assume_role_to_admin": lambda p: Recommendation(
        f"CHAIN: '{p.get('source_role')}' → AssumeRole → admin role '{p.get('target_role')}'.",
        f"Remove AssumeRole permission from '{p.get('source_role')}' to '{p.get('target_role')}'."
    ),
    "multi_hop_chain": lambda p: Recommendation(
        f"MULTI-HOP CHAIN ({p.get('hops', 0)} hops): {p.get('chain')}.",
        f"Break the chain by restricting AssumeRole permissions from '{p.get('source_role')}'."
    ),
    "compute_passrole_chain": lambda p: Recommendation(
        f"CHAIN: Compute service → '{p.get('role')}' → PassRole + CreateFunction (privilege escalation).",
        f"Remove PassRole + CreateFunction combination from '{p.get('role')}'."
    ),
    
    # Critical IAM
    "policy_version_manipulation": lambda p: Recommendation(
        f"CRITICAL: Role '{p.get('role')}' can modify IAM policies via {_fmt_actions(p)}.",
        f"Remove iam:CreatePolicyVersion and iam:SetDefaultPolicyVersion from '{p.get('role')}'."
    ),
    "trust_policy_hijack": lambda p: Recommendation(
        f"CRITICAL: Role '{p.get('role')}' can modify trust policies (iam:UpdateAssumeRolePolicy).",
        f"Remove iam:UpdateAssumeRolePolicy from '{p.get('role')}' - this allows role takeover."
    ),
    "credential_creation": lambda p: Recommendation(
        f"CRITICAL: Role '{p.get('role')}' can create credentials via {_fmt_actions(p)}.",
        f"Remove credential creation permissions from '{p.get('role')}' - allows persistent access."
    ),
    "ssm_remote_execution": lambda p: Recommendation(
        f"CRITICAL: Role '{p.get('role')}' has SSM RCE capabilities ({_fmt_actions(p)}).",
        f"Restrict ssm:SendCommand/StartSession on '{p.get('role')}' to specific instances."
    ),
    "lambda_code_injection": lambda p: Recommendation(
        f"CRITICAL: Role '{p.get('role')}' can inject code into Lambda ({_fmt_actions(p)}).",
        f"Restrict Lambda update permissions on '{p.get('role')}' to specific functions."
    ),
    "ec2_role_hijack": lambda p: Recommendation(
        f"HIGH: Role '{p.get('role')}' can attach/change IAM roles on EC2 instances ({_fmt_actions(p)}).",
        f"Restrict ec2:AssociateIamInstanceProfile on '{p.get('role')}' to specific instances."
    ),
    "permission_boundary_removal": lambda p: Recommendation(
        f"CRITICAL: Role '{p.get('role')}' can remove permission boundaries (security bypass).",
        f"Remove iam:DeleteRolePermissionsBoundary from '{p.get('role')}'."
    ),
    
    # Cross-Service
    "cross_service_s3_lambda": lambda p: Recommendation(
        f"CROSS-SERVICE: {p.get('source')} → Lambda '{p.get('target')}' (s3:PutObject can trigger code execution).",
        f"Review Lambda '{p.get('target')}' permissions - S3 trigger enables indirect code execution."
    ),
    "cross_service_eventbridge": lambda p: Recommendation(
        f"CROSS-SERVICE: EventBridge → '{p.get('target')}' (events:PutEvents can trigger execution).",
        f"Restrict EventBridge rule or review target '{p.get('target')}' permissions."
    ),
    "cross_service_public_resource": lambda p: Recommendation(
        f"PUBLIC RESOURCE: {p.get('resource_type')} '{p.get('resource')}' allows public access - data exfiltration risk!",
        f"Remove wildcard principal from {p.get('resource_type')} policy '{p.get('resource')}'."
    ),
    "cross_service_api_gateway_lambda": lambda p: Recommendation(
        f"CROSS-SERVICE: {p.get('source')} → Lambda (public API can trigger code execution).",
        f"Add authorization to API Gateway and review Lambda permissions."
    ),
    "cross_service_sns_lambda": lambda p: Recommendation(
        f"CROSS-SERVICE: SNS → Lambda '{p.get('target')}' (sns:Publish can trigger code).",
        f"Review SNS topic access policy and Lambda '{p.get('target')}' permissions."
    ),
    "cross_service_public_lambda_url": lambda p: Recommendation(
        f"PUBLIC LAMBDA URL: Lambda '{p.get('resource')}' has public URL without authentication!",
        f"Add IAM or custom authorization to Lambda function URL '{p.get('resource')}'."
    ),
    "cross_service_public_ecr": lambda p: Recommendation(
        f"PUBLIC ECR: Repository '{p.get('resource')}' allows public pull - supply chain risk!",
        f"Restrict ECR repository policy to specific accounts/principals."
    ),
    "cross_service_iot_lambda": lambda p: Recommendation(
        f"CROSS-SERVICE: IoT → Lambda (iot:Publish can trigger code execution).",
        f"Review IoT topic rule access and Lambda permissions."
    ),
    
    # Data & Secrets
    "data_exfiltration_s3": lambda p: Recommendation(
        f"DATA EXFIL: Role '{p.get('role')}' has broad S3 read access ({_fmt_actions(p)}).",
        f"Restrict S3 access on '{p.get('role')}' to specific buckets."
    ),
    "secrets_access": lambda p: Recommendation(
        f"SECRETS: Role '{p.get('role')}' can read secrets ({_fmt_actions(p)}).",
        f"Restrict secrets access on '{p.get('role')}' to specific secrets/parameters."
    ),
    "kms_broad_access": lambda p: Recommendation(
        f"KMS: Role '{p.get('role')}' has broad KMS access ({_fmt_actions(p)}).",
        f"Restrict KMS access on '{p.get('role')}' to specific keys."
    ),
    
    # Security & Audit
    "audit_tampering": lambda p: Recommendation(
        f"AUDIT TAMPERING: Role '{p.get('role')}' can disable CloudTrail ({_fmt_actions(p)}).",
        f"Remove CloudTrail modification permissions from '{p.get('role')}'."
    ),
    "security_service_tampering": lambda p: Recommendation(
        f"SECURITY BYPASS: Role '{p.get('role')}' can disable security services ({_fmt_actions(p)}).",
        f"Remove security service modification permissions from '{p.get('role')}'."
    ),
    "org_manipulation": lambda p: Recommendation(
        f"ORG RISK: Role '{p.get('role')}' can manipulate AWS Organizations ({_fmt_actions(p)}).",
        f"Remove Organizations permissions from '{p.get('role')}'."
    ),
    
    # Supply Chain & Infrastructure
    "ami_backdoor": lambda p: Recommendation(
        f"SUPPLY CHAIN: Role '{p.get('role')}' can create/modify AMIs ({_fmt_actions(p)}).",
        f"Restrict AMI creation permissions on '{p.get('role')}'."
    ),
    "network_modification": lambda p: Recommendation(
        f"NETWORK: Role '{p.get('role')}' can modify VPC infrastructure ({_fmt_actions(p)}).",
        f"Review network modification permissions on '{p.get('role')}'."
    ),
    
    # EC2/EBS
    "snapshot_sharing": lambda p: Recommendation(
        f"SNAPSHOT SHARE: Role '{p.get('role')}' can share snapshots externally ({_fmt_actions(p)}).",
        f"Restrict snapshot sharing permissions on '{p.get('role')}'."
    ),
    "ebs_snapshot_abuse": lambda p: Recommendation(
        f"EBS: Role '{p.get('role')}' has broad snapshot permissions ({_fmt_actions(p)}).",
        f"Restrict EBS snapshot permissions on '{p.get('role')}' to specific volumes."
    ),
    "ec2_userdata_injection": lambda p: Recommendation(
        f"EC2 USERDATA: Role '{p.get('role')}' can inject user data ({_fmt_actions(p)}).",
        f"Restrict ec2:ModifyInstanceAttribute/RunInstances on '{p.get('role')}'."
    ),
    
    # S3 Specific
    "s3_acl_manipulation": lambda p: Recommendation(
        f"S3 ACL: Role '{p.get('role')}' can modify bucket ACLs/policies ({_fmt_actions(p)}) - public exposure risk!",
        f"Remove S3 ACL/policy modification permissions from '{p.get('role')}'."
    ),
    "s3_replication_exfil": lambda p: Recommendation(
        f"S3 REPLICATION: Role '{p.get('role')}' can setup replication ({_fmt_actions(p)}) - data exfiltration risk.",
        f"Restrict S3 replication permissions on '{p.get('role')}'."
    ),
    "s3_lock_bypass": lambda p: Recommendation(
        f"S3 LOCK BYPASS: Role '{p.get('role')}' can bypass object lock ({_fmt_actions(p)}).",
        f"Remove S3 object lock bypass permissions from '{p.get('role')}'."
    ),
    "s3_mass_delete": lambda p: Recommendation(
        f"S3 DELETE: Role '{p.get('role')}' can delete S3 data broadly ({_fmt_actions(p)}) - ransomware risk!",
        f"Restrict S3 delete permissions on '{p.get('role')}' to specific buckets."
    ),
    
    # Network
    "security_group_manipulation": lambda p: Recommendation(
        f"SECURITY GROUP: Role '{p.get('role')}' can modify firewall rules ({_fmt_actions(p)}).",
        f"Restrict security group modification on '{p.get('role')}'."
    ),
}


def get_recommendation(path: Dict[str, Any]) -> Recommendation | None:
    
    # Get recommendation for a detected attack path.
    path_type = path.get("type", "")
    
    # Direct match
    if path_type in PATTERN_RECOMMENDATIONS:
        return PATTERN_RECOMMENDATIONS[path_type](path)
    
    # Generic cross-service lambda pattern
    if path_type.startswith("cross_service_") and "lambda" in path_type:
        source_type = path_type.replace("cross_service_", "").replace("_lambda", "").upper()
        return Recommendation(
            f"CROSS-SERVICE: {source_type} → Lambda '{path.get('target')}' (message injection can trigger code).",
            f"Review Lambda '{path.get('target')}' permissions - {source_type} trigger enables indirect execution."
        )
    
    return None


def generate_recommendations(paths: List[Dict[str, Any]]) -> tuple[List[str], List[str]]:
    
    # Generate blocking issues and recommendations for all paths.
    blocking_issues = []
    recommendations = []
    
    for path in paths:
        rec = get_recommendation(path)
        if rec:
            blocking_issues.append(rec.issue)
            recommendations.append(rec.recommendation)
    
    return blocking_issues, recommendations
