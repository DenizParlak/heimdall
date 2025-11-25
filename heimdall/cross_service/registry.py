# ᚺᛖᛁᛗᛞᚨᛚᛚ • Heimdall's Registry - Service Discovery and Registration
"""
Service Registry for cross-service analysis.

Manages the registration and discovery of service-specific analyzers,
allowing modular addition of new AWS service analysis capabilities.
"""

from typing import Dict, List, Type, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging

from .models import ServiceType, ResourcePolicy, ServicePermission

logger = logging.getLogger(__name__)


@dataclass
class ServiceCapabilities:
    """Describes the capabilities of a service analyzer."""
    service: ServiceType
    
    # What this analyzer can do
    can_enumerate: bool = True          # Can list resources
    can_get_policies: bool = True       # Can retrieve resource policies
    can_analyze_permissions: bool = True # Can analyze permissions
    can_detect_escalation: bool = True   # Can detect privilege escalation
    
    # Required IAM permissions for scanning
    required_permissions: List[str] = field(default_factory=list)
    
    # Service-specific features
    features: Dict[str, bool] = field(default_factory=dict)


class ServiceAnalyzerBase:
    """Base class for service-specific analyzers."""
    
    SERVICE_TYPE: ServiceType = ServiceType.IAM
    
    def __init__(self, session: Any = None, account_id: str = "", region: str = ""):
        self.session = session
        self.account_id = account_id
        self.region = region
        self._client = None
        self._resources: List[Dict] = []
        self._policies: List[ResourcePolicy] = []
    
    @property
    def client(self):
        """Lazy-load the boto3 client."""
        if self._client is None and self.session:
            self._client = self.session.client(
                self.SERVICE_TYPE.value,
                region_name=self.region if self.region else None
            )
        return self._client
    
    @classmethod
    def get_capabilities(cls) -> ServiceCapabilities:
        """Return the capabilities of this analyzer."""
        return ServiceCapabilities(service=cls.SERVICE_TYPE)
    
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """Enumerate resources of this service type."""
        raise NotImplementedError
    
    def get_resource_policy(self, resource_arn: str) -> Optional[ResourcePolicy]:
        """Get the resource-based policy for a resource."""
        raise NotImplementedError
    
    def analyze_permissions(
        self, 
        principal_arn: str, 
        iam_permissions: List[ServicePermission]
    ) -> List[ServicePermission]:
        """
        Analyze what permissions a principal has on this service's resources.
        Combines IAM identity-based policies with resource-based policies.
        """
        raise NotImplementedError
    
    def find_escalation_paths(
        self,
        principal_arn: str,
        permissions: List[ServicePermission]
    ) -> List[Dict[str, Any]]:
        """Find privilege escalation paths through this service."""
        raise NotImplementedError
    
    def get_trust_relationships(self) -> List[Dict[str, Any]]:
        """Get trust relationships involving this service."""
        return []
    
    def get_cross_account_access(self) -> List[Dict[str, Any]]:
        """Find cross-account access patterns."""
        return []


class ServiceRegistry:
    """
    Registry for service analyzers.
    
    Manages registration, discovery, and instantiation of
    service-specific analyzers for cross-service analysis.
    """
    
    _instance: Optional['ServiceRegistry'] = None
    _analyzers: Dict[ServiceType, Type[ServiceAnalyzerBase]] = {}
    _capabilities: Dict[ServiceType, ServiceCapabilities] = {}
    
    def __new__(cls):
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def register(cls, service_type: ServiceType):
        """
        Decorator to register a service analyzer.
        
        Usage:
            @ServiceRegistry.register(ServiceType.S3)
            class S3Analyzer(ServiceAnalyzerBase):
                ...
        """
        def decorator(analyzer_class: Type[ServiceAnalyzerBase]):
            cls._analyzers[service_type] = analyzer_class
            cls._capabilities[service_type] = analyzer_class.get_capabilities()
            logger.debug(f"Registered analyzer for {service_type.value}")
            return analyzer_class
        return decorator
    
    @classmethod
    def get_analyzer(
        cls, 
        service_type: ServiceType,
        session: Any = None,
        account_id: str = "",
        region: str = ""
    ) -> Optional[ServiceAnalyzerBase]:
        """Get an instance of a service analyzer."""
        analyzer_class = cls._analyzers.get(service_type)
        if analyzer_class:
            return analyzer_class(session=session, account_id=account_id, region=region)
        return None
    
    @classmethod
    def get_all_analyzers(
        cls,
        session: Any = None,
        account_id: str = "",
        region: str = ""
    ) -> Dict[ServiceType, ServiceAnalyzerBase]:
        """Get instances of all registered analyzers."""
        return {
            st: cls.get_analyzer(st, session, account_id, region)
            for st in cls._analyzers.keys()
        }
    
    @classmethod
    def list_registered_services(cls) -> List[ServiceType]:
        """List all registered service types."""
        return list(cls._analyzers.keys())
    
    @classmethod
    def get_capabilities(cls, service_type: ServiceType) -> Optional[ServiceCapabilities]:
        """Get capabilities of a specific service analyzer."""
        return cls._capabilities.get(service_type)
    
    @classmethod
    def is_registered(cls, service_type: ServiceType) -> bool:
        """Check if a service analyzer is registered."""
        return service_type in cls._analyzers
    
    @classmethod
    def get_services_with_feature(cls, feature: str) -> List[ServiceType]:
        """Get all services that support a specific feature."""
        result = []
        for service_type, caps in cls._capabilities.items():
            if caps.features.get(feature, False):
                result.append(service_type)
        return result
    
    @classmethod
    def clear(cls):
        """Clear all registered analyzers (mainly for testing)."""
        cls._analyzers.clear()
        cls._capabilities.clear()


# Permission mappings for cross-service escalation detection
CROSS_SERVICE_ESCALATION_PATTERNS = {
    # Service -> list of (action_pattern, target_service, escalation_type, severity)
    ServiceType.IAM: [
        ("iam:PassRole", ServiceType.LAMBDA, "passrole_lambda", "HIGH"),
        ("iam:PassRole", ServiceType.EC2, "passrole_ec2", "HIGH"),
        ("iam:PassRole", ServiceType.ECS, "passrole_ecs", "HIGH"),
        ("iam:PassRole", ServiceType.GLUE, "passrole_glue", "HIGH"),
        ("iam:PassRole", ServiceType.SAGEMAKER, "passrole_sagemaker", "HIGH"),
        ("iam:PassRole", ServiceType.CODEBUILD, "passrole_codebuild", "HIGH"),
        ("iam:PassRole", ServiceType.CLOUDFORMATION, "passrole_cfn", "CRITICAL"),
        ("iam:CreateAccessKey", ServiceType.IAM, "create_access_key", "CRITICAL"),
        ("iam:CreateLoginProfile", ServiceType.IAM, "create_login_profile", "CRITICAL"),
        ("iam:UpdateAssumeRolePolicy", ServiceType.STS, "update_trust_policy", "CRITICAL"),
        ("iam:AttachRolePolicy", ServiceType.IAM, "attach_policy", "CRITICAL"),
        ("iam:PutRolePolicy", ServiceType.IAM, "put_policy", "CRITICAL"),
    ],
    ServiceType.LAMBDA: [
        ("lambda:UpdateFunctionCode", ServiceType.LAMBDA, "lambda_code_injection", "CRITICAL"),
        ("lambda:UpdateFunctionConfiguration", ServiceType.LAMBDA, "lambda_env_modify", "HIGH"),
        ("lambda:CreateFunction", ServiceType.LAMBDA, "lambda_create", "HIGH"),
        ("lambda:InvokeFunction", ServiceType.LAMBDA, "lambda_invoke", "MEDIUM"),
        ("lambda:AddPermission", ServiceType.LAMBDA, "lambda_permission", "HIGH"),
        ("lambda:PublishLayerVersion", ServiceType.LAMBDA, "lambda_layer", "HIGH"),
    ],
    ServiceType.S3: [
        ("s3:PutBucketPolicy", ServiceType.S3, "s3_policy_modify", "CRITICAL"),
        ("s3:PutObject", ServiceType.LAMBDA, "s3_lambda_trigger", "HIGH"),
        ("s3:GetObject", ServiceType.S3, "s3_data_access", "MEDIUM"),
        ("s3:DeleteBucketPolicy", ServiceType.S3, "s3_policy_delete", "HIGH"),
    ],
    ServiceType.KMS: [
        ("kms:CreateGrant", ServiceType.KMS, "kms_grant", "HIGH"),
        ("kms:PutKeyPolicy", ServiceType.KMS, "kms_policy_modify", "CRITICAL"),
        ("kms:Decrypt", ServiceType.SECRETS_MANAGER, "decrypt_secrets", "HIGH"),
        ("kms:Encrypt", ServiceType.KMS, "kms_encrypt", "MEDIUM"),
    ],
    ServiceType.STS: [
        ("sts:AssumeRole", ServiceType.IAM, "assume_role", "HIGH"),
        ("sts:AssumeRoleWithSAML", ServiceType.IAM, "assume_role_saml", "HIGH"),
        ("sts:AssumeRoleWithWebIdentity", ServiceType.IAM, "assume_role_oidc", "HIGH"),
        ("sts:GetFederationToken", ServiceType.STS, "federation_token", "HIGH"),
    ],
    ServiceType.SECRETS_MANAGER: [
        ("secretsmanager:GetSecretValue", ServiceType.SECRETS_MANAGER, "get_secret", "HIGH"),
        ("secretsmanager:PutSecretValue", ServiceType.SECRETS_MANAGER, "put_secret", "HIGH"),
        ("secretsmanager:UpdateSecret", ServiceType.SECRETS_MANAGER, "update_secret", "HIGH"),
    ],
    ServiceType.EC2: [
        ("ec2:RunInstances", ServiceType.EC2, "run_instance", "HIGH"),
        ("ec2:AssociateIamInstanceProfile", ServiceType.EC2, "associate_profile", "CRITICAL"),
        ("ec2:ModifyInstanceAttribute", ServiceType.EC2, "modify_instance", "HIGH"),
        ("ssm:SendCommand", ServiceType.EC2, "ssm_command", "CRITICAL"),
        ("ssm:StartSession", ServiceType.EC2, "ssm_session", "HIGH"),
    ],
    ServiceType.CLOUDFORMATION: [
        ("cloudformation:CreateStack", ServiceType.CLOUDFORMATION, "cfn_create", "CRITICAL"),
        ("cloudformation:UpdateStack", ServiceType.CLOUDFORMATION, "cfn_update", "CRITICAL"),
        ("cloudformation:SetStackPolicy", ServiceType.CLOUDFORMATION, "cfn_policy", "HIGH"),
    ],
    ServiceType.CODEBUILD: [
        ("codebuild:StartBuild", ServiceType.CODEBUILD, "codebuild_start", "HIGH"),
        ("codebuild:UpdateProject", ServiceType.CODEBUILD, "codebuild_update", "CRITICAL"),
        ("codebuild:CreateProject", ServiceType.CODEBUILD, "codebuild_create", "HIGH"),
    ],
    ServiceType.GLUE: [
        ("glue:CreateDevEndpoint", ServiceType.GLUE, "glue_dev_endpoint", "CRITICAL"),
        ("glue:UpdateDevEndpoint", ServiceType.GLUE, "glue_update_endpoint", "HIGH"),
        ("glue:CreateJob", ServiceType.GLUE, "glue_job", "HIGH"),
    ],
}


# High-value targets that indicate critical access
HIGH_VALUE_TARGETS = {
    "admin", "administrator", "root", "production", "prod",
    "master", "main", "core", "infrastructure", "infra",
    "security", "audit", "billing", "finance", "pci",
    "hipaa", "compliance", "secret", "credential", "key",
    "password", "token", "api", "database", "db", "rds",
    "dynamo", "s3", "bucket", "kms", "encryption",
}


def get_escalation_patterns(
    source_service: ServiceType
) -> List[tuple]:
    """Get escalation patterns for a source service."""
    return CROSS_SERVICE_ESCALATION_PATTERNS.get(source_service, [])


def is_high_value_target(resource_name: str) -> bool:
    """Check if a resource name indicates a high-value target."""
    name_lower = resource_name.lower()
    return any(target in name_lower for target in HIGH_VALUE_TARGETS)


# Multi-hop attack chain patterns
# Each pattern: (name, hops, severity, description, mitre_techniques)
# hops: list of (action_pattern, source_service, target_service)
MULTI_HOP_PATTERNS = [
    # === S3 → Lambda → Secrets ===
    {
        "name": "s3_lambda_secrets_exfil",
        "title": "S3 → Lambda → Secrets Exfiltration",
        "description": "Upload malicious code to S3, trigger Lambda, exfiltrate secrets",
        "severity": "CRITICAL",
        "mitre": ["T1059.006", "T1552.005", "T1041"],
        "hops": [
            {"action": "s3:PutObject", "from": ServiceType.S3, "to": ServiceType.LAMBDA, 
             "desc": "Upload malicious payload to S3 bucket with Lambda trigger"},
            {"action": "lambda:InvokeFunction", "from": ServiceType.LAMBDA, "to": ServiceType.SECRETS_MANAGER,
             "desc": "Lambda triggered, executes malicious code with execution role"},
            {"action": "secretsmanager:GetSecretValue", "from": ServiceType.SECRETS_MANAGER, "to": ServiceType.SECRETS_MANAGER,
             "desc": "Retrieve secrets using Lambda's execution role credentials"},
        ],
        "requirements": {
            "s3_trigger": True,  # S3 bucket must have Lambda trigger
            "lambda_role_secrets": True,  # Lambda role must have secrets access
        },
    },
    # === EC2 → IMDS → STS (Credential Theft) ===
    {
        "name": "ec2_imds_lateral_movement",
        "title": "EC2 IMDSv1 → Credential Theft → Lateral Movement",
        "description": "Exploit IMDSv1 to steal instance credentials, assume other roles",
        "severity": "CRITICAL",
        "mitre": ["T1552.005", "T1078.004", "T1550.001"],
        "hops": [
            {"action": "imds:GetCredentials", "from": ServiceType.EC2, "to": ServiceType.STS,
             "desc": "Access IMDS v1 endpoint to retrieve temporary credentials"},
            {"action": "sts:AssumeRole", "from": ServiceType.STS, "to": ServiceType.IAM,
             "desc": "Use stolen credentials to assume another role"},
            {"action": "*:*", "from": ServiceType.IAM, "to": ServiceType.IAM,
             "desc": "Access resources with assumed role's permissions"},
        ],
        "requirements": {
            "imdsv1_enabled": True,
            "instance_profile": True,
        },
    },
    # === PassRole → Lambda → Data Exfil ===
    {
        "name": "passrole_lambda_data_exfil",
        "title": "PassRole → Lambda Creation → Data Exfiltration",
        "description": "Create Lambda with admin role, access all data stores",
        "severity": "CRITICAL",
        "mitre": ["T1078.004", "T1059.006", "T1530"],
        "hops": [
            {"action": "iam:PassRole", "from": ServiceType.IAM, "to": ServiceType.LAMBDA,
             "desc": "Pass privileged role to Lambda service"},
            {"action": "lambda:CreateFunction", "from": ServiceType.LAMBDA, "to": ServiceType.LAMBDA,
             "desc": "Create Lambda function with privileged execution role"},
            {"action": "dynamodb:Scan", "from": ServiceType.LAMBDA, "to": ServiceType.DYNAMODB,
             "desc": "Scan all DynamoDB tables with Lambda's elevated permissions"},
        ],
        "requirements": {
            "passrole": True,
            "create_lambda": True,
        },
    },
    # === KMS → Secrets → RDS ===
    {
        "name": "kms_secrets_rds_chain",
        "title": "KMS Decrypt → Secrets → Database Access",
        "description": "Decrypt KMS key to read secrets containing DB credentials",
        "severity": "HIGH",
        "mitre": ["T1552.005", "T1078.004", "T1213"],
        "hops": [
            {"action": "kms:Decrypt", "from": ServiceType.KMS, "to": ServiceType.SECRETS_MANAGER,
             "desc": "Decrypt data using KMS key"},
            {"action": "secretsmanager:GetSecretValue", "from": ServiceType.SECRETS_MANAGER, "to": ServiceType.RDS,
             "desc": "Retrieve database credentials from Secrets Manager"},
            {"action": "rds-db:connect", "from": ServiceType.RDS, "to": ServiceType.RDS,
             "desc": "Connect to RDS database using retrieved credentials"},
        ],
        "requirements": {
            "kms_decrypt": True,
            "secrets_access": True,
        },
    },
    # === SSM → EC2 → Cloud Credentials ===
    {
        "name": "ssm_ec2_cloud_creds",
        "title": "SSM Session → EC2 Instance → Cloud Credential Access",
        "description": "Start SSM session, access instance, retrieve cloud credentials",
        "severity": "CRITICAL",
        "mitre": ["T1021.007", "T1552.005", "T1078.004"],
        "hops": [
            {"action": "ssm:StartSession", "from": ServiceType.EC2, "to": ServiceType.EC2,
             "desc": "Start SSM session to managed instance"},
            {"action": "shell:ExecuteCommand", "from": ServiceType.EC2, "to": ServiceType.EC2,
             "desc": "Execute commands on instance to retrieve credentials"},
            {"action": "sts:AssumeRole", "from": ServiceType.STS, "to": ServiceType.IAM,
             "desc": "Use instance profile credentials to access AWS resources"},
        ],
        "requirements": {
            "ssm_managed": True,
            "instance_profile": True,
        },
    },
    # === S3 Public → Data Exfil → External ===
    {
        "name": "s3_public_exfil",
        "title": "Public S3 → Sensitive Data → External Exfiltration",
        "description": "Access public bucket containing sensitive data, exfiltrate externally",
        "severity": "CRITICAL",
        "mitre": ["T1530", "T1537", "T1041"],
        "hops": [
            {"action": "s3:GetObject", "from": ServiceType.S3, "to": ServiceType.S3,
             "desc": "Access publicly accessible S3 bucket"},
            {"action": "s3:ListBucket", "from": ServiceType.S3, "to": ServiceType.S3,
             "desc": "Enumerate objects in bucket to find sensitive data"},
            {"action": "external:Exfiltrate", "from": ServiceType.S3, "to": ServiceType.S3,
             "desc": "Download and exfiltrate sensitive data externally"},
        ],
        "requirements": {
            "public_bucket": True,
            "sensitive_data": True,
        },
    },
]


def get_multi_hop_patterns() -> List[dict]:
    """Get all multi-hop attack chain patterns."""
    return MULTI_HOP_PATTERNS


def find_matching_multi_hop(
    permissions: List[ServicePermission],
    analyzer_data: dict
) -> List[dict]:
    """
    Find multi-hop patterns that match the given permissions and analyzer data.
    
    Args:
        permissions: List of permissions the principal has
        analyzer_data: Dict containing data from all analyzers (public buckets, IMDSv1, etc.)
    
    Returns:
        List of matching multi-hop patterns with context
    """
    matches = []
    
    # Index permissions by action prefix for quick lookup
    action_set = {p.action.lower() for p in permissions if p.effect == "Allow"}
    has_wildcard = "*" in action_set or "*:*" in action_set
    
    for pattern in MULTI_HOP_PATTERNS:
        # Check if all required actions are available
        can_execute = True
        matched_hops = []
        
        for hop in pattern["hops"]:
            action = hop["action"].lower()
            # Check if principal has this action
            if has_wildcard:
                matched_hops.append(hop)
            elif action in action_set:
                matched_hops.append(hop)
            elif any(action.startswith(a.rstrip("*")) for a in action_set if a.endswith("*")):
                matched_hops.append(hop)
            else:
                # Check if requirement is met by analyzer data
                req = pattern.get("requirements", {})
                if "imdsv1_enabled" in req and analyzer_data.get("imdsv1_instances"):
                    matched_hops.append(hop)
                elif "public_bucket" in req and analyzer_data.get("public_buckets"):
                    matched_hops.append(hop)
                elif "s3_trigger" in req and analyzer_data.get("s3_lambda_triggers"):
                    matched_hops.append(hop)
                else:
                    can_execute = False
                    break
        
        if can_execute and len(matched_hops) >= 2:
            matches.append({
                "pattern": pattern,
                "matched_hops": matched_hops,
            })
    
    return matches
