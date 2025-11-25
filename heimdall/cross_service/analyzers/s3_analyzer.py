# ᛊᚲᛁᛞᛒᛚᚨᛞᚾᛁᚱ • Skíðblaðnir - S3 Bucket Analyzer
"""S3 Bucket Analyzer for cross-service privilege escalation detection."""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging
import json
import re

from ..models import ServiceType, Severity, ServicePermission, ResourcePolicy
from ..registry import ServiceRegistry, ServiceAnalyzerBase, ServiceCapabilities

logger = logging.getLogger(__name__)

# Sensitive bucket patterns
SENSITIVE_PATTERNS = [
    r".*backup.*", r".*secret.*", r".*credential.*", r".*private.*",
    r".*confidential.*", r".*pii.*", r".*hipaa.*", r".*pci.*",
    r".*cloudtrail.*", r".*terraform.*", r".*state.*", r".*prod.*",
]

# Dangerous S3 actions
DANGEROUS_ACTIONS = {
    "s3:PutBucketPolicy": (Severity.CRITICAL, "policy_modification"),
    "s3:DeleteBucketPolicy": (Severity.HIGH, "policy_deletion"),
    "s3:PutBucketAcl": (Severity.HIGH, "acl_modification"),
    "s3:PutBucketNotification": (Severity.HIGH, "event_trigger"),
    "s3:PutReplicationConfiguration": (Severity.HIGH, "data_exfiltration"),
}


@dataclass
class S3BucketInfo:
    """S3 bucket information."""
    name: str
    arn: str
    region: str = ""
    policy: Optional[Dict] = None
    acl: Optional[Dict] = None
    public_access_block: Optional[Dict] = None
    encryption_enabled: bool = False
    kms_key_id: str = ""
    versioning_enabled: bool = False
    logging_enabled: bool = False
    website_enabled: bool = False
    lambda_triggers: List[Dict] = field(default_factory=list)
    replication_destinations: List[str] = field(default_factory=list)
    is_public: bool = False
    public_access_type: str = ""
    allows_cross_account: bool = False
    cross_account_principals: List[str] = field(default_factory=list)
    is_sensitive: bool = False
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@ServiceRegistry.register(ServiceType.S3)
class S3Analyzer(ServiceAnalyzerBase):
    """S3 Bucket Analyzer for cross-service privilege escalation."""
    
    SERVICE_TYPE = ServiceType.S3
    
    def __init__(self, session: Any = None, account_id: str = "", region: str = ""):
        super().__init__(session, account_id, region)
        self._buckets: Dict[str, S3BucketInfo] = {}
    
    @classmethod
    def get_capabilities(cls) -> ServiceCapabilities:
        return ServiceCapabilities(
            service=ServiceType.S3,
            required_permissions=[
                "s3:ListAllMyBuckets", "s3:GetBucketPolicy", "s3:GetBucketAcl",
                "s3:GetBucketLocation", "s3:GetBucketNotification",
                "s3:GetBucketEncryption", "s3:GetBucketPublicAccessBlock",
            ],
            features={
                "public_bucket_detection": True,
                "cross_account_analysis": True,
                "event_trigger_analysis": True,
            },
        )
    
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """Enumerate all S3 buckets."""
        if not self.client:
            return []
        
        buckets = []
        try:
            response = self.client.list_buckets()
            for bucket in response.get("Buckets", []):
                bucket_name = bucket["Name"]
                info = self._analyze_bucket(bucket_name)
                if info:
                    self._buckets[bucket_name] = info
                    buckets.append({
                        "name": bucket_name,
                        "arn": info.arn,
                        "region": info.region,
                        "is_public": info.is_public,
                        "is_sensitive": info.is_sensitive,
                        "risk_score": info.risk_score,
                    })
            logger.info(f"Enumerated {len(buckets)} S3 buckets")
        except Exception as e:
            logger.error(f"Failed to enumerate S3 buckets: {e}")
        return buckets
    
    def _analyze_bucket(self, bucket_name: str) -> Optional[S3BucketInfo]:
        """Analyze a single bucket."""
        try:
            info = S3BucketInfo(name=bucket_name, arn=f"arn:aws:s3:::{bucket_name}")
            
            # Region
            try:
                resp = self.client.get_bucket_location(Bucket=bucket_name)
                info.region = resp.get("LocationConstraint") or "us-east-1"
            except: pass
            
            # Policy
            try:
                resp = self.client.get_bucket_policy(Bucket=bucket_name)
                info.policy = json.loads(resp.get("Policy", "{}"))
            except: pass
            
            # ACL
            try:
                info.acl = self.client.get_bucket_acl(Bucket=bucket_name)
            except: pass
            
            # Public Access Block
            try:
                resp = self.client.get_public_access_block(Bucket=bucket_name)
                info.public_access_block = resp.get("PublicAccessBlockConfiguration")
            except: pass
            
            # Encryption
            try:
                resp = self.client.get_bucket_encryption(Bucket=bucket_name)
                rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    info.encryption_enabled = True
                    cfg = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                    info.kms_key_id = cfg.get("KMSMasterKeyID", "")
            except: pass
            
            # Notifications (Lambda triggers)
            try:
                resp = self.client.get_bucket_notification_configuration(Bucket=bucket_name)
                for cfg in resp.get("LambdaFunctionConfigurations", []):
                    info.lambda_triggers.append({
                        "function_arn": cfg.get("LambdaFunctionArn"),
                        "events": cfg.get("Events", []),
                    })
            except: pass
            
            # Website
            try:
                self.client.get_bucket_website(Bucket=bucket_name)
                info.website_enabled = True
            except: pass
            
            # Analyze access
            self._analyze_public_access(info)
            self._analyze_cross_account(info)
            self._analyze_sensitivity(info)
            self._calculate_risk(info)
            
            return info
        except Exception as e:
            logger.warning(f"Failed to analyze bucket {bucket_name}: {e}")
            return None
    
    def _analyze_public_access(self, info: S3BucketInfo) -> None:
        """Check for public access."""
        # Check public access block
        pab = info.public_access_block
        if pab and all([
            pab.get("BlockPublicAcls"), pab.get("IgnorePublicAcls"),
            pab.get("BlockPublicPolicy"), pab.get("RestrictPublicBuckets")
        ]):
            return
        
        # Check policy
        if info.policy:
            for stmt in info.policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", {})
                if principal == "*" or (isinstance(principal, dict) and 
                    principal.get("AWS") in ["*", ["*"]]):
                    if not self._has_restrictive_conditions(stmt.get("Condition", {})):
                        info.is_public = True
                        info.public_access_type = "policy"
                        info.risk_factors.append("Public via bucket policy")
                        return
        
        # Check ACL
        if info.acl:
            public_uris = [
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            ]
            for grant in info.acl.get("Grants", []):
                if grant.get("Grantee", {}).get("URI") in public_uris:
                    info.is_public = True
                    info.public_access_type = "acl"
                    info.risk_factors.append("Public via ACL")
                    return
    
    def _has_restrictive_conditions(self, conditions: Dict) -> bool:
        """Check for restrictive conditions."""
        if not conditions:
            return False
        keys = ["aws:SourceAccount", "aws:SourceArn", "aws:SourceVpc",
                "aws:PrincipalOrgID", "aws:PrincipalAccount", "aws:SourceIp"]
        cond_str = json.dumps(conditions).lower()
        return any(k.lower() in cond_str for k in keys)
    
    def _analyze_cross_account(self, info: S3BucketInfo) -> None:
        """Analyze cross-account access."""
        if not info.policy or not self.account_id:
            return
        for stmt in info.policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principals = self._extract_principals(stmt.get("Principal", {}))
            for p in principals:
                if p == "*":
                    continue
                parts = p.split(":") if ":" in p else []
                if len(parts) >= 5 and parts[4] != self.account_id:
                    info.allows_cross_account = True
                    info.cross_account_principals.append(p)
                    info.risk_factors.append(f"Cross-account: {parts[4]}")
    
    def _extract_principals(self, principal: Any) -> List[str]:
        """Extract principals from policy."""
        if principal == "*":
            return ["*"]
        if isinstance(principal, str):
            return [principal]
        if isinstance(principal, dict):
            result = []
            for v in principal.values():
                if isinstance(v, list):
                    result.extend(v)
                else:
                    result.append(v)
            return result
        return []
    
    def _analyze_sensitivity(self, info: S3BucketInfo) -> None:
        """Check for sensitive bucket indicators."""
        name_lower = info.name.lower()
        for pattern in SENSITIVE_PATTERNS:
            if re.match(pattern, name_lower):
                info.is_sensitive = True
                info.risk_factors.append(f"Sensitive name pattern: {pattern}")
                break
    
    def _calculate_risk(self, info: S3BucketInfo) -> None:
        """Calculate risk score."""
        score = 0
        if info.is_public: score += 40
        if info.allows_cross_account: score += 20
        if info.is_sensitive: score += 15
        if not info.encryption_enabled: score += 10
        if info.lambda_triggers: score += 15
        if not info.public_access_block: score += 10
        info.risk_score = min(100, score)
    
    def get_resource_policy(self, resource_arn: str) -> Optional[ResourcePolicy]:
        """Get bucket policy as ResourcePolicy."""
        bucket_name = resource_arn.replace("arn:aws:s3:::", "").split("/")[0]
        info = self._buckets.get(bucket_name)
        if not info or not info.policy:
            return None
        
        policy = ResourcePolicy(
            resource_arn=resource_arn,
            resource_type=ServiceType.S3,
            policy_document=info.policy,
            resource_name=bucket_name,
            account_id=self.account_id,
            region=info.region,
        )
        policy.parse_policy()
        policy.is_public = info.is_public
        policy.allows_cross_account = info.allows_cross_account
        return policy
    
    def find_escalation_paths(
        self, principal_arn: str, permissions: List[ServicePermission]
    ) -> List[Dict[str, Any]]:
        """Find S3-based privilege escalation paths."""
        paths = []
        
        for perm in permissions:
            if perm.service != ServiceType.S3 or perm.effect != "Allow":
                continue
            
            # Check for dangerous actions
            for action, (severity, esc_type) in DANGEROUS_ACTIONS.items():
                if self._action_matches(perm.action, action):
                    paths.append({
                        "type": esc_type,
                        "action": action,
                        "resource": perm.resource,
                        "severity": severity.value,
                        "description": f"Can {action} on {perm.resource}",
                    })
            
            # Check for Lambda trigger abuse
            if self._action_matches(perm.action, "s3:PutBucketNotification"):
                for bucket_name, info in self._buckets.items():
                    if self._resource_matches(perm.resource, info.arn):
                        paths.append({
                            "type": "lambda_trigger",
                            "action": "s3:PutBucketNotification",
                            "resource": info.arn,
                            "severity": "HIGH",
                            "description": f"Can configure Lambda triggers on {bucket_name}",
                            "lambda_targets": [t["function_arn"] for t in info.lambda_triggers],
                        })
        
        return paths
    
    def _action_matches(self, action: str, pattern: str) -> bool:
        """Check if action matches pattern."""
        if action == "*" or action == "s3:*":
            return True
        return action.lower() == pattern.lower() or (
            pattern.endswith("*") and action.lower().startswith(pattern[:-1].lower())
        )
    
    def _resource_matches(self, resource: str, arn: str) -> bool:
        """Check if resource pattern matches ARN."""
        if resource == "*":
            return True
        if resource.endswith("*"):
            return arn.startswith(resource[:-1])
        return resource == arn
    
    def get_public_buckets(self) -> List[S3BucketInfo]:
        """Get all public buckets."""
        return [b for b in self._buckets.values() if b.is_public]
    
    def get_sensitive_buckets(self) -> List[S3BucketInfo]:
        """Get all sensitive buckets."""
        return [b for b in self._buckets.values() if b.is_sensitive]
    
    def get_cross_account_buckets(self) -> List[S3BucketInfo]:
        """Get buckets with cross-account access."""
        return [b for b in self._buckets.values() if b.allows_cross_account]
    
    def get_high_risk_buckets(self, threshold: int = 50) -> List[S3BucketInfo]:
        """Get buckets above risk threshold."""
        return [b for b in self._buckets.values() if b.risk_score >= threshold]
