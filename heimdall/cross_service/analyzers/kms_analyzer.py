# ᚷᛚᛖᛁᛈᚾᛁᚱ • Gleipnir - The Unbreakable Chain (KMS Analyzer)
"""KMS Key Analyzer for cross-service privilege escalation detection."""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging
import json

from ..models import ServiceType, Severity, ServicePermission, ResourcePolicy
from ..registry import ServiceRegistry, ServiceAnalyzerBase, ServiceCapabilities

logger = logging.getLogger(__name__)

# Dangerous KMS actions
DANGEROUS_KMS_ACTIONS = {
    "kms:PutKeyPolicy": (Severity.CRITICAL, "key_policy_modification"),
    "kms:CreateGrant": (Severity.HIGH, "grant_creation"),
    "kms:ScheduleKeyDeletion": (Severity.HIGH, "key_deletion"),
    "kms:DisableKey": (Severity.HIGH, "key_disable"),
    "kms:Decrypt": (Severity.MEDIUM, "decrypt"),
    "kms:Encrypt": (Severity.LOW, "encrypt"),
    "kms:GenerateDataKey": (Severity.MEDIUM, "generate_key"),
    "kms:CreateKey": (Severity.MEDIUM, "key_creation"),
}


@dataclass
class KMSKeyInfo:
    """KMS key information."""
    key_id: str
    arn: str
    alias: str = ""
    description: str = ""
    key_state: str = ""  # Enabled, Disabled, PendingDeletion
    key_usage: str = ""  # ENCRYPT_DECRYPT, SIGN_VERIFY
    key_spec: str = ""   # SYMMETRIC_DEFAULT, RSA_2048, etc.
    origin: str = ""     # AWS_KMS, EXTERNAL, AWS_CLOUDHSM
    key_manager: str = ""  # AWS or CUSTOMER
    creation_date: str = ""
    
    # Policy
    key_policy: Optional[Dict] = None
    
    # Grants
    grants: List[Dict] = field(default_factory=list)
    
    # Access analysis
    allows_public: bool = False
    allows_cross_account: bool = False
    cross_account_principals: List[str] = field(default_factory=list)
    admin_principals: List[str] = field(default_factory=list)
    
    # Usage info
    used_by_services: List[str] = field(default_factory=list)
    
    # Risk
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@ServiceRegistry.register(ServiceType.KMS)
class KMSAnalyzer(ServiceAnalyzerBase):
    """KMS Key Analyzer for cross-service privilege escalation."""
    
    SERVICE_TYPE = ServiceType.KMS
    
    def __init__(self, session: Any = None, account_id: str = "", region: str = ""):
        super().__init__(session, account_id, region)
        self._keys: Dict[str, KMSKeyInfo] = {}
    
    @classmethod
    def get_capabilities(cls) -> ServiceCapabilities:
        return ServiceCapabilities(
            service=ServiceType.KMS,
            required_permissions=[
                "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy",
                "kms:ListGrants", "kms:ListAliases",
            ],
            features={
                "key_policy_analysis": True,
                "grant_analysis": True,
                "cross_account_detection": True,
            },
        )
    
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """Enumerate all KMS keys."""
        if not self.client:
            return []
        
        keys = []
        aliases = self._get_aliases()
        
        try:
            paginator = self.client.get_paginator('list_keys')
            for page in paginator.paginate():
                for key in page.get('Keys', []):
                    key_id = key.get('KeyId', '')
                    info = self._analyze_key(key_id, aliases)
                    if info:
                        self._keys[key_id] = info
                        keys.append({
                            "key_id": key_id,
                            "arn": info.arn,
                            "alias": info.alias,
                            "key_state": info.key_state,
                            "key_manager": info.key_manager,
                            "risk_score": info.risk_score,
                        })
            logger.info(f"Enumerated {len(keys)} KMS keys")
        except Exception as e:
            logger.error(f"Failed to enumerate KMS keys: {e}")
        return keys
    
    def _get_aliases(self) -> Dict[str, str]:
        """Get key aliases mapping."""
        aliases = {}
        try:
            paginator = self.client.get_paginator('list_aliases')
            for page in paginator.paginate():
                for alias in page.get('Aliases', []):
                    key_id = alias.get('TargetKeyId', '')
                    if key_id:
                        aliases[key_id] = alias.get('AliasName', '')
        except Exception as e:
            logger.debug(f"Could not get aliases: {e}")
        return aliases
    
    def _analyze_key(self, key_id: str, aliases: Dict[str, str]) -> Optional[KMSKeyInfo]:
        """Analyze a single KMS key."""
        try:
            # Describe key
            response = self.client.describe_key(KeyId=key_id)
            metadata = response.get('KeyMetadata', {})
            
            # Skip AWS managed keys for detailed analysis
            key_manager = metadata.get('KeyManager', '')
            
            info = KMSKeyInfo(
                key_id=key_id,
                arn=metadata.get('Arn', ''),
                alias=aliases.get(key_id, ''),
                description=metadata.get('Description', ''),
                key_state=metadata.get('KeyState', ''),
                key_usage=metadata.get('KeyUsage', ''),
                key_spec=metadata.get('KeySpec', ''),
                origin=metadata.get('Origin', ''),
                key_manager=key_manager,
                creation_date=str(metadata.get('CreationDate', '')),
            )
            
            # Only analyze customer managed keys in detail
            if key_manager == 'CUSTOMER':
                # Get key policy
                self._analyze_key_policy(key_id, info)
                
                # Get grants
                self._analyze_grants(key_id, info)
            
            # Calculate risk
            self._calculate_risk(info)
            
            return info
        except Exception as e:
            logger.warning(f"Failed to analyze key {key_id}: {e}")
            return None
    
    def _analyze_key_policy(self, key_id: str, info: KMSKeyInfo) -> None:
        """Analyze key policy."""
        try:
            response = self.client.get_key_policy(KeyId=key_id, PolicyName='default')
            policy_str = response.get('Policy', '{}')
            info.key_policy = json.loads(policy_str)
            
            for stmt in info.key_policy.get('Statement', []):
                if stmt.get('Effect') != 'Allow':
                    continue
                
                principal = stmt.get('Principal', {})
                principals = self._extract_principals(principal)
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                # Check for admin access
                admin_actions = ['kms:*', 'kms:PutKeyPolicy', 'kms:CreateGrant']
                has_admin = any(a in actions for a in admin_actions)
                
                for p in principals:
                    # Public access
                    if p == '*':
                        cond = stmt.get('Condition', {})
                        if not self._has_restrictive_conditions(cond):
                            info.allows_public = True
                            info.risk_factors.append("Public key access")
                    
                    # Cross-account
                    elif self._is_cross_account(p):
                        info.allows_cross_account = True
                        info.cross_account_principals.append(p)
                    
                    # Admin principals
                    if has_admin:
                        info.admin_principals.append(p)
                        
        except Exception as e:
            logger.debug(f"Could not get key policy for {key_id}: {e}")
    
    def _analyze_grants(self, key_id: str, info: KMSKeyInfo) -> None:
        """Analyze key grants."""
        try:
            paginator = self.client.get_paginator('list_grants')
            for page in paginator.paginate(KeyId=key_id):
                for grant in page.get('Grants', []):
                    info.grants.append({
                        "grant_id": grant.get('GrantId'),
                        "grantee_principal": grant.get('GranteePrincipal', ''),
                        "operations": grant.get('Operations', []),
                        "retiring_principal": grant.get('RetiringPrincipal', ''),
                    })
                    
                    # Check for cross-account grants
                    grantee = grant.get('GranteePrincipal', '')
                    if self._is_cross_account(grantee):
                        info.allows_cross_account = True
                        if grantee not in info.cross_account_principals:
                            info.cross_account_principals.append(grantee)
                            info.risk_factors.append(f"Cross-account grant to {grantee.split(':')[4]}")
                    
                    # Service usage
                    if ':service:' in grantee or 'service-role' in grantee:
                        service = grantee.split('/')[-1] if '/' in grantee else grantee
                        if service not in info.used_by_services:
                            info.used_by_services.append(service)
                            
        except Exception as e:
            logger.debug(f"Could not get grants for {key_id}: {e}")
    
    def _extract_principals(self, principal: Any) -> List[str]:
        """Extract principals from policy."""
        if principal == '*':
            return ['*']
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
    
    def _has_restrictive_conditions(self, conditions: Dict) -> bool:
        """Check for restrictive conditions."""
        if not conditions:
            return False
        restrictive = ["aws:SourceAccount", "aws:PrincipalOrgID", "kms:ViaService"]
        cond_str = str(conditions).lower()
        return any(k.lower() in cond_str for k in restrictive)
    
    def _is_cross_account(self, principal: str) -> bool:
        """Check if principal is from different account."""
        if not self.account_id or principal == '*':
            return False
        parts = principal.split(':')
        if len(parts) >= 5:
            return parts[4] != self.account_id and parts[4] != ''
        return False
    
    def _calculate_risk(self, info: KMSKeyInfo) -> None:
        """Calculate risk score."""
        score = 0
        
        # AWS managed keys are lower risk
        if info.key_manager == 'AWS':
            score = 5
            info.risk_score = score
            return
        
        # Public access (critical)
        if info.allows_public:
            score += 50
        
        # Cross-account access
        if info.allows_cross_account:
            score += 25
            
        # Many grants
        if len(info.grants) > 10:
            score += 10
            info.risk_factors.append(f"High grant count: {len(info.grants)}")
        
        # Many admin principals
        if len(info.admin_principals) > 3:
            score += 15
            info.risk_factors.append(f"Many admin principals: {len(info.admin_principals)}")
        
        # Key pending deletion
        if info.key_state == 'PendingDeletion':
            score += 10
            info.risk_factors.append("Key pending deletion")
        
        # External origin
        if info.origin == 'EXTERNAL':
            score += 10
            info.risk_factors.append("External key material")
        
        info.risk_score = min(100, score)
    
    def get_resource_policy(self, resource_arn: str) -> Optional[ResourcePolicy]:
        """Get key policy as ResourcePolicy."""
        key_id = resource_arn.split('/')[-1]
        info = self._keys.get(key_id)
        if not info or not info.key_policy:
            return None
        
        policy = ResourcePolicy(
            resource_arn=resource_arn,
            resource_type=ServiceType.KMS,
            policy_document=info.key_policy,
            resource_name=info.alias or key_id,
            account_id=self.account_id,
            region=self.region,
        )
        policy.parse_policy()
        policy.is_public = info.allows_public
        policy.allows_cross_account = info.allows_cross_account
        return policy
    
    def find_escalation_paths(
        self, principal_arn: str, permissions: List[ServicePermission]
    ) -> List[Dict[str, Any]]:
        """Find KMS-based privilege escalation paths."""
        paths = []
        
        for perm in permissions:
            if perm.service != ServiceType.KMS or perm.effect != "Allow":
                continue
            
            for action, (severity, esc_type) in DANGEROUS_KMS_ACTIONS.items():
                if self._action_matches(perm.action, action):
                    paths.append({
                        "type": esc_type,
                        "action": action,
                        "resource": perm.resource,
                        "severity": severity.value,
                        "description": f"Can {action}",
                    })
        
        return paths
    
    def _action_matches(self, action: str, pattern: str) -> bool:
        if action == "*" or action == "kms:*":
            return True
        return action.lower() == pattern.lower()
    
    # Helper methods
    def get_customer_keys(self) -> List[KMSKeyInfo]:
        """Get customer managed keys."""
        return [k for k in self._keys.values() if k.key_manager == 'CUSTOMER']
    
    def get_public_keys(self) -> List[KMSKeyInfo]:
        """Get keys with public access."""
        return [k for k in self._keys.values() if k.allows_public]
    
    def get_cross_account_keys(self) -> List[KMSKeyInfo]:
        """Get keys with cross-account access."""
        return [k for k in self._keys.values() if k.allows_cross_account]
    
    def get_high_risk_keys(self, threshold: int = 30) -> List[KMSKeyInfo]:
        """Get keys above risk threshold."""
        return [k for k in self._keys.values() if k.risk_score >= threshold]
    
    def get_keys_with_grants(self) -> List[KMSKeyInfo]:
        """Get keys that have grants."""
        return [k for k in self._keys.values() if k.grants]
