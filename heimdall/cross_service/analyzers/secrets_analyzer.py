# ᛗᛁᛗᛁᚱ • Mímir - Keeper of Secrets (Secrets Manager Analyzer)
"""Secrets Manager Analyzer for sensitive data access detection."""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging
import json
import re

from ..models import ServiceType, Severity, ServicePermission, ResourcePolicy
from ..registry import ServiceRegistry, ServiceAnalyzerBase, ServiceCapabilities

logger = logging.getLogger(__name__)

# Sensitive secret name patterns
SENSITIVE_PATTERNS = [
    r".*prod.*", r".*production.*", r".*database.*", r".*db[-_].*",
    r".*password.*", r".*credential.*", r".*api[-_]?key.*",
    r".*token.*", r".*auth.*", r".*secret.*", r".*private.*",
    r".*master.*", r".*admin.*", r".*root.*", r".*rds.*",
]


@dataclass
class SecretInfo:
    """Secrets Manager secret information."""
    name: str
    arn: str
    description: str = ""
    kms_key_id: str = ""
    rotation_enabled: bool = False
    last_rotated: str = ""
    last_accessed: str = ""
    created_date: str = ""
    
    # Tags
    tags: Dict[str, str] = field(default_factory=dict)
    
    # Resource policy
    resource_policy: Optional[Dict] = None
    allows_cross_account: bool = False
    cross_account_principals: List[str] = field(default_factory=list)
    
    # Sensitivity
    is_sensitive: bool = False
    sensitivity_indicators: List[str] = field(default_factory=list)
    
    # Risk
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@ServiceRegistry.register(ServiceType.SECRETS_MANAGER)
class SecretsManagerAnalyzer(ServiceAnalyzerBase):
    """Secrets Manager Analyzer for sensitive data access."""
    
    SERVICE_TYPE = ServiceType.SECRETS_MANAGER
    
    def __init__(self, session: Any = None, account_id: str = "", region: str = ""):
        super().__init__(session, account_id, region)
        self._secrets: Dict[str, SecretInfo] = {}
    
    @classmethod
    def get_capabilities(cls) -> ServiceCapabilities:
        return ServiceCapabilities(
            service=ServiceType.SECRETS_MANAGER,
            required_permissions=[
                "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
                "secretsmanager:GetResourcePolicy",
            ],
            features={
                "resource_policy_analysis": True,
                "cross_account_detection": True,
                "rotation_analysis": True,
            },
        )
    
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """Enumerate all secrets."""
        if not self.client:
            return []
        
        secrets = []
        try:
            paginator = self.client.get_paginator('list_secrets')
            for page in paginator.paginate():
                for secret in page.get('SecretList', []):
                    info = self._analyze_secret(secret)
                    if info:
                        self._secrets[info.name] = info
                        secrets.append({
                            "name": info.name,
                            "arn": info.arn,
                            "rotation_enabled": info.rotation_enabled,
                            "is_sensitive": info.is_sensitive,
                            "risk_score": info.risk_score,
                        })
            logger.info(f"Enumerated {len(secrets)} secrets")
        except Exception as e:
            logger.error(f"Failed to enumerate secrets: {e}")
        return secrets
    
    def _analyze_secret(self, secret_data: Dict) -> Optional[SecretInfo]:
        """Analyze a single secret."""
        try:
            name = secret_data.get('Name', '')
            arn = secret_data.get('ARN', '')
            
            info = SecretInfo(
                name=name,
                arn=arn,
                description=secret_data.get('Description', ''),
                kms_key_id=secret_data.get('KmsKeyId', ''),
                rotation_enabled=secret_data.get('RotationEnabled', False),
                last_rotated=str(secret_data.get('LastRotatedDate', '')),
                last_accessed=str(secret_data.get('LastAccessedDate', '')),
                created_date=str(secret_data.get('CreatedDate', '')),
            )
            
            # Tags
            for tag in secret_data.get('Tags', []):
                info.tags[tag.get('Key', '')] = tag.get('Value', '')
            
            # Get resource policy
            self._analyze_resource_policy(name, info)
            
            # Check sensitivity
            self._analyze_sensitivity(info)
            
            # Calculate risk
            self._calculate_risk(info)
            
            return info
        except Exception as e:
            logger.warning(f"Failed to analyze secret: {e}")
            return None
    
    def _analyze_resource_policy(self, secret_name: str, info: SecretInfo) -> None:
        """Analyze secret resource policy."""
        try:
            response = self.client.get_resource_policy(SecretId=secret_name)
            policy_str = response.get('ResourcePolicy')
            
            if policy_str:
                info.resource_policy = json.loads(policy_str)
                
                for stmt in info.resource_policy.get('Statement', []):
                    if stmt.get('Effect') != 'Allow':
                        continue
                    
                    principal = stmt.get('Principal', {})
                    principals = self._extract_principals(principal)
                    
                    for p in principals:
                        if self._is_cross_account(p):
                            info.allows_cross_account = True
                            info.cross_account_principals.append(p)
                            
        except self.client.exceptions.ResourceNotFoundException:
            pass
        except Exception as e:
            logger.debug(f"Could not get resource policy for {secret_name}: {e}")
    
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
    
    def _is_cross_account(self, principal: str) -> bool:
        """Check if principal is from different account."""
        if not self.account_id or principal == '*':
            return False
        parts = principal.split(':')
        if len(parts) >= 5:
            return parts[4] != self.account_id and parts[4] != ''
        return False
    
    def _analyze_sensitivity(self, info: SecretInfo) -> None:
        """Analyze secret sensitivity based on name and tags."""
        name_lower = info.name.lower()
        
        # Check name patterns
        for pattern in SENSITIVE_PATTERNS:
            if re.match(pattern, name_lower):
                info.is_sensitive = True
                keyword = pattern.replace('.*', '').replace('[-_]?', '')
                info.sensitivity_indicators.append(f"name:{keyword}")
                break
        
        # Check tags for environment
        env = info.tags.get('Environment', '').lower()
        if env in ['production', 'prod', 'prd']:
            info.is_sensitive = True
            info.sensitivity_indicators.append(f"tag:production")
        
        # Check description
        desc_lower = info.description.lower()
        sensitive_words = ['production', 'database', 'credential', 'password', 'api key']
        for word in sensitive_words:
            if word in desc_lower:
                info.is_sensitive = True
                info.sensitivity_indicators.append(f"desc:{word}")
                break
    
    def _calculate_risk(self, info: SecretInfo) -> None:
        """Calculate risk score for secret."""
        score = 0
        
        # Sensitive secret
        if info.is_sensitive:
            score += 25
        
        # Cross-account access
        if info.allows_cross_account:
            score += 30
            info.risk_factors.append("Cross-account access")
        
        # No rotation
        if not info.rotation_enabled:
            score += 15
            info.risk_factors.append("Rotation not enabled")
        
        # Default KMS key (less secure)
        if not info.kms_key_id or 'alias/aws/secretsmanager' in info.kms_key_id:
            score += 5
        
        # Has resource policy (wider access)
        if info.resource_policy:
            score += 10
        
        info.risk_score = min(100, score)
    
    def get_resource_policy(self, resource_arn: str) -> Optional[ResourcePolicy]:
        """Get secret policy as ResourcePolicy."""
        # Find by ARN or name
        info = None
        for secret in self._secrets.values():
            if secret.arn == resource_arn or secret.name == resource_arn:
                info = secret
                break
        
        if not info or not info.resource_policy:
            return None
        
        policy = ResourcePolicy(
            resource_arn=info.arn,
            resource_type=ServiceType.SECRETS_MANAGER,
            policy_document=info.resource_policy,
            resource_name=info.name,
            account_id=self.account_id,
        )
        policy.parse_policy()
        policy.allows_cross_account = info.allows_cross_account
        return policy
    
    def find_escalation_paths(
        self, principal_arn: str, permissions: List[ServicePermission]
    ) -> List[Dict[str, Any]]:
        """Find Secrets Manager escalation paths."""
        paths = []
        
        for perm in permissions:
            if perm.service != ServiceType.SECRETS_MANAGER or perm.effect != "Allow":
                continue
            
            action = perm.action.lower()
            
            # GetSecretValue - critical for data access
            if 'getsecretvalue' in action or action in ['*', 'secretsmanager:*']:
                for name, info in self._secrets.items():
                    if self._resource_matches(perm.resource, info.arn):
                        severity = "HIGH" if info.is_sensitive else "MEDIUM"
                        paths.append({
                            "type": "secret_access",
                            "action": "secretsmanager:GetSecretValue",
                            "secret": name,
                            "secret_arn": info.arn,
                            "is_sensitive": info.is_sensitive,
                            "severity": severity,
                            "description": f"Can read secret: {name}",
                        })
            
            # PutSecretValue - can modify
            if 'putsecretvalue' in action or action in ['*', 'secretsmanager:*']:
                paths.append({
                    "type": "secret_modification",
                    "action": "secretsmanager:PutSecretValue",
                    "resource": perm.resource,
                    "severity": "HIGH",
                    "description": "Can modify secret values",
                })
        
        return paths
    
    def _resource_matches(self, resource: str, arn: str) -> bool:
        """Check if resource pattern matches ARN."""
        if resource == '*':
            return True
        if resource.endswith('*'):
            return arn.startswith(resource[:-1])
        return resource == arn
    
    # Helper methods
    def get_sensitive_secrets(self) -> List[SecretInfo]:
        """Get secrets marked as sensitive."""
        return [s for s in self._secrets.values() if s.is_sensitive]
    
    def get_cross_account_secrets(self) -> List[SecretInfo]:
        """Get secrets with cross-account access."""
        return [s for s in self._secrets.values() if s.allows_cross_account]
    
    def get_unrotated_secrets(self) -> List[SecretInfo]:
        """Get secrets without rotation."""
        return [s for s in self._secrets.values() if not s.rotation_enabled]
    
    def get_high_risk_secrets(self, threshold: int = 30) -> List[SecretInfo]:
        """Get secrets above risk threshold."""
        return [s for s in self._secrets.values() if s.risk_score >= threshold]
