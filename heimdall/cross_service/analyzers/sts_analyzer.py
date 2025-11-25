# ᛒᛁᚠᚱᛟᛊᛏ • Bifröst - The Rainbow Bridge (STS Analyzer)
"""STS Analyzer for cross-account role assumption analysis."""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
import logging
import json

from ..models import ServiceType, Severity, ServicePermission, ResourcePolicy
from ..registry import ServiceRegistry, ServiceAnalyzerBase, ServiceCapabilities

logger = logging.getLogger(__name__)


@dataclass
class AssumeRoleTarget:
    """Represents a role that can be assumed."""
    role_arn: str
    role_name: str
    trust_policy: Dict = field(default_factory=dict)
    
    # Who can assume
    trusted_principals: List[str] = field(default_factory=list)
    trusted_services: List[str] = field(default_factory=list)
    trusted_accounts: List[str] = field(default_factory=list)
    
    # Conditions
    requires_external_id: bool = False
    requires_mfa: bool = False
    has_conditions: bool = False
    
    # Flags
    allows_cross_account: bool = False
    allows_any_principal: bool = False  # Principal: "*"
    is_service_role: bool = False
    
    # Risk
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@dataclass
class AssumeRoleChain:
    """Represents a chain of role assumptions."""
    source_principal: str
    roles: List[str]  # List of role ARNs in chain
    final_permissions: List[str] = field(default_factory=list)
    crosses_accounts: bool = False
    accounts_involved: Set[str] = field(default_factory=set)


@ServiceRegistry.register(ServiceType.STS)
class STSAnalyzer(ServiceAnalyzerBase):
    """STS Analyzer for role assumption and cross-account access."""
    
    SERVICE_TYPE = ServiceType.STS
    
    def __init__(self, session: Any = None, account_id: str = "", region: str = ""):
        super().__init__(session, account_id, region)
        self._roles: Dict[str, AssumeRoleTarget] = {}
        self._assume_chains: List[AssumeRoleChain] = []
    
    @classmethod
    def get_capabilities(cls) -> ServiceCapabilities:
        return ServiceCapabilities(
            service=ServiceType.STS,
            required_permissions=[
                "iam:ListRoles", "iam:GetRole",
            ],
            features={
                "trust_policy_analysis": True,
                "cross_account_detection": True,
                "assume_chain_analysis": True,
            },
        )
    
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """Enumerate all assumable roles."""
        if not self.session:
            return []
        
        roles = []
        try:
            iam = self.session.client('iam')
            paginator = iam.get_paginator('list_roles')
            
            for page in paginator.paginate():
                for role in page.get('Roles', []):
                    # Skip service-linked roles
                    if '/aws-service-role/' in role.get('Path', ''):
                        continue
                    
                    info = self._analyze_role(role)
                    if info:
                        self._roles[info.role_arn] = info
                        roles.append({
                            "role_arn": info.role_arn,
                            "role_name": info.role_name,
                            "allows_cross_account": info.allows_cross_account,
                            "is_service_role": info.is_service_role,
                            "risk_score": info.risk_score,
                        })
            
            logger.info(f"Enumerated {len(roles)} assumable roles")
        except Exception as e:
            logger.error(f"Failed to enumerate roles: {e}")
        return roles
    
    def _analyze_role(self, role_data: Dict) -> Optional[AssumeRoleTarget]:
        """Analyze a role's trust policy."""
        try:
            role_arn = role_data.get('Arn', '')
            role_name = role_data.get('RoleName', '')
            trust_policy = role_data.get('AssumeRolePolicyDocument', {})
            
            info = AssumeRoleTarget(
                role_arn=role_arn,
                role_name=role_name,
                trust_policy=trust_policy,
            )
            
            # Analyze trust policy
            for stmt in trust_policy.get('Statement', []):
                if stmt.get('Effect') != 'Allow':
                    continue
                
                action = stmt.get('Action', [])
                if isinstance(action, str):
                    action = [action]
                
                # Check if this is an assume role statement
                assume_actions = ['sts:AssumeRole', 'sts:AssumeRoleWithSAML', 
                                  'sts:AssumeRoleWithWebIdentity']
                if not any(a in action for a in assume_actions):
                    continue
                
                principal = stmt.get('Principal', {})
                conditions = stmt.get('Condition', {})
                
                # Analyze principal
                self._analyze_principal(principal, info)
                
                # Analyze conditions
                self._analyze_conditions(conditions, info)
            
            # Calculate risk
            self._calculate_risk(info)
            
            return info
        except Exception as e:
            logger.warning(f"Failed to analyze role: {e}")
            return None
    
    def _analyze_principal(self, principal: Any, info: AssumeRoleTarget) -> None:
        """Analyze trust policy principal."""
        if principal == '*':
            info.allows_any_principal = True
            info.risk_factors.append("Allows any principal (Principal: *)")
            return
        
        if isinstance(principal, str):
            self._add_principal(principal, info)
            return
        
        if isinstance(principal, dict):
            # AWS principals
            aws_principals = principal.get('AWS', [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for p in aws_principals:
                self._add_principal(p, info)
            
            # Service principals
            service_principals = principal.get('Service', [])
            if isinstance(service_principals, str):
                service_principals = [service_principals]
            for s in service_principals:
                info.trusted_services.append(s)
                info.is_service_role = True
            
            # Federated principals
            federated = principal.get('Federated', [])
            if isinstance(federated, str):
                federated = [federated]
            for f in federated:
                info.trusted_principals.append(f)
    
    def _add_principal(self, principal: str, info: AssumeRoleTarget) -> None:
        """Add a principal to the trust analysis."""
        if principal == '*':
            info.allows_any_principal = True
            info.risk_factors.append("Allows any AWS principal")
            return
        
        info.trusted_principals.append(principal)
        
        # Extract account ID
        if ':' in principal:
            parts = principal.split(':')
            if len(parts) >= 5:
                account = parts[4]
                if account and account != self.account_id:
                    info.allows_cross_account = True
                    if account not in info.trusted_accounts:
                        info.trusted_accounts.append(account)
        
        # Check for :root (account-level trust)
        if ':root' in principal:
            info.risk_factors.append(f"Account-level trust: {principal}")
    
    def _analyze_conditions(self, conditions: Dict, info: AssumeRoleTarget) -> None:
        """Analyze trust policy conditions."""
        if not conditions:
            return
        
        info.has_conditions = True
        cond_str = json.dumps(conditions).lower()
        
        # Check for external ID
        if 'externalid' in cond_str:
            info.requires_external_id = True
        
        # Check for MFA
        if 'multifactorauthpresent' in cond_str or 'aws:multifactorauthage' in cond_str:
            info.requires_mfa = True
    
    def _calculate_risk(self, info: AssumeRoleTarget) -> None:
        """Calculate risk score for assumable role."""
        score = 0
        
        # Any principal (critical)
        if info.allows_any_principal:
            score += 50
        
        # Cross-account without conditions
        if info.allows_cross_account:
            score += 25
            if not info.requires_external_id:
                score += 15
                info.risk_factors.append("Cross-account without external ID")
        
        # Account-level trust (:root)
        root_trusts = [p for p in info.trusted_principals if ':root' in p]
        if root_trusts:
            score += 20
        
        # No MFA required
        if not info.requires_mfa and not info.is_service_role:
            score += 5
        
        # Many trusted principals
        if len(info.trusted_principals) > 5:
            score += 10
            info.risk_factors.append(f"Many trusted principals: {len(info.trusted_principals)}")
        
        info.risk_score = min(100, score)
    
    def get_resource_policy(self, resource_arn: str) -> Optional[ResourcePolicy]:
        """Get role trust policy as ResourcePolicy."""
        info = self._roles.get(resource_arn)
        if not info:
            return None
        
        policy = ResourcePolicy(
            resource_arn=resource_arn,
            resource_type=ServiceType.STS,
            policy_document={"Statement": [info.trust_policy]},
            resource_name=info.role_name,
            account_id=self.account_id,
        )
        policy.allows_cross_account = info.allows_cross_account
        return policy
    
    def find_escalation_paths(
        self, principal_arn: str, permissions: List[ServicePermission]
    ) -> List[Dict[str, Any]]:
        """Find STS-based escalation paths."""
        paths = []
        
        # Check what roles the principal can assume
        for perm in permissions:
            if perm.effect != "Allow":
                continue
            
            action = perm.action.lower()
            if 'sts:assumerole' not in action and action not in ['*', 'sts:*']:
                continue
            
            # Find matching roles
            for role_arn, info in self._roles.items():
                if self._can_assume_role(principal_arn, info, perm):
                    paths.append({
                        "type": "assume_role",
                        "action": "sts:AssumeRole",
                        "target_role": role_arn,
                        "role_name": info.role_name,
                        "is_cross_account": info.allows_cross_account,
                        "severity": "HIGH" if info.allows_cross_account else "MEDIUM",
                        "risk_score": info.risk_score,
                        "description": f"Can assume role {info.role_name}",
                    })
        
        return paths
    
    def _can_assume_role(
        self, 
        principal_arn: str, 
        role: AssumeRoleTarget,
        permission: ServicePermission
    ) -> bool:
        """Check if principal can assume a role."""
        # Check resource constraint
        if permission.resource != '*':
            if not permission.resource.endswith('*'):
                if permission.resource != role.role_arn:
                    return False
            else:
                prefix = permission.resource[:-1]
                if not role.role_arn.startswith(prefix):
                    return False
        
        # Check trust policy
        if role.allows_any_principal:
            return True
        
        for trusted in role.trusted_principals:
            if trusted == '*':
                return True
            if trusted == principal_arn:
                return True
            # Account-level trust
            if ':root' in trusted:
                trusted_account = trusted.split(':')[4]
                principal_account = principal_arn.split(':')[4] if ':' in principal_arn else ''
                if trusted_account == principal_account:
                    return True
        
        return False
    
    # Helper methods
    def get_cross_account_roles(self) -> List[AssumeRoleTarget]:
        """Get roles with cross-account trust."""
        return [r for r in self._roles.values() if r.allows_cross_account]
    
    def get_overly_permissive_roles(self) -> List[AssumeRoleTarget]:
        """Get roles with overly permissive trust."""
        return [r for r in self._roles.values() if r.allows_any_principal]
    
    def get_high_risk_roles(self, threshold: int = 30) -> List[AssumeRoleTarget]:
        """Get roles above risk threshold."""
        return [r for r in self._roles.values() if r.risk_score >= threshold]
    
    def get_roles_without_external_id(self) -> List[AssumeRoleTarget]:
        """Get cross-account roles without external ID requirement."""
        return [r for r in self._roles.values() 
                if r.allows_cross_account and not r.requires_external_id]
