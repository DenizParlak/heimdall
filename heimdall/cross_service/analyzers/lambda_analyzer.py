# ᛚᛟᚲᛁ • Loki - The Shapeshifter (Lambda Analyzer)
"""Lambda Function Analyzer for cross-service privilege escalation detection."""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging
import re

from ..models import ServiceType, Severity, ServicePermission, ResourcePolicy
from ..registry import ServiceRegistry, ServiceAnalyzerBase, ServiceCapabilities

logger = logging.getLogger(__name__)

# Sensitive environment variable patterns
SENSITIVE_ENV_PATTERNS = [
    r".*password.*", r".*secret.*", r".*key.*", r".*token.*",
    r".*credential.*", r".*api_key.*", r".*apikey.*", r".*auth.*",
    r".*private.*", r".*database.*", r".*db_.*", r".*mysql.*",
    r".*postgres.*", r".*mongo.*", r".*redis.*", r".*aws_.*",
]

# Dangerous Lambda permissions
DANGEROUS_LAMBDA_ACTIONS = {
    "lambda:UpdateFunctionCode": (Severity.CRITICAL, "code_injection"),
    "lambda:UpdateFunctionConfiguration": (Severity.HIGH, "config_modification"),
    "lambda:CreateFunction": (Severity.HIGH, "function_creation"),
    "lambda:AddPermission": (Severity.HIGH, "permission_grant"),
    "lambda:PublishLayerVersion": (Severity.HIGH, "layer_injection"),
    "lambda:UpdateFunctionEventInvokeConfig": (Severity.MEDIUM, "invoke_config"),
    "lambda:PutFunctionConcurrency": (Severity.LOW, "concurrency_change"),
}


@dataclass
class LambdaFunctionInfo:
    """Lambda function information."""
    name: str
    arn: str
    runtime: str = ""
    role_arn: str = ""  # Execution role
    handler: str = ""
    code_size: int = 0
    memory_size: int = 128
    timeout: int = 3
    last_modified: str = ""
    
    # Environment
    env_vars: Dict[str, str] = field(default_factory=dict)
    sensitive_env_vars: List[str] = field(default_factory=list)
    
    # Layers
    layers: List[str] = field(default_factory=list)
    
    # VPC config
    vpc_id: str = ""
    subnet_ids: List[str] = field(default_factory=list)
    security_group_ids: List[str] = field(default_factory=list)
    
    # Event sources
    event_sources: List[Dict] = field(default_factory=list)
    
    # Resource policy
    resource_policy: Optional[Dict] = None
    allows_public_invoke: bool = False
    allows_cross_account: bool = False
    cross_account_principals: List[str] = field(default_factory=list)
    
    # Risk assessment
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
    
    # Role analysis
    role_permissions: List[str] = field(default_factory=list)
    role_is_admin: bool = False


@ServiceRegistry.register(ServiceType.LAMBDA)
class LambdaAnalyzer(ServiceAnalyzerBase):
    """Lambda Function Analyzer for cross-service privilege escalation."""
    
    SERVICE_TYPE = ServiceType.LAMBDA
    
    def __init__(self, session: Any = None, account_id: str = "", region: str = ""):
        super().__init__(session, account_id, region)
        self._functions: Dict[str, LambdaFunctionInfo] = {}
    
    @classmethod
    def get_capabilities(cls) -> ServiceCapabilities:
        return ServiceCapabilities(
            service=ServiceType.LAMBDA,
            required_permissions=[
                "lambda:ListFunctions", "lambda:GetFunction",
                "lambda:GetFunctionConfiguration", "lambda:GetPolicy",
                "lambda:ListEventSourceMappings", "lambda:ListLayers",
            ],
            features={
                "execution_role_analysis": True,
                "env_var_detection": True,
                "layer_analysis": True,
                "event_source_analysis": True,
                "resource_policy_analysis": True,
            },
        )
    
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """Enumerate all Lambda functions."""
        if not self.client:
            return []
        
        functions = []
        try:
            paginator = self.client.get_paginator('list_functions')
            for page in paginator.paginate():
                for func in page.get('Functions', []):
                    info = self._analyze_function(func)
                    if info:
                        self._functions[info.name] = info
                        functions.append({
                            "name": info.name,
                            "arn": info.arn,
                            "runtime": info.runtime,
                            "role_arn": info.role_arn,
                            "risk_score": info.risk_score,
                            "has_sensitive_env": len(info.sensitive_env_vars) > 0,
                        })
            logger.info(f"Enumerated {len(functions)} Lambda functions")
        except Exception as e:
            logger.error(f"Failed to enumerate Lambda functions: {e}")
        return functions
    
    def _analyze_function(self, func_data: Dict) -> Optional[LambdaFunctionInfo]:
        """Analyze a single Lambda function."""
        try:
            name = func_data.get('FunctionName', '')
            arn = func_data.get('FunctionArn', '')
            
            info = LambdaFunctionInfo(
                name=name,
                arn=arn,
                runtime=func_data.get('Runtime', ''),
                role_arn=func_data.get('Role', ''),
                handler=func_data.get('Handler', ''),
                code_size=func_data.get('CodeSize', 0),
                memory_size=func_data.get('MemorySize', 128),
                timeout=func_data.get('Timeout', 3),
                last_modified=func_data.get('LastModified', ''),
            )
            
            # Environment variables
            env = func_data.get('Environment', {}).get('Variables', {})
            info.env_vars = env
            info.sensitive_env_vars = self._find_sensitive_env_vars(env)
            
            # Layers
            info.layers = [l.get('Arn', '') for l in func_data.get('Layers', [])]
            
            # VPC config
            vpc_config = func_data.get('VpcConfig', {})
            info.vpc_id = vpc_config.get('VpcId', '')
            info.subnet_ids = vpc_config.get('SubnetIds', [])
            info.security_group_ids = vpc_config.get('SecurityGroupIds', [])
            
            # Get resource policy
            self._analyze_resource_policy(name, info)
            
            # Get event source mappings
            self._analyze_event_sources(name, info)
            
            # Analyze execution role
            self._analyze_execution_role(info)
            
            # Calculate risk
            self._calculate_risk(info)
            
            return info
        except Exception as e:
            logger.warning(f"Failed to analyze function {func_data.get('FunctionName')}: {e}")
            return None
    
    def _find_sensitive_env_vars(self, env_vars: Dict[str, str]) -> List[str]:
        """Find environment variables that may contain secrets."""
        sensitive = []
        for key in env_vars.keys():
            key_lower = key.lower()
            for pattern in SENSITIVE_ENV_PATTERNS:
                if re.match(pattern, key_lower):
                    sensitive.append(key)
                    break
        return sensitive
    
    def _analyze_resource_policy(self, func_name: str, info: LambdaFunctionInfo) -> None:
        """Analyze function resource policy."""
        try:
            response = self.client.get_policy(FunctionName=func_name)
            import json
            policy = json.loads(response.get('Policy', '{}'))
            info.resource_policy = policy
            
            for stmt in policy.get('Statement', []):
                if stmt.get('Effect') != 'Allow':
                    continue
                
                principal = stmt.get('Principal', {})
                
                # Check for public invoke
                if principal == '*' or principal.get('AWS') == '*':
                    condition = stmt.get('Condition', {})
                    if not self._has_restrictive_conditions(condition):
                        info.allows_public_invoke = True
                        info.risk_factors.append("Publicly invokable")
                
                # Check for cross-account
                if isinstance(principal, dict):
                    aws_principal = principal.get('AWS', [])
                    if isinstance(aws_principal, str):
                        aws_principal = [aws_principal]
                    for p in aws_principal:
                        if self._is_cross_account(p):
                            info.allows_cross_account = True
                            info.cross_account_principals.append(p)
                            
        except self.client.exceptions.ResourceNotFoundException:
            pass  # No resource policy
        except Exception as e:
            logger.debug(f"Could not get policy for {func_name}: {e}")
    
    def _has_restrictive_conditions(self, conditions: Dict) -> bool:
        """Check for restrictive conditions."""
        if not conditions:
            return False
        restrictive = ["aws:SourceAccount", "aws:SourceArn", "aws:PrincipalOrgID"]
        cond_str = str(conditions).lower()
        return any(k.lower() in cond_str for k in restrictive)
    
    def _is_cross_account(self, principal: str) -> bool:
        """Check if principal is from different account."""
        if not self.account_id or principal == '*':
            return False
        parts = principal.split(':')
        if len(parts) >= 5:
            return parts[4] != self.account_id
        return False
    
    def _analyze_event_sources(self, func_name: str, info: LambdaFunctionInfo) -> None:
        """Analyze event source mappings."""
        try:
            response = self.client.list_event_source_mappings(FunctionName=func_name)
            for mapping in response.get('EventSourceMappings', []):
                info.event_sources.append({
                    "uuid": mapping.get('UUID'),
                    "event_source_arn": mapping.get('EventSourceArn', ''),
                    "state": mapping.get('State'),
                    "batch_size": mapping.get('BatchSize'),
                })
        except Exception as e:
            logger.debug(f"Could not get event sources for {func_name}: {e}")
    
    def _analyze_execution_role(self, info: LambdaFunctionInfo) -> None:
        """Analyze the Lambda execution role permissions."""
        if not info.role_arn or not self.session:
            return
        
        try:
            iam = self.session.client('iam')
            role_name = info.role_arn.split('/')[-1]
            
            # Get attached policies
            attached = iam.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get('AttachedPolicies', []):
                policy_arn = policy.get('PolicyArn', '')
                info.role_permissions.append(policy_arn)
                
                # Check for admin policies
                if 'AdministratorAccess' in policy_arn or 'PowerUserAccess' in policy_arn:
                    info.role_is_admin = True
                    info.risk_factors.append(f"Admin policy: {policy_arn.split('/')[-1]}")
            
            # Get inline policies
            inline = iam.list_role_policies(RoleName=role_name)
            for policy_name in inline.get('PolicyNames', []):
                info.role_permissions.append(f"inline:{policy_name}")
                
                # Check inline policy for wildcards
                policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                doc = policy_doc.get('PolicyDocument', {})
                if self._has_admin_permissions(doc):
                    info.role_is_admin = True
                    info.risk_factors.append(f"Admin inline policy: {policy_name}")
                    
        except Exception as e:
            logger.debug(f"Could not analyze role {info.role_arn}: {e}")
    
    def _has_admin_permissions(self, policy_doc: Dict) -> bool:
        """Check if policy has admin permissions."""
        for stmt in policy_doc.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue
            actions = stmt.get('Action', [])
            resources = stmt.get('Resource', [])
            
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # Check for *:* or iam:*
            if '*' in actions or '*:*' in actions:
                if '*' in resources:
                    return True
            if any(a.startswith('iam:') and '*' in a for a in actions):
                return True
        return False
    
    def _calculate_risk(self, info: LambdaFunctionInfo) -> None:
        """Calculate risk score for function."""
        score = 0
        
        # Admin execution role (critical)
        if info.role_is_admin:
            score += 40
        
        # Public invoke
        if info.allows_public_invoke:
            score += 30
            
        # Cross-account access
        if info.allows_cross_account:
            score += 15
        
        # Sensitive environment variables
        if info.sensitive_env_vars:
            score += 15
            info.risk_factors.append(f"Sensitive env vars: {', '.join(info.sensitive_env_vars[:3])}")
        
        # No VPC (internet accessible)
        if not info.vpc_id:
            score += 5
        
        # External layers
        if info.layers:
            for layer in info.layers:
                if self._is_cross_account(layer):
                    score += 10
                    info.risk_factors.append("External layer")
                    break
        
        # Deprecated runtime
        deprecated = ['python2.7', 'nodejs8.10', 'nodejs10.x', 'dotnetcore2.1', 'ruby2.5']
        if info.runtime in deprecated:
            score += 10
            info.risk_factors.append(f"Deprecated runtime: {info.runtime}")
        
        info.risk_score = min(100, score)
    
    def get_resource_policy(self, resource_arn: str) -> Optional[ResourcePolicy]:
        """Get function policy as ResourcePolicy."""
        func_name = resource_arn.split(':')[-1]
        info = self._functions.get(func_name)
        if not info or not info.resource_policy:
            return None
        
        policy = ResourcePolicy(
            resource_arn=resource_arn,
            resource_type=ServiceType.LAMBDA,
            policy_document=info.resource_policy,
            resource_name=func_name,
            account_id=self.account_id,
            region=self.region,
        )
        policy.parse_policy()
        policy.is_public = info.allows_public_invoke
        policy.allows_cross_account = info.allows_cross_account
        return policy
    
    def find_escalation_paths(
        self, principal_arn: str, permissions: List[ServicePermission]
    ) -> List[Dict[str, Any]]:
        """Find Lambda-based privilege escalation paths."""
        paths = []
        
        for perm in permissions:
            if perm.service != ServiceType.LAMBDA or perm.effect != "Allow":
                continue
            
            for action, (severity, esc_type) in DANGEROUS_LAMBDA_ACTIONS.items():
                if self._action_matches(perm.action, action):
                    # Find affected functions
                    for name, info in self._functions.items():
                        if self._resource_matches(perm.resource, info.arn):
                            paths.append({
                                "type": esc_type,
                                "action": action,
                                "function": name,
                                "function_arn": info.arn,
                                "execution_role": info.role_arn,
                                "role_is_admin": info.role_is_admin,
                                "severity": severity.value,
                                "description": f"Can {action} on {name}",
                            })
        
        return paths
    
    def _action_matches(self, action: str, pattern: str) -> bool:
        if action == "*" or action == "lambda:*":
            return True
        return action.lower() == pattern.lower()
    
    def _resource_matches(self, resource: str, arn: str) -> bool:
        if resource == "*":
            return True
        if resource.endswith("*"):
            return arn.startswith(resource[:-1])
        return resource == arn
    
    # Helper methods for querying
    def get_admin_functions(self) -> List[LambdaFunctionInfo]:
        """Get functions with admin execution roles."""
        return [f for f in self._functions.values() if f.role_is_admin]
    
    def get_public_functions(self) -> List[LambdaFunctionInfo]:
        """Get publicly invokable functions."""
        return [f for f in self._functions.values() if f.allows_public_invoke]
    
    def get_functions_with_secrets(self) -> List[LambdaFunctionInfo]:
        """Get functions with sensitive env vars."""
        return [f for f in self._functions.values() if f.sensitive_env_vars]
    
    def get_high_risk_functions(self, threshold: int = 50) -> List[LambdaFunctionInfo]:
        """Get functions above risk threshold."""
        return [f for f in self._functions.values() if f.risk_score >= threshold]
    
    def get_cross_account_functions(self) -> List[LambdaFunctionInfo]:
        """Get functions with cross-account access."""
        return [f for f in self._functions.values() if f.allows_cross_account]
