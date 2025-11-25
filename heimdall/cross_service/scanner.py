# ᛟᛞᛁᚾ • Odin's Eye - The All-Seeing Cross-Service Scanner
"""
Cross-Service Scanner - Orchestrates analysis across AWS services.

This is the main entry point for cross-service privilege escalation detection.
It coordinates individual service analyzers and builds cross-service attack chains.
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging
import json

from .models import (
    ServiceType,
    VectorType,
    Severity,
    ServicePermission,
    ResourcePolicy,
    AttackVector,
    CrossServiceChain,
    CrossServiceFinding,
)
from .registry import (
    ServiceRegistry,
    ServiceAnalyzerBase,
    CROSS_SERVICE_ESCALATION_PATTERNS,
    get_escalation_patterns,
    is_high_value_target,
    get_multi_hop_patterns,
    find_matching_multi_hop,
)

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Configuration for cross-service scanning."""
    # Services to scan
    services: List[ServiceType] = field(default_factory=lambda: [
        ServiceType.S3,
        ServiceType.LAMBDA,
        ServiceType.KMS,
        ServiceType.SECRETS_MANAGER,
    ])
    
    # Scan depth
    max_chain_depth: int = 5
    max_findings_per_principal: int = 20
    
    # Regions to scan
    regions: List[str] = field(default_factory=lambda: ["us-east-1"])
    
    # Analysis options
    include_public_resources: bool = True
    include_cross_account: bool = True
    analyze_resource_policies: bool = True
    
    # Output options
    include_evidence: bool = True
    include_remediation: bool = True


@dataclass
class ScanResult:
    """Result of a cross-service scan."""
    # Findings
    findings: List[CrossServiceFinding] = field(default_factory=list)
    chains: List[CrossServiceChain] = field(default_factory=list)
    
    # Statistics
    resources_scanned: Dict[str, int] = field(default_factory=dict)
    policies_analyzed: int = 0
    escalation_paths_found: int = 0
    
    # Metadata
    scan_started: datetime = field(default_factory=datetime.utcnow)
    scan_completed: Optional[datetime] = None
    account_id: str = ""
    regions_scanned: List[str] = field(default_factory=list)
    services_scanned: List[str] = field(default_factory=list)
    
    # Errors
    errors: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_finding(self, finding: CrossServiceFinding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)
        self.escalation_paths_found += 1
    
    def add_chain(self, chain: CrossServiceChain) -> None:
        """Add a chain to the results (with deduplication)."""
        # Create a unique key for deduplication
        chain_key = f"{chain.initial_principal}:{chain.title}:{chain.final_target}"
        
        # Check for duplicates
        for existing in self.chains:
            existing_key = f"{existing.initial_principal}:{existing.title}:{existing.final_target}"
            if chain_key == existing_key:
                return  # Skip duplicate
        
        self.chains.append(chain)
    
    def add_error(self, service: str, error: str) -> None:
        """Record an error."""
        self.errors.append({
            "service": service,
            "error": str(error),
            "timestamp": datetime.utcnow().isoformat(),
        })
    
    @property
    def severity_summary(self) -> Dict[str, int]:
        """Get count of findings by severity."""
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings:
            summary[finding.severity.value] = summary.get(finding.severity.value, 0) + 1
        return summary
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "summary": {
                "total_findings": len(self.findings),
                "total_chains": len(self.chains),
                "by_severity": self.severity_summary,
                "resources_scanned": self.resources_scanned,
                "policies_analyzed": self.policies_analyzed,
                "escalation_paths_found": self.escalation_paths_found,
            },
            "metadata": {
                "scan_started": self.scan_started.isoformat(),
                "scan_completed": self.scan_completed.isoformat() if self.scan_completed else None,
                "account_id": self.account_id,
                "regions_scanned": self.regions_scanned,
                "services_scanned": self.services_scanned,
            },
            "findings": [f.to_dict() for f in self.findings],
            "chains": [c.to_dict() for c in self.chains],
            "errors": self.errors,
        }


class CrossServiceScanner:
    """
    Main scanner for cross-service privilege escalation detection.
    
    This scanner:
    1. Enumerates resources across multiple AWS services
    2. Retrieves and analyzes resource-based policies
    3. Combines with IAM identity-based policies
    4. Builds cross-service attack chains
    5. Calculates risk scores and generates findings
    """
    
    def __init__(
        self,
        session: Any = None,
        account_id: str = "",
        region: str = "",
        iam_data: Optional[Dict] = None,
    ):
        """
        Initialize the cross-service scanner.
        
        Args:
            session: boto3 Session object
            account_id: AWS account ID
            region: Default AWS region
            iam_data: Pre-loaded IAM data from heimdall scan
        """
        self.session = session
        self.account_id = account_id
        self.region = region
        self.iam_data = iam_data or {}
        
        # Analyzers
        self._analyzers: Dict[ServiceType, ServiceAnalyzerBase] = {}
        
        # Cached data
        self._principal_permissions: Dict[str, List[ServicePermission]] = {}
        self._resource_policies: Dict[str, ResourcePolicy] = {}
        
        # Results
        self._result: Optional[ScanResult] = None
        
        # Chain building state
        self._chain_counter = 0
        self._finding_counter = 0
    
    def _init_analyzers(self, services: List[ServiceType]) -> None:
        """Initialize service analyzers."""
        for service in services:
            if ServiceRegistry.is_registered(service):
                analyzer = ServiceRegistry.get_analyzer(
                    service,
                    session=self.session,
                    account_id=self.account_id,
                    region=self.region
                )
                if analyzer:
                    self._analyzers[service] = analyzer
                    logger.debug(f"Initialized analyzer for {service.value}")
    
    def scan(
        self,
        config: Optional[ScanConfig] = None,
        principals: Optional[List[str]] = None,
    ) -> ScanResult:
        """
        Perform a cross-service scan.
        
        Args:
            config: Scan configuration
            principals: Specific principals to analyze (None = all)
            
        Returns:
            ScanResult with findings and chains
        """
        config = config or ScanConfig()
        
        # Initialize result - use actual region, not config default
        actual_region = self.region or (self.session.region_name if self.session else "us-east-1")
        self._result = ScanResult(
            account_id=self.account_id,
            regions_scanned=[actual_region],
            services_scanned=[s.value for s in config.services],
        )
        
        logger.info(f"Starting cross-service scan for {len(config.services)} services")
        
        try:
            # Initialize analyzers
            self._init_analyzers(config.services)
            
            # Load IAM principal permissions
            self._load_principal_permissions(principals)
            
            # Enumerate and analyze each service
            for service in config.services:
                self._scan_service(service, config)
            
            # Build cross-service attack chains
            self._build_cross_service_chains(config)
            
            # Build multi-hop chains (S3→Lambda→Secrets, etc.)
            self._build_multi_hop_chains(config)
            
            # Generate findings from chains
            self._generate_findings(config)
            
            self._result.scan_completed = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Cross-service scan failed: {e}")
            self._result.add_error("scanner", str(e))
        
        return self._result
    
    def _load_principal_permissions(
        self, 
        principals: Optional[List[str]] = None
    ) -> None:
        """Load permissions for principals from IAM data or boto3."""
        # Try to load from heimdall graph format first
        if self.iam_data:
            graph = self.iam_data.get("graph", {})
            nodes = graph.get("nodes", [])
            
            if nodes:
                # Extract users and roles from graph nodes
                users = [n for n in nodes if n.get("type") == "user"]
                roles = [n for n in nodes if n.get("type") == "role"]
                logger.info(f"Found {len(users)} users, {len(roles)} roles in graph")
                
                # For graph format, fetch full IAM data via boto3
                if self.session:
                    self._load_permissions_from_boto3(principals)
                return
        
        # Fallback: load directly from boto3
        if self.session:
            self._load_permissions_from_boto3(principals)
            return
        
        logger.warning("No IAM data or session available")
    
    def _load_permissions_from_boto3(
        self, 
        principals: Optional[List[str]] = None
    ) -> None:
        """Load IAM permissions directly from AWS."""
        try:
            iam = self.session.client('iam')
            
            # Get users
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    arn = user.get('Arn', '')
                    if principals and arn not in principals:
                        continue
                    permissions = self._get_user_permissions_boto3(iam, user['UserName'])
                    if permissions:
                        self._principal_permissions[arn] = permissions
            
            # Get roles
            paginator = iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page.get('Roles', []):
                    arn = role.get('Arn', '')
                    if principals and arn not in principals:
                        continue
                    # Skip service-linked roles
                    if '/aws-service-role/' in arn:
                        continue
                    permissions = self._get_role_permissions_boto3(iam, role['RoleName'])
                    if permissions:
                        self._principal_permissions[arn] = permissions
            
            logger.info(f"Loaded permissions for {len(self._principal_permissions)} principals")
            
        except Exception as e:
            logger.error(f"Failed to load IAM permissions: {e}")
    
    def _get_user_permissions_boto3(self, iam, user_name: str) -> List[ServicePermission]:
        """Get permissions for a user via boto3."""
        permissions = []
        try:
            # Inline policies
            for policy in iam.list_user_policies(UserName=user_name).get('PolicyNames', []):
                doc = iam.get_user_policy(UserName=user_name, PolicyName=policy).get('PolicyDocument', {})
                permissions.extend(self._parse_policy_document(doc, f"inline:{policy}"))
            
            # Attached policies
            for policy in iam.list_attached_user_policies(UserName=user_name).get('AttachedPolicies', []):
                policy_arn = policy.get('PolicyArn', '')
                doc = self._get_policy_document_boto3(iam, policy_arn)
                if doc:
                    permissions.extend(self._parse_policy_document(doc, policy_arn))
        except Exception as e:
            logger.debug(f"Error getting permissions for user {user_name}: {e}")
        return permissions
    
    def _get_role_permissions_boto3(self, iam, role_name: str) -> List[ServicePermission]:
        """Get permissions for a role via boto3."""
        permissions = []
        try:
            # Inline policies
            for policy in iam.list_role_policies(RoleName=role_name).get('PolicyNames', []):
                doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy).get('PolicyDocument', {})
                permissions.extend(self._parse_policy_document(doc, f"inline:{policy}"))
            
            # Attached policies
            for policy in iam.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', []):
                policy_arn = policy.get('PolicyArn', '')
                doc = self._get_policy_document_boto3(iam, policy_arn)
                if doc:
                    permissions.extend(self._parse_policy_document(doc, policy_arn))
        except Exception as e:
            logger.debug(f"Error getting permissions for role {role_name}: {e}")
        return permissions
    
    def _get_policy_document_boto3(self, iam, policy_arn: str) -> Optional[Dict]:
        """Get policy document via boto3."""
        try:
            policy = iam.get_policy(PolicyArn=policy_arn)
            version_id = policy['Policy']['DefaultVersionId']
            version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            return version['PolicyVersion']['Document']
        except Exception:
            return None
    
    def _load_principal_permissions_legacy(
        self, 
        principals: Optional[List[str]] = None
    ) -> None:
        """Load permissions from legacy IAM data format."""
        # Extract principals from IAM data
        users = self.iam_data.get("users", [])
        roles = self.iam_data.get("roles", [])
        
        for user in users:
            arn = user.get("Arn", "")
            if principals and arn not in principals:
                continue
            permissions = self._extract_user_permissions(user)
            self._principal_permissions[arn] = permissions
        
        for role in roles:
            arn = role.get("Arn", "")
            if principals and arn not in principals:
                continue
            permissions = self._extract_role_permissions(role)
            self._principal_permissions[arn] = permissions
        
        logger.info(f"Loaded permissions for {len(self._principal_permissions)} principals")
    
    def _extract_user_permissions(self, user: Dict) -> List[ServicePermission]:
        """Extract permissions from a user."""
        permissions = []
        
        # Inline policies
        for policy in user.get("UserPolicyList", []):
            doc = policy.get("PolicyDocument", {})
            permissions.extend(self._parse_policy_document(doc, policy.get("PolicyName", "")))
        
        # Attached policies
        for policy in user.get("AttachedManagedPolicies", []):
            policy_arn = policy.get("PolicyArn", "")
            # Get policy document from IAM data
            policy_doc = self._get_policy_document(policy_arn)
            if policy_doc:
                permissions.extend(self._parse_policy_document(policy_doc, policy_arn))
        
        return permissions
    
    def _extract_role_permissions(self, role: Dict) -> List[ServicePermission]:
        """Extract permissions from a role."""
        permissions = []
        
        # Inline policies
        for policy in role.get("RolePolicyList", []):
            doc = policy.get("PolicyDocument", {})
            permissions.extend(self._parse_policy_document(doc, policy.get("PolicyName", "")))
        
        # Attached policies
        for policy in role.get("AttachedManagedPolicies", []):
            policy_arn = policy.get("PolicyArn", "")
            policy_doc = self._get_policy_document(policy_arn)
            if policy_doc:
                permissions.extend(self._parse_policy_document(policy_doc, policy_arn))
        
        return permissions
    
    def _get_policy_document(self, policy_arn: str) -> Optional[Dict]:
        """Get policy document from IAM data."""
        policies = self.iam_data.get("policies", [])
        for policy in policies:
            if policy.get("Arn") == policy_arn:
                versions = policy.get("PolicyVersionList", [])
                for version in versions:
                    if version.get("IsDefaultVersion", False):
                        return version.get("Document", {})
        return None
    
    def _parse_policy_document(
        self, 
        doc: Dict, 
        source_policy: str
    ) -> List[ServicePermission]:
        """Parse a policy document into permissions."""
        permissions = []
        
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for stmt in statements:
            effect = stmt.get("Effect", "Allow")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", ["*"])
            conditions = stmt.get("Condition", {})
            
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            for action in actions:
                for resource in resources:
                    service = self._extract_service_from_action(action)
                    permissions.append(ServicePermission(
                        service=service,
                        action=action,
                        resource=resource,
                        effect=effect,
                        conditions=conditions,
                        source_policy=source_policy,
                        source_type="identity",
                    ))
        
        return permissions
    
    def _extract_service_from_action(self, action: str) -> ServiceType:
        """Extract service type from an action string."""
        if ":" in action:
            service_prefix = action.split(":")[0].lower()
        else:
            service_prefix = action.lower()
        
        service_map = {
            "iam": ServiceType.IAM,
            "s3": ServiceType.S3,
            "lambda": ServiceType.LAMBDA,
            "kms": ServiceType.KMS,
            "sts": ServiceType.STS,
            "sns": ServiceType.SNS,
            "sqs": ServiceType.SQS,
            "secretsmanager": ServiceType.SECRETS_MANAGER,
            "ecr": ServiceType.ECR,
            "ec2": ServiceType.EC2,
            "ecs": ServiceType.ECS,
            "dynamodb": ServiceType.DYNAMODB,
            "rds": ServiceType.RDS,
            "cloudformation": ServiceType.CLOUDFORMATION,
            "codebuild": ServiceType.CODEBUILD,
            "glue": ServiceType.GLUE,
            "sagemaker": ServiceType.SAGEMAKER,
        }
        
        return service_map.get(service_prefix, ServiceType.IAM)
    
    def _scan_service(self, service: ServiceType, config: ScanConfig) -> None:
        """Scan a specific service."""
        analyzer = self._analyzers.get(service)
        if not analyzer:
            logger.warning(f"No analyzer available for {service.value}")
            return
        
        try:
            # Enumerate resources
            resources = analyzer.enumerate_resources()
            self._result.resources_scanned[service.value] = len(resources)
            
            # Get resource policies
            if config.analyze_resource_policies:
                for resource in resources:
                    arn = resource.get("arn", resource.get("Arn", ""))
                    if arn:
                        policy = analyzer.get_resource_policy(arn)
                        if policy:
                            policy.parse_policy()
                            self._resource_policies[arn] = policy
                            self._result.policies_analyzed += 1
            
            logger.info(f"Scanned {service.value}: {len(resources)} resources")
            
        except Exception as e:
            logger.error(f"Error scanning {service.value}: {e}")
            self._result.add_error(service.value, str(e))
    
    def _build_cross_service_chains(self, config: ScanConfig) -> None:
        """Build cross-service attack chains."""
        for principal_arn, permissions in self._principal_permissions.items():
            chains = self._find_chains_for_principal(
                principal_arn,
                permissions,
                config.max_chain_depth
            )
            for chain in chains:
                self._result.add_chain(chain)
    
    def _find_chains_for_principal(
        self,
        principal_arn: str,
        permissions: List[ServicePermission],
        max_depth: int
    ) -> List[CrossServiceChain]:
        """Find all attack chains for a principal."""
        chains = []
        
        # Group permissions by service
        by_service: Dict[ServiceType, List[ServicePermission]] = {}
        for perm in permissions:
            if perm.effect != "Allow":
                continue
            if perm.service not in by_service:
                by_service[perm.service] = []
            by_service[perm.service].append(perm)
        
        # Check for escalation patterns
        for source_service, perms in by_service.items():
            patterns = get_escalation_patterns(source_service)
            
            for perm in perms:
                for pattern, target_service, escalation_type, severity in patterns:
                    if self._matches_action(perm.action, pattern):
                        # Found a potential escalation vector
                        chain = self._build_chain(
                            principal_arn,
                            perm,
                            source_service,
                            target_service,
                            escalation_type,
                            severity,
                        )
                        if chain:
                            chains.append(chain)
        
        # Check resource policies for additional access
        for resource_arn, policy in self._resource_policies.items():
            if self._principal_allowed_by_resource_policy(principal_arn, policy):
                chain = self._build_resource_policy_chain(
                    principal_arn,
                    resource_arn,
                    policy,
                )
                if chain:
                    chains.append(chain)
        
        return chains
    
    def _matches_action(self, action: str, pattern: str) -> bool:
        """Check if an action matches a pattern."""
        action_lower = action.lower()
        pattern_lower = pattern.lower()
        
        if pattern_lower == "*" or pattern_lower == "*:*":
            return True
        
        if "*" not in pattern_lower:
            return action_lower == pattern_lower
        
        # Handle wildcards
        if pattern_lower.endswith("*"):
            prefix = pattern_lower[:-1]
            return action_lower.startswith(prefix)
        
        return action_lower == pattern_lower
    
    def _build_chain(
        self,
        principal_arn: str,
        permission: ServicePermission,
        source_service: ServiceType,
        target_service: ServiceType,
        escalation_type: str,
        severity: str,
    ) -> Optional[CrossServiceChain]:
        """Build a cross-service chain from an escalation pattern."""
        self._chain_counter += 1
        
        # Create attack vector
        vector = AttackVector(
            vector_id=f"vec_{self._chain_counter:04d}",
            vector_type=self._get_vector_type(escalation_type),
            source_service=source_service,
            target_service=target_service,
            source_principal=principal_arn,
            target_resource=permission.resource,
            required_permissions=[permission],
            severity=Severity[severity],
            risk_score=self._calculate_vector_risk(permission, escalation_type),
            title=self._get_escalation_title(escalation_type),
            description=self._get_escalation_description(escalation_type, permission),
            technique=self._get_mitre_technique(escalation_type),
            evidence={
                "action": permission.action,
                "resource": permission.resource,
                "source_policy": permission.source_policy,
            },
        )
        
        # Create chain
        chain = CrossServiceChain(
            chain_id=f"chain_{self._chain_counter:04d}",
            title=f"{escalation_type.replace('_', ' ').title()} via {source_service.value}",
            description=f"Cross-service escalation from {source_service.value} to {target_service.value}",
            initial_principal=principal_arn,
            final_target=permission.resource,
        )
        chain.add_vector(vector)
        
        # Add remediation
        chain.remediation_steps = self._get_remediation_steps(escalation_type)
        chain.quick_win = chain.remediation_steps[0] if chain.remediation_steps else ""
        
        return chain
    
    def _build_resource_policy_chain(
        self,
        principal_arn: str,
        resource_arn: str,
        policy: ResourcePolicy,
    ) -> Optional[CrossServiceChain]:
        """Build a chain from a resource policy grant."""
        self._chain_counter += 1
        
        severity = Severity.HIGH if policy.is_public else Severity.MEDIUM
        if policy.allows_cross_account:
            severity = Severity.HIGH
        
        vector = AttackVector(
            vector_id=f"vec_{self._chain_counter:04d}",
            vector_type=VectorType.RESOURCE_POLICY,
            source_service=ServiceType.IAM,
            target_service=policy.resource_type,
            source_principal=principal_arn,
            target_resource=resource_arn,
            severity=severity,
            risk_score=70 if policy.is_public else 50,
            title=f"Resource Policy Access to {policy.resource_type.value}",
            description=f"Principal has access via resource-based policy on {resource_arn}",
            technique="T1078",  # Valid Accounts
            evidence={
                "resource_arn": resource_arn,
                "is_public": policy.is_public,
                "allows_cross_account": policy.allows_cross_account,
                "allowed_actions": policy.allowed_actions[:5],
            },
        )
        
        chain = CrossServiceChain(
            chain_id=f"chain_{self._chain_counter:04d}",
            title=f"Resource Policy Access: {policy.resource_type.value}",
            description=f"Access to {resource_arn} via resource-based policy",
            initial_principal=principal_arn,
            final_target=resource_arn,
        )
        chain.add_vector(vector)
        
        return chain
    
    def _principal_allowed_by_resource_policy(
        self,
        principal_arn: str,
        policy: ResourcePolicy
    ) -> bool:
        """Check if a principal is allowed by a resource policy."""
        if not policy.allowed_principals:
            return False
        
        for allowed in policy.allowed_principals:
            if allowed == "*":
                return True
            if allowed == principal_arn:
                return True
            # Check for account-level wildcards
            if ":root" in allowed:
                account = allowed.split(":")[4] if ":" in allowed else ""
                if account and account in principal_arn:
                    return True
        
        return False
    
    def _get_vector_type(self, escalation_type: str) -> VectorType:
        """Map escalation type to vector type."""
        mapping = {
            "passrole_lambda": VectorType.PASSROLE,
            "passrole_ec2": VectorType.PASSROLE,
            "passrole_ecs": VectorType.PASSROLE,
            "passrole_glue": VectorType.PASSROLE,
            "passrole_sagemaker": VectorType.PASSROLE,
            "passrole_codebuild": VectorType.PASSROLE,
            "passrole_cfn": VectorType.PASSROLE,
            "create_access_key": VectorType.BACKDOOR_USER,
            "create_login_profile": VectorType.BACKDOOR_USER,
            "update_trust_policy": VectorType.BACKDOOR_ROLE,
            "attach_policy": VectorType.DIRECT_POLICY,
            "put_policy": VectorType.DIRECT_POLICY,
            "lambda_code_injection": VectorType.LAMBDA_UPDATE,
            "lambda_env_modify": VectorType.LAMBDA_UPDATE,
            "lambda_invoke": VectorType.LAMBDA_INVOKE,
            "assume_role": VectorType.ASSUME_ROLE,
            "s3_policy_modify": VectorType.RESOURCE_POLICY,
            "s3_data_access": VectorType.DATA_EXFILTRATION,
            "kms_grant": VectorType.KEY_ACCESS,
            "get_secret": VectorType.SECRET_ACCESS,
        }
        return mapping.get(escalation_type, VectorType.DIRECT_POLICY)
    
    def _calculate_vector_risk(
        self, 
        permission: ServicePermission,
        escalation_type: str
    ) -> int:
        """Calculate risk score for a vector."""
        base_scores = {
            "passrole_lambda": 70,
            "passrole_ec2": 75,
            "passrole_cfn": 85,
            "create_access_key": 90,
            "update_trust_policy": 95,
            "lambda_code_injection": 85,
            "assume_role": 65,
            "s3_policy_modify": 80,
            "get_secret": 70,
        }
        
        score = base_scores.get(escalation_type, 50)
        
        # Wildcards increase risk
        if permission.is_wildcard_resource:
            score += 10
        if permission.is_wildcard_action:
            score += 15
        
        # High-value targets increase risk
        if is_high_value_target(permission.resource):
            score += 10
        
        return min(100, score)
    
    def _get_escalation_title(self, escalation_type: str) -> str:
        """Get human-readable title for escalation type."""
        titles = {
            "passrole_lambda": "PassRole to Lambda Execution Role",
            "passrole_ec2": "PassRole to EC2 Instance Profile",
            "passrole_cfn": "PassRole to CloudFormation Stack Role",
            "create_access_key": "Create IAM Access Key",
            "update_trust_policy": "Modify Role Trust Policy",
            "lambda_code_injection": "Lambda Function Code Injection",
            "assume_role": "Assume IAM Role",
            "s3_policy_modify": "Modify S3 Bucket Policy",
            "get_secret": "Access Secrets Manager Secret",
        }
        return titles.get(escalation_type, escalation_type.replace("_", " ").title())
    
    def _get_escalation_description(
        self, 
        escalation_type: str, 
        permission: ServicePermission
    ) -> str:
        """Get description for escalation."""
        templates = {
            "passrole_lambda": f"Can pass role to Lambda function, potentially executing code with elevated privileges on resource {permission.resource}",
            "create_access_key": f"Can create access keys for IAM users, enabling persistent backdoor access",
            "update_trust_policy": f"Can modify role trust policies, allowing arbitrary principals to assume roles",
            "lambda_code_injection": f"Can update Lambda function code, enabling arbitrary code execution with the function's role",
            "assume_role": f"Can assume IAM roles, potentially accessing resources in other accounts",
        }
        return templates.get(
            escalation_type, 
            f"Cross-service escalation via {permission.action} on {permission.resource}"
        )
    
    def _get_mitre_technique(self, escalation_type: str) -> str:
        """Get MITRE ATT&CK technique ID."""
        techniques = {
            "passrole_lambda": "T1548.005",
            "passrole_ec2": "T1548.005",
            "create_access_key": "T1098.001",
            "update_trust_policy": "T1484.002",
            "lambda_code_injection": "T1059.009",
            "assume_role": "T1550.001",
            "s3_data_access": "T1530",
            "get_secret": "T1552.005",
        }
        return techniques.get(escalation_type, "T1078")
    
    def _get_remediation_steps(self, escalation_type: str) -> List[str]:
        """Get remediation steps for escalation type."""
        remediations = {
            "passrole_lambda": [
                "Restrict iam:PassRole to specific role ARNs",
                "Add condition 'iam:PassedToService': 'lambda.amazonaws.com'",
                "Review and minimize Lambda execution role permissions",
            ],
            "create_access_key": [
                "Remove iam:CreateAccessKey permission",
                "Restrict to specific users if needed",
                "Enable MFA for sensitive IAM operations",
            ],
            "update_trust_policy": [
                "Remove iam:UpdateAssumeRolePolicy permission",
                "Use SCPs to prevent trust policy modifications",
                "Enable CloudTrail for IAM change monitoring",
            ],
            "lambda_code_injection": [
                "Restrict lambda:UpdateFunctionCode to specific functions",
                "Implement code signing for Lambda functions",
                "Use separate deployment roles with minimal permissions",
            ],
        }
        return remediations.get(escalation_type, [
            "Review and restrict permissions",
            "Apply principle of least privilege",
            "Enable logging and monitoring",
        ])
    
    def _generate_findings(self, config: ScanConfig) -> None:
        """Generate findings from chains."""
        for chain in self._result.chains:
            self._finding_counter += 1
            
            finding = CrossServiceFinding(
                finding_id=f"CS-{self._finding_counter:04d}",
                title=chain.title,
                description=chain.description,
                chain=chain,
                affected_principals=[chain.initial_principal],
                affected_resources=[chain.final_target],
                severity=chain.severity,
                risk_score=chain.total_risk_score,
                account_id=self.account_id,
                region=self.region,
                category=self._get_category(chain),
                attack_surface=self._get_attack_surface(chain),
                remediation=chain.quick_win,
                references=self._get_references(chain),
            )
            
            self._result.add_finding(finding)
    
    def _get_category(self, chain: CrossServiceChain) -> str:
        """Determine finding category."""
        if any(v.vector_type in [VectorType.DATA_EXFILTRATION, VectorType.SECRET_ACCESS] 
               for v in chain.vectors):
            return "data_access"
        if any(v.vector_type in [VectorType.BACKDOOR_USER, VectorType.BACKDOOR_ROLE]
               for v in chain.vectors):
            return "persistence"
        if any(v.vector_type in [VectorType.LAMBDA_UPDATE, VectorType.LAMBDA_INVOKE]
               for v in chain.vectors):
            return "code_execution"
        return "privilege_escalation"
    
    def _get_attack_surface(self, chain: CrossServiceChain) -> str:
        """Determine attack surface."""
        for v in chain.vectors:
            if hasattr(v, 'evidence'):
                if v.evidence.get('allows_cross_account'):
                    return "cross_account"
                if v.evidence.get('is_public'):
                    return "external"
        return "internal"
    
    def _get_references(self, chain: CrossServiceChain) -> List[str]:
        """Get reference links for finding."""
        return [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            "https://attack.mitre.org/tactics/TA0004/",
        ]
    
    def _build_multi_hop_chains(self, config: ScanConfig) -> None:
        """Build multi-hop cross-service attack chains."""
        # Collect analyzer data for context
        analyzer_data = self._collect_analyzer_data()
        
        for principal_arn, permissions in self._principal_permissions.items():
            chains = self._find_multi_hop_chains_for_principal(
                principal_arn,
                permissions,
                analyzer_data,
            )
            for chain in chains:
                self._result.add_chain(chain)
    
    def _collect_analyzer_data(self) -> dict:
        """Collect relevant data from all analyzers for multi-hop detection."""
        data = {
            "public_buckets": [],
            "imdsv1_instances": [],
            "s3_lambda_triggers": [],
            "sensitive_secrets": [],
            "cross_account_roles": [],
        }
        
        # S3 data
        s3_analyzer = self._analyzers.get(ServiceType.S3)
        if s3_analyzer:
            if hasattr(s3_analyzer, 'get_public_buckets'):
                data["public_buckets"] = [b.name for b in s3_analyzer.get_public_buckets()]
            if hasattr(s3_analyzer, '_buckets'):
                for name, info in s3_analyzer._buckets.items():
                    if hasattr(info, 'lambda_triggers') and info.lambda_triggers:
                        data["s3_lambda_triggers"].append({
                            "bucket": name,
                            "triggers": info.lambda_triggers,
                        })
        
        # EC2 data
        ec2_analyzer = self._analyzers.get(ServiceType.EC2)
        if ec2_analyzer and hasattr(ec2_analyzer, '_instances'):
            for iid, info in ec2_analyzer._instances.items():
                if hasattr(info, 'imdsv1_enabled') and info.imdsv1_enabled:
                    data["imdsv1_instances"].append({
                        "instance_id": iid,
                        "name": getattr(info, 'name', ''),
                        "profile_arn": getattr(info, 'instance_profile_arn', ''),
                    })
        
        # Secrets data
        secrets_analyzer = self._analyzers.get(ServiceType.SECRETS_MANAGER)
        if secrets_analyzer and hasattr(secrets_analyzer, 'get_sensitive_secrets'):
            data["sensitive_secrets"] = [s.name for s in secrets_analyzer.get_sensitive_secrets()]
        
        # STS data
        sts_analyzer = self._analyzers.get(ServiceType.STS)
        if sts_analyzer and hasattr(sts_analyzer, 'get_cross_account_roles'):
            data["cross_account_roles"] = [r.role_name for r in sts_analyzer.get_cross_account_roles()]
        
        return data
    
    def _find_multi_hop_chains_for_principal(
        self,
        principal_arn: str,
        permissions: List[ServicePermission],
        analyzer_data: dict,
    ) -> List[CrossServiceChain]:
        """Find multi-hop chains for a specific principal."""
        chains = []
        
        # Get matching patterns
        matches = find_matching_multi_hop(permissions, analyzer_data)
        
        for match in matches:
            pattern = match["pattern"]
            matched_hops = match["matched_hops"]
            
            self._chain_counter += 1
            
            # Build vectors for each hop
            vectors = []
            services_involved = set()
            
            for i, hop in enumerate(matched_hops):
                vector = AttackVector(
                    vector_id=f"vec_{self._chain_counter:04d}_{i+1}",
                    vector_type=self._get_vector_type_for_hop(hop),
                    source_service=hop["from"],
                    target_service=hop["to"],
                    source_principal=principal_arn,
                    target_resource=f"step_{i+1}",
                    severity=Severity[pattern["severity"]],
                    risk_score=self._calculate_hop_risk(hop, i),
                    title=f"Step {i+1}: {hop['action'].split(':')[-1] if ':' in hop['action'] else hop['action']}",
                    description=hop["desc"],
                    technique=pattern["mitre"][i] if i < len(pattern["mitre"]) else "",
                    evidence={"hop_index": i, "action": hop["action"]},
                )
                vectors.append(vector)
                services_involved.add(hop["from"])
                services_involved.add(hop["to"])
            
            # Create multi-hop chain
            chain = CrossServiceChain(
                chain_id=f"mhop_{self._chain_counter:04d}",
                title=f"🔗 {pattern['title']}",
                description=pattern["description"],
                initial_principal=principal_arn,
                final_target=f"{len(matched_hops)}-hop attack",
            )
            
            for v in vectors:
                chain.add_vector(v)
            
            # Add context from analyzer data
            chain.remediation_steps = self._get_multi_hop_remediation(pattern)
            chain.quick_win = chain.remediation_steps[0] if chain.remediation_steps else ""
            
            chains.append(chain)
        
        return chains
    
    def _get_vector_type_for_hop(self, hop: dict) -> VectorType:
        """Get vector type based on hop action."""
        action = hop["action"].lower()
        
        if "passrole" in action:
            return VectorType.PASSROLE
        if "assume" in action or "sts" in action:
            return VectorType.ASSUME_ROLE
        if "secret" in action:
            return VectorType.SECRET_ACCESS
        if "s3" in action:
            return VectorType.DATA_EXFILTRATION
        if "lambda" in action:
            return VectorType.LAMBDA_INVOKE
        if "ssm" in action or "ec2" in action:
            return VectorType.EC2_INSTANCE
        if "kms" in action:
            return VectorType.KEY_ACCESS
        
        return VectorType.DIRECT_POLICY
    
    def _calculate_hop_risk(self, hop: dict, index: int) -> int:
        """Calculate risk score for a specific hop."""
        base_risk = 50
        
        action = hop["action"].lower()
        
        # Action-based adjustments
        if "passrole" in action or "assume" in action:
            base_risk += 20
        if "secret" in action or "credential" in action:
            base_risk += 25
        if "admin" in action or "*" in action:
            base_risk += 30
        
        # Later hops are more dangerous (closer to goal)
        base_risk += index * 5
        
        return min(100, base_risk)
    
    def _get_multi_hop_remediation(self, pattern: dict) -> List[str]:
        """Get remediation steps for a multi-hop pattern."""
        name = pattern["name"]
        
        remediations = {
            "s3_lambda_secrets_exfil": [
                "Remove S3 event notifications or restrict to specific functions",
                "Restrict Lambda execution role secrets access",
                "Enable S3 bucket versioning and access logging",
            ],
            "ec2_imds_lateral_movement": [
                "Upgrade all instances to IMDSv2 (require token)",
                "Restrict instance profile permissions",
                "Enable VPC flow logs and CloudTrail",
            ],
            "passrole_lambda_data_exfil": [
                "Restrict iam:PassRole to specific roles",
                "Limit Lambda execution roles to least privilege",
                "Enable Lambda function logging",
            ],
            "kms_secrets_rds_chain": [
                "Restrict KMS key usage with key policies",
                "Rotate secrets regularly",
                "Enable RDS IAM authentication",
            ],
            "ssm_ec2_cloud_creds": [
                "Restrict ssm:StartSession to specific instances",
                "Use SSM Session Manager logging",
                "Implement least privilege for instance profiles",
            ],
            "s3_public_exfil": [
                "Remove public access from S3 buckets",
                "Enable S3 Block Public Access at account level",
                "Implement S3 access logging and monitoring",
            ],
        }
        
        return remediations.get(name, [
            "Review and restrict cross-service permissions",
            "Implement least privilege across all services",
            "Enable comprehensive logging and monitoring",
        ])
