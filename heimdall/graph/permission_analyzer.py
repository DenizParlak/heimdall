"""
Permission-Aware Path Analysis

Combines trust graph (AssumeRole) with permission analysis (IAM policies)
to detect privilege escalation opportunities.

Phase 2A-1: Basic permission-aware privesc detection
"""

from typing import List, Dict, Any, Set, Optional
from collections import deque
from heimdall.iam.policy_resolver import PolicyResolver, EffectivePermissions
from heimdall.iam.privesc_patterns import PrivescDetector
from heimdall.iam.arn_utils import extract_account_id, is_cross_account
from heimdall.iam.scp_resolver import SCPResolver


class PermissionAnalyzer:
    """
    Analyzes IAM permissions to detect privilege escalation opportunities.
    
    Combines:
    - Trust graph (who can assume which roles)
    - Permission analysis (what actions each principal can perform)
    - Privesc pattern matching
    """
    
    def __init__(
        self, 
        roles_data: List[Dict], 
        users_data: List[Dict], 
        iam_client=None,
        scp_policies: Optional[List[Dict[str, Any]]] = None,
        eks_data: Optional[Dict[str, Any]] = None,
        secrets_data: Optional[Dict[str, Any]] = None
    ):
        """
        Args:
            roles_data: List of role data from IAMScanner
            users_data: List of user data from IAMScanner
            iam_client: boto3 IAM client for fetching custom managed policies (Phase 2A-2)
            scp_policies: List of SCP policy documents for v1.0.0 evaluation
            eks_data: EKS cluster and IRSA data from EKSScanner (v1.1.0)
            secrets_data: Secrets Manager and SSM data from SecretsScanner (v1.2.0)
        """
        self.roles_data = roles_data
        self.users_data = users_data
        self.policy_resolver = PolicyResolver(iam_client=iam_client)
        self.privesc_detector = PrivescDetector()
        
        # v1.0.0: SCP evaluation
        self.scp_resolver = SCPResolver(scp_policies) if scp_policies else None
        
        # v1.2.0: Secrets impact analysis
        self.secrets_data = secrets_data
        
        # v1.1.0: EKS detection
        self.eks_detector = None
        if eks_data and eks_data.get('clusters'):
            from heimdall.iam.eks_detector import EKSDetector
            self.eks_detector = EKSDetector(eks_data, roles_data)
        
        # Cache for effective permissions
        self._permission_cache = {}
        
        # High-value roles (admin-level)
        self._high_value_roles = self._identify_high_value_roles()
    
    def _identify_high_value_roles(self) -> Set[str]:
        """
        Identify roles with admin or high-privilege access.
        
        Phase 2A-1: Simple heuristic based on policy names
        Phase 2A-2: Will analyze actual permissions
        """
        high_value = set()
        
        admin_policy_patterns = [
            'administratoraccess',
            'iamfullaccess',
            'admin',
            'root',
            'fullaccess'
        ]
        
        for role in self.roles_data:
            role_arn = role['arn']
            role_name = role['name'].lower()
            
            # Check role name
            if any(pattern in role_name for pattern in admin_policy_patterns):
                high_value.add(role_arn)
                continue
            
            # Check attached policies (FIX: use 'PolicyName' not 'name')
            for policy in role.get('attached_policies', []):
                policy_name = policy.get('PolicyName', '').lower()
                if any(pattern in policy_name for pattern in admin_policy_patterns):
                    high_value.add(role_arn)
                    break
        
        return high_value
    
    def _is_admin_principal(self, principal_data: Dict[str, Any]) -> bool:
        """
        Check if a principal has admin/high-privilege policies.
        
        Used by exclude_admin_roles to filter out already-admin principals.
        """
        admin_policy_patterns = [
            'administratoraccess',
            'poweruseraccess', 
            'iamfullaccess',
            'admin',
            'fullaccess',  # More specific than 'full' to avoid false positives (GPT's suggestion)
            'systemadministrator',
        ]
        
        # Check attached policies
        for policy in principal_data.get('attached_policies', []):
            # Support both 'PolicyName' (AWS API) and 'name' (scanner format)
            policy_name = policy.get('PolicyName', policy.get('name', '')).lower()
            if any(pattern in policy_name for pattern in admin_policy_patterns):
                return True
        
        # Check inline policies
        for policy_name in principal_data.get('inline_policies', {}).keys():
            if any(pattern in policy_name.lower() for pattern in admin_policy_patterns):
                return True
        
        # Check groups (for users)
        for group in principal_data.get('groups', []):
            if any(pattern in group.lower() for pattern in admin_policy_patterns):
                return True
        
        return False
    
    def _get_source_policies_for_finding(
        self,
        perms: 'EffectivePermissions',
        required_actions: List[str]
    ) -> List[str]:
        """
        Get the source policy names that grant the specific actions for this finding.
        This returns ONLY the policies that contribute to this specific privilege escalation.
        """
        source_policies = perms.get_source_policies_for_actions(required_actions)
        
        # Format inline policies
        formatted_policies = []
        for policy in source_policies:
            # Check if it's from a group (we need to track this in source_policy field)
            # For now, inline policies are already marked in source_policy
            formatted_policies.append(policy)
        
        return formatted_policies[:5]  # Limit to first 5
    
    def get_effective_permissions(self, principal_arn: str) -> EffectivePermissions:
        """Get or compute effective permissions for a principal"""
        if principal_arn in self._permission_cache:
            return self._permission_cache[principal_arn]
        
        # Find principal data
        principal_data = None
        for role in self.roles_data:
            if role['arn'] == principal_arn:
                principal_data = role
                break
        
        if not principal_data:
            for user in self.users_data:
                if user['arn'] == principal_arn:
                    principal_data = user
                    break
        
        if not principal_data:
            # Return empty permissions
            return EffectivePermissions(
                principal_arn=principal_arn,
                principal_type='unknown',
                statements=[]
            )
        
        # Resolve permissions
        perms = self.policy_resolver.resolve_principal_permissions(principal_data)
        self._permission_cache[principal_arn] = perms
        return perms
    
    def _extract_trust_principals(self, trust_policy: Dict[str, Any]) -> List[str]:
        """
        Extract principal ARNs from a trust policy.
        
        Args:
            trust_policy: AssumeRolePolicyDocument
        
        Returns:
            List of principal ARNs that can assume the role
        """
        principals = []
        
        for statement in trust_policy.get('Statement', []):
            if statement.get('Effect') != 'Allow':
                continue
            
            principal_block = statement.get('Principal', {})
            
            # Handle AWS principals (can be string or list)
            aws_principals = principal_block.get('AWS', [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            
            for p in aws_principals:
                # Could be ARN or account root (arn:aws:iam::123456789012:root)
                if p.startswith('arn:'):
                    principals.append(p)
                elif p.isdigit() and len(p) == 12:
                    # Account ID -> convert to root ARN
                    principals.append(f"arn:aws:iam::{p}:root")
        
        return principals
    
    def detect_direct_privesc(self, exclude_admin_roles: bool = False) -> List[Dict[str, Any]]:
        """
        Detect direct privilege escalation opportunities.
        
        A principal has direct privesc if they have permissions matching
        a known privesc pattern (e.g., iam:AttachUserPolicy).
        
        Returns:
            List of privesc findings
        """
        findings = []
        
        # Check all users
        for user in self.users_data:
            user_arn = user['arn']
            perms = self.get_effective_permissions(user_arn)
            
            # Skip admin users if requested
            if exclude_admin_roles and self._is_admin_principal(user):
                continue
            
            # Detect privesc methods
            methods = self.privesc_detector.detect_privesc_methods(
                perms,
                high_value_roles=self._high_value_roles
            )
            
            for method in methods:
                finding = {
                    'type': 'direct_privesc',
                    'principal': user_arn,
                    'principal_name': user.get('name'),
                    'principal_type': 'user',
                    'severity': method['severity'],
                    'privesc_method': method['pattern_id'],
                    'description': method['description'],
                    'explanation': method['explanation'],
                    'remediation': method['remediation'],
                    'required_actions': method['required_actions'],
                    'conditional_requirements': method.get('conditional_requirements'),
                    'source_policies': self._get_source_policies_for_finding(perms, method['required_actions'])
                }
                
                # v1.0.0: Add account ID enrichment
                account_id = extract_account_id(user_arn)
                if account_id:
                    finding['source_account_id'] = account_id
                    finding['target_account_id'] = account_id  # User acting in own account
                    finding['cross_account'] = False
                
                # v1.0.0: Check SCP blocking
                if self.scp_resolver and account_id:
                    scp_blocked = self.scp_resolver.is_any_action_blocked(
                        account_id,
                        method['required_actions']
                    )
                    finding['scp_blocked'] = scp_blocked
                    
                    if scp_blocked:
                        blocking_policies = self.scp_resolver.get_blocking_policies(
                            account_id,
                            method['required_actions']
                        )
                        finding['scp_policies_blocking'] = blocking_policies
                
                # v1.2.0: Analyze secrets impact
                self._analyze_secrets_impact(finding, perms)
                
                # v1.8.0: Add target_role for patterns that require it
                pattern = self.privesc_detector.get_pattern_by_id(method['pattern_id'])
                if pattern and pattern.requires_target_role and self._high_value_roles:
                    # Find a high-value role that this principal can pass to
                    target_role = self._find_passable_role(perms, list(self._high_value_roles))
                    if target_role:
                        finding['target_role'] = target_role
                        finding['target_role_name'] = target_role.split('/')[-1]
                
                findings.append(finding)
        
        # Check all roles
        for role in self.roles_data:
            role_arn = role['arn']
            perms = self.get_effective_permissions(role_arn)
            
            # Skip admin roles if requested
            if exclude_admin_roles and self._is_admin_principal(role):
                continue
            
            methods = self.privesc_detector.detect_privesc_methods(
                perms,
                high_value_roles=self._high_value_roles
            )
            
            for method in methods:
                finding = {
                    'type': 'direct_privesc',
                    'principal': role_arn,
                    'principal_name': role['name'],
                    'principal_type': 'role',
                    'severity': method['severity'],
                    'privesc_method': method['pattern_id'],
                    'description': method['description'],
                    'explanation': method['explanation'],
                    'remediation': method['remediation'],
                    'required_actions': method['required_actions'],
                    'conditional_requirements': method.get('conditional_requirements'),
                    'source_policies': self._get_source_policies_for_finding(perms, method['required_actions'])
                }
                
                # v1.0.0: Add account ID enrichment
                role_account_id = extract_account_id(role_arn)
                if role_account_id:
                    finding['target_account_id'] = role_account_id
                    
                    # Check if this is a cross-account privesc
                    # (user from different account assuming this role)
                    trust_policy = role.get('trust_policy', {})
                    source_principals = self._extract_trust_principals(trust_policy)
                    
                    # If role trusts principals from other accounts, mark as cross-account
                    cross_account = False
                    source_account_ids = set()
                    for principal_arn in source_principals:
                        source_acct = extract_account_id(principal_arn)
                        if source_acct:
                            source_account_ids.add(source_acct)
                            if source_acct != role_account_id:
                                cross_account = True
                    
                    finding['cross_account'] = cross_account
                    if source_account_ids:
                        # Pick first source account (or could be list in future)
                        finding['source_account_id'] = list(source_account_ids)[0]
                    else:
                        finding['source_account_id'] = role_account_id
                
                # v1.0.0: Check SCP blocking
                if self.scp_resolver and role_account_id:
                    scp_blocked = self.scp_resolver.is_any_action_blocked(
                        role_account_id,
                        method['required_actions']
                    )
                    finding['scp_blocked'] = scp_blocked
                    
                    if scp_blocked:
                        blocking_policies = self.scp_resolver.get_blocking_policies(
                            role_account_id,
                            method['required_actions']
                        )
                        finding['scp_policies_blocking'] = blocking_policies
                        finding['scp_block_location'] = 'target_account'
                
                # v1.2.0: Analyze secrets impact
                self._analyze_secrets_impact(finding, perms)
                
                # v1.8.0: Add target_role for patterns that require it
                pattern = self.privesc_detector.get_pattern_by_id(method['pattern_id'])
                if pattern and pattern.requires_target_role and self._high_value_roles:
                    # Find a high-value role that this principal can pass to
                    target_role = self._find_passable_role(perms, list(self._high_value_roles))
                    if target_role:
                        finding['target_role'] = target_role
                        finding['target_role_name'] = target_role.split('/')[-1]
                
                findings.append(finding)
        
        # v1.1.0: Add EKS-specific findings
        if self.eks_detector:
            # Check EKS escalations for all principals
            for principal_data in self.roles_data + self.users_data:
                principal_arn = principal_data['arn']
                principal_name = principal_data['name']
                principal_type = 'role' if principal_arn.startswith('arn:aws:iam::') and ':role/' in principal_arn else 'user'
                
                perms = self.get_effective_permissions(principal_arn)
                eks_findings = self.eks_detector.detect_all(principal_arn, perms)
                
                for eks_finding in eks_findings:
                    finding = {
                        'type': 'direct_privesc',
                        'principal': principal_arn,
                        'principal_name': principal_name,
                        'principal_type': principal_type,
                        'severity': eks_finding['severity'],
                        'privesc_method': eks_finding['pattern_id'],
                        'description': eks_finding['description'],
                        'explanation': eks_finding.get('explanation', ''),
                        'remediation': eks_finding.get('remediation', ''),
                        'required_actions': eks_finding.get('required_actions', []),
                        'service': 'eks',
                        'eks_specific': True,
                    }
                    
                    # Add EKS-specific context
                    if 'cluster_name' in eks_finding:
                        finding['cluster_name'] = eks_finding['cluster_name']
                    if 'cluster_arn' in eks_finding:
                        finding['cluster_arn'] = eks_finding['cluster_arn']
                    if 'target_role_arn' in eks_finding:
                        finding['target_role_arn'] = eks_finding['target_role_arn']
                        finding['target_role_name'] = eks_finding.get('target_role_name', '')
                    if 'attack_vector' in eks_finding:
                        finding['attack_vector'] = eks_finding['attack_vector']
                    
                    # Add account ID context
                    account_id = extract_account_id(principal_arn)
                    if account_id:
                        finding['source_account_id'] = account_id
                        finding['target_account_id'] = account_id
                        finding['cross_account'] = False
                    
                    findings.append(finding)
        
        # Optionally exclude admin/high-privilege roles from findings to reduce noise
        if exclude_admin_roles:
            findings = [
                f for f in findings
                if not (
                    f.get('principal_type') == 'role'
                    and f.get('principal') in self._high_value_roles
                )
            ]
        
        return findings
    
    def detect_indirect_privesc(
        self, 
        trust_graph: Dict[str, Any], 
        max_depth: int = 2,
        exclude_admin_roles: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Detect indirect (second-order) privilege escalation through multi-hop trust chains.
        
        Example:
            user/junior → sts:AssumeRole → role/DevRole
                        → sts:AssumeRole → role/AdminRole (has attach_user_policy)
        
        Args:
            trust_graph: Trust graph with nodes and links (from GraphBuilder)
            max_depth: Maximum number of AssumeRole hops to explore (default: 2)
            exclude_admin_roles: If True, don't report paths starting from admin roles
            
        Returns:
            List of indirect privesc findings with path information
        """
        findings = []
        
        # Step 1: Build adjacency list from trust graph
        adjacency = self._build_adjacency_from_trust_graph(trust_graph)
        
        # Step 2: Get starting principals (users + non-admin roles)
        start_principals = []
        
        # Add all users
        for user in self.users_data:
            start_principals.append(user['arn'])
        
        # Add roles (optionally excluding admin roles)
        for role in self.roles_data:
            role_arn = role['arn']
            if exclude_admin_roles and role_arn in self._high_value_roles:
                continue
            start_principals.append(role_arn)
        
        # Step 3: For each starting principal, find reachable roles and check for patterns
        for start_arn in start_principals:
            paths = self._find_reachable_roles_bfs(start_arn, adjacency, max_depth)
            
            for path_info in paths:
                target_arn = path_info['target_principal']
                
                # Don't check if target is the same as start (no hop)
                if target_arn == start_arn:
                    continue
                
                # Get effective permissions of target role
                target_perms = self.get_effective_permissions(target_arn)
                
                # Detect privesc patterns on target
                methods = self.privesc_detector.detect_privesc_methods(
                    target_perms,
                    high_value_roles=self._high_value_roles
                )
                
                # Create findings for each detected pattern
                for method in methods:
                    # Get start principal info
                    start_name = self._get_principal_name(start_arn)
                    start_type = 'user' if ':user/' in start_arn else 'role'
                    
                    findings.append({
                        'type': 'indirect_privesc',
                        'start_principal': start_arn,
                        'start_principal_name': start_name,
                        'start_principal_type': start_type,
                        'path': path_info['hops'],
                        'path_length': path_info['path_length'],
                        'target_principal': target_arn,
                        'target_principal_name': self._get_principal_name(target_arn),
                        'severity': method['severity'],
                        'privesc_method': method['pattern_id'],
                        'description': method['description'],
                        'explanation': method['explanation'],
                        'remediation': method['remediation'],
                        'required_actions': method['required_actions']
                    })
        
        return findings
    
    def _build_adjacency_from_trust_graph(self, trust_graph: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Build adjacency list: principal_arn → [reachable_role_arns]
        
        Only includes 'can_assume' relationships (sts:AssumeRole).
        """
        adjacency = {}
        
        for link in trust_graph.get('links', []):
            # Only process AssumeRole relationships
            # Check both 'relationship' (legacy) and 'type' (GraphBuilder format)
            link_type = link.get('relationship') or link.get('type')
            if link_type in ['can_assume', 'assume_role']:
                source = link['source']
                target = link['target']
                
                if source not in adjacency:
                    adjacency[source] = []
                adjacency[source].append(target)
        
        return adjacency
    
    def _find_reachable_roles_bfs(
        self, 
        start_arn: str, 
        adjacency: Dict[str, List[str]], 
        max_depth: int
    ) -> List[Dict[str, Any]]:
        """
        BFS to find ALL roles reachable from start_arn within max_depth hops.
        
        Important: Finds ALL paths, not just one per destination.
        Uses path-specific cycle detection instead of global visited set.
        
        Returns:
            List of path information dicts with:
                - target_principal: final role ARN
                - hops: list of {from, to, action} dicts
                - path_length: number of hops
        """
        queue = deque([(start_arn, [], 0, set())])  # (current_arn, path_so_far, depth, visited_in_this_path)
        paths = []
        
        while queue:
            current, path, depth, path_visited = queue.popleft()
            
            # Skip if we've exceeded max depth
            if depth > max_depth:
                continue
            
            # Skip if this node is already in the current path (cycle detection)
            if current in path_visited:
                continue
            
            # Add current to this path's visited set
            path_visited = path_visited | {current}
            
            # Record this path if we've made at least one hop
            if depth > 0:
                paths.append({
                    'target_principal': current,
                    'hops': path.copy(),
                    'path_length': depth
                })
            
            # Explore neighbors
            for neighbor in adjacency.get(current, []):
                # Only skip if neighbor is already in THIS path (prevents cycles)
                if neighbor not in path_visited:
                    new_hop = {
                        'from': current,
                        'to': neighbor,
                        'action': 'sts:AssumeRole'
                    }
                    new_path = path + [new_hop]
                    queue.append((neighbor, new_path, depth + 1, path_visited))
        
        return paths
    
    def _get_principal_name(self, arn: str) -> str:
        """Extract principal name from ARN."""
        # ARN format: arn:aws:iam::123456789012:user/name or role/name
        if '/' in arn:
            return arn.split('/')[-1]
        return arn
    
    def _analyze_secrets_impact(self, finding: Dict, perms: 'EffectivePermissions') -> None:
        """
        Analyze what secrets/parameters this finding can access (v1.2.0)
        
        Args:
            finding: Finding dict to enrich
            perms: Effective permissions of the principal
        """
        if not self.secrets_data:
            return
        
        accessible_secrets = []
        accessible_parameters = []
        
        # Check Secrets Manager access
        if perms.has_actions(['secretsmanager:GetSecretValue']):
            # Check if wildcard or specific secrets
            for secret in self.secrets_data.get('secrets', []):
                secret_arn = secret['arn']
                
                # Simple check: if permission is granted, consider it accessible
                # TODO: More sophisticated resource constraint checking
                if perms.has_actions(['secretsmanager:GetSecretValue']):
                    accessible_secrets.append({
                        'arn': secret['arn'],
                        'name': secret['name'],
                        'high_value': secret['high_value'],
                        'value_indicators': secret.get('value_indicators', []),
                        'kms_encrypted': bool(secret.get('kms_key_id'))
                    })
        
        # Check SSM Parameter Store access
        if perms.has_actions(['ssm:GetParameter']) or perms.has_actions(['ssm:GetParameters']):
            for param in self.secrets_data.get('parameters', []):
                accessible_parameters.append({
                    'name': param['name'],
                    'type': param.get('type'),
                    'high_value': param['high_value'],
                    'value_indicators': param.get('value_indicators', []),
                    'kms_encrypted': bool(param.get('key_id'))
                })
        
        # Add impacted_secrets field if any secrets are accessible
        if accessible_secrets or accessible_parameters:
            finding['impacted_secrets'] = {
                'secrets': accessible_secrets[:10],  # Limit to top 10
                'parameters': accessible_parameters[:10],  # Limit to top 10
                'total_secrets': len(accessible_secrets),
                'total_parameters': len(accessible_parameters),
                'total_count': len(accessible_secrets) + len(accessible_parameters),
                'high_value_count': sum(1 for s in accessible_secrets if s['high_value']) + 
                                   sum(1 for p in accessible_parameters if p['high_value'])
            }
    
    def _find_passable_role(self, perms: 'EffectivePermissions', high_value_roles: List[str]) -> Optional[str]:
        """
        Find a high-value role that this principal can pass to a service.
        
        Args:
            perms: Effective permissions of the principal
            high_value_roles: List of high-value role ARNs
            
        Returns:
            ARN of a passable high-value role, or None
        """
        # Check if principal has iam:PassRole permission
        if not perms.has_actions(['iam:PassRole']):
            return None
        
        # Return the first high-value role (could be enhanced to check resource constraints)
        # TODO: Check if PassRole is restricted to specific roles via resource constraints
        if high_value_roles:
            return high_value_roles[0]
        
        return None
    
    def enhance_trust_graph_risks(self, risky_paths: List[Dict]) -> List[Dict]:
        """
        Enhance existing trust-graph risky paths with permission analysis.
        
        Phase 2A-1: Add info about what the target role can do
        
        Args:
            risky_paths: Risky paths from PathAnalyzer (trust graph only)
            
        Returns:
            Enhanced risky paths with permission details
        """
        enhanced = []
        
        for path_info in risky_paths:
            # Get target (last node in path)
            target_arn = path_info['path'][-1]
            
            # Get target permissions
            target_perms = self.get_effective_permissions(target_arn)
            
            # Detect what the target can do
            target_methods = self.privesc_detector.detect_privesc_methods(
                target_perms,
                high_value_roles=self._high_value_roles
            )
            
            # Enhance the path info
            enhanced_path = path_info.copy()
            enhanced_path['target_permissions'] = {
                'can_further_escalate': len(target_methods) > 0,
                'privesc_methods': [m['pattern_id'] for m in target_methods],
                'all_actions_count': len(target_perms.get_all_actions())
            }
            
            enhanced.append(enhanced_path)
        
        return enhanced
