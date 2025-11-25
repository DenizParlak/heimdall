"""
EKS Privilege Escalation Detector
Analyzes EKS clusters and IRSA roles to identify privilege escalation opportunities
"""

import logging
from typing import List, Dict, Any, Optional, Set
from heimdall.iam.privesc_patterns import PRIVESC_PATTERNS

logger = logging.getLogger(__name__)


class EKSDetector:
    """Detects EKS-specific privilege escalation opportunities"""
    
    def __init__(self, eks_data: Dict[str, Any], roles: List[Dict[str, Any]]):
        """
        Initialize EKS detector
        
        Args:
            eks_data: Output from EKSScanner.scan_all()
            roles: List of IAM roles from IAMScanner
        """
        self.eks_data = eks_data
        self.roles = roles
        self.clusters = eks_data.get('clusters', [])
        self.irsa_roles = eks_data.get('irsa_roles', {})
        
        # Build role lookup by ARN
        self.roles_by_arn = {role['arn']: role for role in roles}
    
    def detect_irsa_escalations(self, principal_arn: str, effective_permissions) -> List[Dict[str, Any]]:
        """
        Detect if a principal can escalate via IRSA (IAM Roles for Service Accounts)
        
        Args:
            principal_arn: ARN of the principal to check
            effective_permissions: EffectivePermissions object for the principal
            
        Returns:
            List of IRSA escalation findings
        """
        findings = []
        
        # Check if principal has eks:DescribeCluster (needed to know cluster details)
        if not effective_permissions.has_actions(['eks:DescribeCluster']):
            return findings
        
        # For each cluster, check if powerful IRSA roles exist
        for cluster_name, irsa_roles_list in self.irsa_roles.items():
            if not irsa_roles_list:
                continue
            
            # Find cluster data
            cluster_data = None
            for cluster in self.clusters:
                if cluster['name'] == cluster_name:
                    cluster_data = cluster
                    break
            
            if not cluster_data:
                continue
            
            # Check each IRSA role for privilege escalation potential
            for irsa_role in irsa_roles_list:
                role_arn = irsa_role['role_arn']
                role_data = self.roles_by_arn.get(role_arn)
                
                if not role_data:
                    continue
                
                # Check if IRSA role has powerful permissions
                is_powerful = self._is_powerful_role(role_data)
                
                if is_powerful:
                    findings.append({
                        'pattern_id': 'eks_irsa_pod_exec',
                        'pattern_name': PRIVESC_PATTERNS['eks_irsa_pod_exec'].name,
                        'severity': 'CRITICAL',
                        'method': 'eks_abuse',
                        'description': f'Can deploy pod with IRSA role {role_data["name"]} to escalate privileges',
                        'explanation': PRIVESC_PATTERNS['eks_irsa_pod_exec'].explanation,
                        'remediation': PRIVESC_PATTERNS['eks_irsa_pod_exec'].remediation,
                        'principal': principal_arn,
                        'target_role_arn': role_arn,
                        'target_role_name': role_data['name'],
                        'cluster_name': cluster_name,
                        'cluster_arn': cluster_data['arn'],
                        'oidc_provider_arn': cluster_data.get('oidc_provider_arn'),
                        'attack_vector': (
                            f"1. Use kubectl to deploy a pod with service account linked to {role_data['name']}\n"
                            f"2. Pod receives AWS_WEB_IDENTITY_TOKEN_FILE with OIDC token\n"
                            f"3. AWS SDK automatically assumes {role_data['name']} via sts:AssumeRoleWithWebIdentity\n"
                            f"4. Execute AWS CLI commands with elevated permissions"
                        ),
                        'required_actions': ['eks:DescribeCluster', 'kubectl access'],
                        'service': 'eks',
                        'eks_specific': True,
                    })
        
        return findings
    
    def detect_node_role_escalations(self, principal_arn: str, effective_permissions) -> List[Dict[str, Any]]:
        """
        Detect if a principal can escalate via EKS node roles (instance metadata abuse)
        
        Args:
            principal_arn: ARN of the principal to check
            effective_permissions: EffectivePermissions object for the principal
            
        Returns:
            List of node role escalation findings
        """
        findings = []
        
        # Check if principal has eks:DescribeCluster
        if not effective_permissions.has_actions(['eks:DescribeCluster']):
            return findings
        
        # For each cluster, check if node roles are powerful
        for cluster in self.clusters:
            node_roles = cluster.get('node_roles', [])
            
            for node_role_arn in node_roles:
                role_data = self.roles_by_arn.get(node_role_arn)
                
                if not role_data:
                    continue
                
                # Check if node role has powerful permissions
                is_powerful = self._is_powerful_role(role_data)
                
                if is_powerful:
                    findings.append({
                        'pattern_id': 'eks_node_role_abuse',
                        'pattern_name': PRIVESC_PATTERNS['eks_node_role_abuse'].name,
                        'severity': 'HIGH',
                        'method': 'eks_abuse',
                        'description': f'Can access EKS node role {role_data["name"]} via instance metadata',
                        'explanation': PRIVESC_PATTERNS['eks_node_role_abuse'].explanation,
                        'remediation': PRIVESC_PATTERNS['eks_node_role_abuse'].remediation,
                        'principal': principal_arn,
                        'target_role_arn': node_role_arn,
                        'target_role_name': role_data['name'],
                        'cluster_name': cluster['name'],
                        'cluster_arn': cluster['arn'],
                        'attack_vector': (
                            f"1. Deploy pod to cluster {cluster['name']}\n"
                            f"2. From inside pod: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_data['name']}\n"
                            f"3. Extract temporary credentials for {role_data['name']}\n"
                            f"4. Use credentials outside cluster for AWS API calls"
                        ),
                        'required_actions': ['eks:DescribeCluster', 'kubectl access'],
                        'service': 'eks',
                        'eks_specific': True,
                    })
        
        return findings
    
    def detect_passrole_escalations(self, principal_arn: str, effective_permissions) -> List[Dict[str, Any]]:
        """
        Detect PassRole + EKS escalations (CreateNodegroup, CreateFargateProfile)
        
        Args:
            principal_arn: ARN of the principal to check
            effective_permissions: EffectivePermissions object for the principal
            
        Returns:
            List of PassRole-based EKS escalation findings
        """
        findings = []
        
        # Check for PassRole + CreateNodegroup
        if effective_permissions.has_actions(['iam:PassRole', 'eks:CreateNodegroup']):
            # Find powerful roles that could be passed
            powerful_roles = self._find_powerful_roles()
            
            for role in powerful_roles:
                findings.append({
                    'pattern_id': 'eks_passrole_nodegroup',
                    'pattern_name': PRIVESC_PATTERNS['eks_passrole_nodegroup'].name,
                    'severity': 'CRITICAL',
                    'method': 'passrole_abuse',
                    'description': f'Create EKS node group with privileged role {role["name"]}',
                    'explanation': PRIVESC_PATTERNS['eks_passrole_nodegroup'].explanation,
                    'remediation': PRIVESC_PATTERNS['eks_passrole_nodegroup'].remediation,
                    'principal': principal_arn,
                    'target_role_arn': role['arn'],
                    'target_role_name': role['name'],
                    'attack_vector': (
                        f"1. aws eks create-nodegroup --role-arn {role['arn']}\n"
                        f"2. Wait for node group to launch EC2 instances\n"
                        f"3. Deploy pod to cluster with nodeSelector for new node group\n"
                        f"4. From pod, access instance metadata to get {role['name']} credentials"
                    ),
                    'required_actions': ['iam:PassRole', 'eks:CreateNodegroup'],
                    'service': 'eks',
                    'eks_specific': True,
                })
        
        # Check for PassRole + CreateFargateProfile
        if effective_permissions.has_actions(['iam:PassRole', 'eks:CreateFargateProfile']):
            powerful_roles = self._find_powerful_roles()
            
            for role in powerful_roles:
                findings.append({
                    'pattern_id': 'eks_passrole_fargate',
                    'pattern_name': PRIVESC_PATTERNS['eks_passrole_fargate'].name,
                    'severity': 'HIGH',
                    'method': 'passrole_abuse',
                    'description': f'Create Fargate profile with privileged pod execution role {role["name"]}',
                    'explanation': PRIVESC_PATTERNS['eks_passrole_fargate'].explanation,
                    'remediation': PRIVESC_PATTERNS['eks_passrole_fargate'].remediation,
                    'principal': principal_arn,
                    'target_role_arn': role['arn'],
                    'target_role_name': role['name'],
                    'attack_vector': (
                        f"1. aws eks create-fargate-profile --pod-execution-role-arn {role['arn']}\n"
                        f"2. Configure profile to match namespace 'attack-ns'\n"
                        f"3. Deploy pod to 'attack-ns' namespace\n"
                        f"4. Pod runs on Fargate with {role['name']} credentials in environment"
                    ),
                    'required_actions': ['iam:PassRole', 'eks:CreateFargateProfile'],
                    'service': 'eks',
                    'eks_specific': True,
                })
        
        return findings
    
    def detect_cluster_admin_escalations(self, principal_arn: str, effective_permissions) -> List[Dict[str, Any]]:
        """
        Detect cluster admin escalations (UpdateClusterConfig, eks:*)
        
        Args:
            principal_arn: ARN of the principal to check
            effective_permissions: EffectivePermissions object for the principal
            
        Returns:
            List of cluster admin escalation findings
        """
        findings = []
        
        # Check for UpdateClusterConfig
        if effective_permissions.has_actions(['eks:UpdateClusterConfig']):
            for cluster in self.clusters:
                findings.append({
                    'pattern_id': 'eks_update_cluster_config',
                    'pattern_name': PRIVESC_PATTERNS['eks_update_cluster_config'].name,
                    'severity': 'CRITICAL',
                    'method': 'eks_abuse',
                    'description': f'Can add self as cluster admin to {cluster["name"]}',
                    'explanation': PRIVESC_PATTERNS['eks_update_cluster_config'].explanation,
                    'remediation': PRIVESC_PATTERNS['eks_update_cluster_config'].remediation,
                    'principal': principal_arn,
                    'cluster_name': cluster['name'],
                    'cluster_arn': cluster['arn'],
                    'attack_vector': (
                        f"1. aws eks update-cluster-config --name {cluster['name']}\n"
                        f"2. Add {principal_arn} to access entries with system:masters\n"
                        f"3. Use kubectl with full cluster admin permissions\n"
                        f"4. Deploy privileged pods, access secrets, abuse IRSA roles"
                    ),
                    'required_actions': ['eks:UpdateClusterConfig'],
                    'service': 'eks',
                    'eks_specific': True,
                })
        
        # Check for eks:* wildcard
        if effective_permissions.has_actions(['eks:*']):
            findings.append({
                'pattern_id': 'eks_wildcard_permissions',
                'pattern_name': PRIVESC_PATTERNS['eks_wildcard_permissions'].name,
                'severity': 'CRITICAL',
                'method': 'eks_abuse',
                'description': 'Has unrestricted EKS permissions (eks:*)',
                'explanation': PRIVESC_PATTERNS['eks_wildcard_permissions'].explanation,
                'remediation': PRIVESC_PATTERNS['eks_wildcard_permissions'].remediation,
                'principal': principal_arn,
                'attack_vector': (
                    "With eks:* permissions, attacker can:\n"
                    "1. UpdateClusterConfig to add self as admin\n"
                    "2. CreateNodegroup/CreateFargateProfile with PassRole\n"
                    "3. Access OIDC details for IRSA abuse\n"
                    "4. Delete clusters for denial of service\n"
                    "5. Modify logging/monitoring to hide tracks"
                ),
                'required_actions': ['eks:*'],
                'service': 'eks',
                'eks_specific': True,
            })
        
        return findings
    
    def detect_all(self, principal_arn: str, effective_permissions) -> List[Dict[str, Any]]:
        """
        Run all EKS detection methods
        
        Args:
            principal_arn: ARN of the principal to check
            effective_permissions: EffectivePermissions object for the principal
            
        Returns:
            Combined list of all EKS escalation findings
        """
        findings = []
        
        # Run all detection methods
        findings.extend(self.detect_irsa_escalations(principal_arn, effective_permissions))
        findings.extend(self.detect_node_role_escalations(principal_arn, effective_permissions))
        findings.extend(self.detect_passrole_escalations(principal_arn, effective_permissions))
        findings.extend(self.detect_cluster_admin_escalations(principal_arn, effective_permissions))
        
        logger.info(f"Detected {len(findings)} EKS escalation opportunities for {principal_arn}")
        
        return findings
    
    def _is_powerful_role(self, role: Dict[str, Any]) -> bool:
        """
        Check if a role has powerful permissions (admin, sensitive resource access)
        
        Args:
            role: Role data from IAMScanner
            
        Returns:
            True if role is considered powerful/high-value
        """
        # Check attached policies for admin/power user indicators
        attached_policies = role.get('attached_policies', [])
        
        for policy in attached_policies:
            policy_name = policy.get('PolicyName', '').lower()
            
            # Check for admin policies
            if any(keyword in policy_name for keyword in [
                'admin', 'poweruser', 'fullaccess', 'administrator'
            ]):
                return True
        
        # Check inline policies for dangerous permissions
        inline_policies = role.get('inline_policies', {})
        
        # Handle both dict (from IAMScanner) and list formats
        if isinstance(inline_policies, dict):
            policy_docs = inline_policies.values()
        else:
            policy_docs = [p.get('PolicyDocument', {}) for p in inline_policies] if inline_policies else []
        
        for policy_doc in policy_docs:
            statements = policy_doc.get('Statement', [])
            
            if not isinstance(statements, list):
                statements = [statements]
            
            for statement in statements:
                if statement.get('Effect') != 'Allow':
                    continue
                
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                # Check for powerful action patterns
                for action in actions:
                    action_lower = action.lower()
                    
                    # Wildcards are powerful
                    if action_lower in ['*', '*:*']:
                        return True
                    
                    # Service-level wildcards
                    if action_lower in ['iam:*', 's3:*', 'ec2:*', 'lambda:*', 'secretsmanager:*']:
                        return True
                    
                    # Specific dangerous actions
                    if any(dangerous in action_lower for dangerous in [
                        'putrolepolicy', 'attachrolepolicy', 'createrole', 
                        'createaccesskey', 'updateassumerolepolicy',
                        'deletebucket', 'putbucketpolicy'
                    ]):
                        return True
        
        return False
    
    def _find_powerful_roles(self, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Find powerful/high-value roles for PassRole attacks
        
        Args:
            limit: Maximum number of roles to return
            
        Returns:
            List of powerful roles
        """
        powerful_roles = []
        
        for role in self.roles:
            if self._is_powerful_role(role):
                powerful_roles.append(role)
                
                if len(powerful_roles) >= limit:
                    break
        
        return powerful_roles
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics for EKS environment
        
        Returns:
            Dictionary with EKS security posture summary
        """
        total_irsa_roles = sum(len(roles) for roles in self.irsa_roles.values())
        total_node_roles = sum(len(cluster.get('node_roles', [])) for cluster in self.clusters)
        
        powerful_irsa_roles = []
        for cluster_name, irsa_roles_list in self.irsa_roles.items():
            for irsa_role in irsa_roles_list:
                role_data = self.roles_by_arn.get(irsa_role['role_arn'])
                if role_data and self._is_powerful_role(role_data):
                    powerful_irsa_roles.append(role_data['arn'])
        
        return {
            'total_clusters': len(self.clusters),
            'total_irsa_roles': total_irsa_roles,
            'powerful_irsa_roles': len(powerful_irsa_roles),
            'total_node_roles': total_node_roles,
            'clusters_with_oidc': sum(1 for c in self.clusters if c.get('oidc_provider_arn')),
        }
