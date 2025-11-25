"""
Graph Builder - Constructs assume-role relationship graphs from IAM data

v1.0.0: Enhanced with account ID extraction and cross-account edge detection
"""

import networkx as nx
from typing import List, Dict, Any
import re
from heimdall.iam.arn_utils import extract_account_id, is_cross_account


class GraphBuilder:
    """Builds directed graph of IAM assume-role relationships"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
    
    def build_from_principals(
        self,
        roles: List[Dict[str, Any]],
        users: List[Dict[str, Any]],
        eks_data: Dict[str, Any] = None,
        secrets_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Build graph from IAM roles and users
        
        Args:
            roles: List of role data from IAMScanner
            users: List of user data from IAMScanner
            eks_data: Optional EKS cluster and IRSA data (v1.1.0)
            secrets_data: Optional Secrets Manager and SSM data (v1.2.0)
            
        Returns:
            Graph data as dict (NetworkX node-link format)
        """
        # Add all principals as nodes
        for role in roles:
            account_id = extract_account_id(role['arn'])
            self.graph.add_node(
                role['arn'],
                type='role',
                name=role['name'],
                path=role['path'],
                account_id=account_id  # v1.0.0: Account enrichment
            )
        
        for user in users:
            account_id = extract_account_id(user['arn'])
            self.graph.add_node(
                user['arn'],
                type='user',
                name=user['name'],
                path=user['path'],
                account_id=account_id  # v1.0.0: Account enrichment
            )
        
        # Parse trust policies and add edges
        for role in roles:
            self._parse_trust_policy(role)
        
        # v1.1.0: Add EKS clusters and IRSA relationships
        if eks_data:
            self._add_eks_nodes(eks_data)
        
        # v1.2.0: Add Secrets Manager and SSM nodes
        if secrets_data:
            self._add_secrets_nodes(secrets_data, roles, users)
        
        # Convert to JSON-serializable format
        graph_data = nx.node_link_data(self.graph, edges='links')
        
        # Add stats
        role_count = sum(1 for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'role')
        user_count = sum(1 for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'user')
        service_count = sum(1 for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'service')
        federated_count = sum(1 for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'federated')
        eks_cluster_count = sum(1 for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'eks_cluster')  # v1.1.0
        secret_count = sum(1 for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'secret')  # v1.2.0
        parameter_count = sum(1 for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'parameter')  # v1.2.0
        
        # Count human→role direct paths and cross-account edges (v1.0.0)
        human_to_role_paths = 0
        cross_account_edges = 0
        for edge in self.graph.edges():
            source, target = edge
            if (self.graph.nodes[source].get('type') == 'user' and 
                self.graph.nodes[target].get('type') == 'role'):
                human_to_role_paths += 1
            
            # v1.0.0: Count cross-account edges
            edge_data = self.graph.edges[edge]
            if edge_data.get('cross_account', False):
                cross_account_edges += 1
        
        # Extract unique account IDs for v1.0.0
        accounts = set()
        for node in self.graph.nodes():
            account_id = self.graph.nodes[node].get('account_id')
            if account_id:
                accounts.add(account_id)
        
        graph_data['stats'] = {
            'node_count': self.graph.number_of_nodes(),
            'edge_count': self.graph.number_of_edges(),
            'role_count': role_count,
            'user_count': user_count,
            'service_count': service_count,
            'federated_count': federated_count,
            'eks_cluster_count': eks_cluster_count,  # v1.1.0
            'secret_count': secret_count,  # v1.2.0
            'parameter_count': parameter_count,  # v1.2.0
            'human_to_role_paths': human_to_role_paths,
            'cross_account_edges': cross_account_edges,  # v1.0.0
            'account_count': len(accounts),  # v1.0.0
            'accounts': sorted(list(accounts))  # v1.0.0
        }
        
        return graph_data
    
    def _parse_trust_policy(self, role: Dict[str, Any]):
        """
        Parse role's trust policy and add assume-role edges
        
        Args:
            role: Role data containing trust policy
        """
        trust_policy = role.get('trust_policy', {})
        role_arn = role['arn']
        
        # Parse each statement
        for statement in trust_policy.get('Statement', []):
            # Only process Allow statements
            if statement.get('Effect') != 'Allow':
                continue
            
            # Check if this is an AssumeRole statement
            action = statement.get('Action', [])
            if isinstance(action, str):
                action = [action]
            
            if not any('AssumeRole' in a for a in action):
                continue
            
            # Extract principals
            principal = statement.get('Principal', {})
            
            # AWS principals (IAM users/roles)
            if 'AWS' in principal:
                aws_principals = principal['AWS']
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                
                for principal_arn in aws_principals:
                    # Handle wildcard or account-level principals
                    if principal_arn == '*':
                        # Anyone can assume this role - very risky
                        if 'PUBLIC' not in self.graph.nodes():
                            self.graph.add_node('PUBLIC', type='public', name='PUBLIC')
                        self.graph.add_edge(
                            'PUBLIC',
                            role_arn,
                            type='assume_role',
                            condition='public',
                            risk='CRITICAL'
                        )
                    elif ':root' in principal_arn:
                        # Entire account can assume
                        account_id = self._extract_account_id(principal_arn)
                        account_node = f'account:{account_id}'
                        if account_node not in self.graph.nodes():
                            self.graph.add_node(account_node, type='account', name=account_id)
                        self.graph.add_edge(
                            account_node,
                            role_arn,
                            type='assume_role',
                            condition='account_wide',
                            risk='HIGH'
                        )
                    else:
                        # Specific principal
                        # Normalize ARN
                        normalized_arn = self._normalize_arn(principal_arn)
                        
                        # Only add edge if source node exists in graph
                        if normalized_arn in self.graph.nodes():
                            # v1.0.0: Check if this is a cross-account edge
                            cross_account = is_cross_account(normalized_arn, role_arn)
                            self.graph.add_edge(
                                normalized_arn,
                                role_arn,
                                type='assume_role',
                                risk='MEDIUM',
                                cross_account=cross_account
                            )
            
            # Service principals (e.g., ec2.amazonaws.com)
            if 'Service' in principal:
                services = principal['Service']
                if isinstance(services, str):
                    services = [services]
                
                for service in services:
                    service_node = f'service:{service}'
                    if service_node not in self.graph.nodes():
                        self.graph.add_node(service_node, type='service', name=service)
                    self.graph.add_edge(
                        service_node,
                        role_arn,
                        type='assume_role_service',
                        risk='LOW'
                    )
            
            # Federated principals (SAML, OIDC)
            if 'Federated' in principal:
                federated = principal['Federated']
                if isinstance(federated, str):
                    federated = [federated]
                
                for fed_arn in federated:
                    fed_node = f'federated:{fed_arn}'
                    if fed_node not in self.graph.nodes():
                        # Extract friendly name from ARN
                        fed_name = fed_arn.split('/')[-1] if '/' in fed_arn else fed_arn
                        self.graph.add_node(fed_node, type='federated', name=fed_name)
                    self.graph.add_edge(
                        fed_node,
                        role_arn,
                        type='assume_role_federated',
                        risk='MEDIUM'
                    )
    
    def _extract_account_id(self, arn: str) -> str:
        """Extract AWS account ID from ARN"""
        match = re.search(r':(\d{12}):', arn)
        return match.group(1) if match else 'unknown'
    
    def _normalize_arn(self, arn: str) -> str:
        """
        Normalize ARN format
        
        Handles cases like:
        - Full ARN: arn:aws:iam::123456789012:role/MyRole
        - Partial: 123456789012 or role/MyRole
        """
        if arn.startswith('arn:aws:iam::'):
            return arn
        
        # If it's just account ID, convert to root
        if arn.isdigit():
            return f'arn:aws:iam::{arn}:root'
        
        return arn
    
    def _add_eks_nodes(self, eks_data: Dict[str, Any]):
        """
        Add EKS clusters and their IRSA/node role relationships to the graph
        
        Args:
            eks_data: Output from EKSScanner.scan_all() containing clusters and IRSA roles
        """
        clusters = eks_data.get('clusters', [])
        irsa_roles = eks_data.get('irsa_roles', {})
        account_id = eks_data.get('account_id')
        region = eks_data.get('region')
        
        for cluster in clusters:
            cluster_arn = cluster.get('arn')
            cluster_name = cluster.get('name')
            
            # Add EKS cluster as a node
            self.graph.add_node(
                cluster_arn,
                type='eks_cluster',
                name=cluster_name,
                region=region,
                account_id=account_id,
                oidc_provider_arn=cluster.get('oidc_provider_arn'),
                oidc_issuer_url=cluster.get('oidc_issuer_url'),
                version=cluster.get('version'),
                status=cluster.get('status')
            )
            
            # Add edges from cluster to IRSA roles
            cluster_irsa_roles = irsa_roles.get(cluster_name, [])
            for irsa_role in cluster_irsa_roles:
                role_arn = irsa_role.get('role_arn')
                
                # Only add edge if the IAM role exists in graph
                if role_arn in self.graph.nodes():
                    self.graph.add_edge(
                        cluster_arn,
                        role_arn,
                        type='irsa_relationship',
                        risk='HIGH',
                        description=f'Pods in {cluster_name} can assume this role via IRSA'
                    )
            
            # Add edges from cluster to node roles
            node_roles = cluster.get('node_roles', [])
            for node_role_arn in node_roles:
                # Only add edge if the IAM role exists in graph
                if node_role_arn in self.graph.nodes():
                    self.graph.add_edge(
                        cluster_arn,
                        node_role_arn,
                        type='node_role',
                        risk='MEDIUM',
                        description=f'EKS nodes in {cluster_name} use this role'
                    )
    
    def _add_secrets_nodes(self, secrets_data: Dict[str, Any], roles: List[Dict], users: List[Dict]):
        """
        Add Secrets Manager and SSM Parameter Store nodes to the graph
        
        Args:
            secrets_data: Output from SecretsScanner.scan()
            roles: List of IAM roles (to check permissions)
            users: List of IAM users (to check permissions)
        """
        from heimdall.iam.policy_resolver import PolicyResolver
        
        # Add secret nodes (limit to high-value secrets for graph clarity)
        for secret in secrets_data.get('secrets', []):
            if not secret.get('high_value'):
                continue  # Only show high-value secrets in graph
            
            secret_id = f"secret:{secret['name']}"
            
            self.graph.add_node(
                secret_id,
                type='secret',
                name=secret['name'],
                arn=secret['arn'],
                high_value=secret['high_value'],
                value_indicators=secret.get('value_indicators', []),
                kms_encrypted=bool(secret.get('kms_key_id')),
                rotation_enabled=secret.get('rotation_enabled', False)
            )
        
        # Add parameter nodes (limit to high-value parameters)
        for param in secrets_data.get('parameters', []):
            if not param.get('high_value'):
                continue  # Only show high-value parameters in graph
            
            param_id = f"parameter:{param['name']}"
            
            self.graph.add_node(
                param_id,
                type='parameter',
                name=param['name'],
                param_type=param.get('type'),
                high_value=param['high_value'],
                value_indicators=param.get('value_indicators', []),
                kms_encrypted=bool(param.get('key_id'))
            )
        
        # Add edges from IAM principals to secrets they can access
        policy_resolver = PolicyResolver()
        
        for principal_data in roles + users:
            principal_arn = principal_data['arn']
            
            # Get effective permissions
            perms = policy_resolver.resolve_principal_permissions(principal_data)
            
            # Check Secrets Manager access
            if perms.has_actions(['secretsmanager:GetSecretValue']):
                for secret in secrets_data.get('secrets', []):
                    if not secret.get('high_value'):
                        continue
                    
                    secret_id = f"secret:{secret['name']}"
                    if secret_id in self.graph.nodes():
                        self.graph.add_edge(
                            principal_arn,
                            secret_id,
                            type='secret_access',
                            permission='secretsmanager:GetSecretValue',
                            risk='HIGH' if secret['high_value'] else 'MEDIUM'
                        )
            
            # Check SSM Parameter Store access
            if perms.has_actions(['ssm:GetParameter']) or perms.has_actions(['ssm:GetParameters']):
                for param in secrets_data.get('parameters', []):
                    if not param.get('high_value'):
                        continue
                    
                    param_id = f"parameter:{param['name']}"
                    if param_id in self.graph.nodes():
                        self.graph.add_edge(
                            principal_arn,
                            param_id,
                            type='parameter_access',
                            permission='ssm:GetParameter',
                            risk='HIGH' if param['high_value'] else 'MEDIUM'
                        )
