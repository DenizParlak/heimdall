"""
EKS Scanner - Scans AWS EKS clusters and IRSA (IAM Roles for Service Accounts)
"""

import boto3
from typing import List, Dict, Any, Optional
import json
import logging

logger = logging.getLogger(__name__)


class EKSScanner:
    """Scans AWS EKS clusters and extracts IRSA relationships"""
    
    def __init__(self, profile_name: str = 'default', region_name: str = None):
        """
        Initialize EKS scanner with AWS credentials
        
        Args:
            profile_name: AWS profile name from ~/.aws/credentials
            region_name: AWS region (optional, uses profile default)
        """
        self.session = boto3.Session(
            profile_name=profile_name,
            region_name=region_name
        )
        self.eks = self.session.client('eks')
        self.iam = self.session.client('iam')
        self.sts = self.session.client('sts')
        self.ec2 = self.session.client('ec2')
        
        # Get account ID and region
        try:
            self.account_id = self.sts.get_caller_identity()['Account']
            self.region = self.session.region_name or region_name or 'us-east-1'
        except Exception as e:
            raise RuntimeError(f"Failed to get AWS account ID: {e}")
    
    def scan_clusters(self) -> List[Dict[str, Any]]:
        """
        Scan all EKS clusters in the account/region
        
        Returns:
            List of cluster data including OIDC provider info
        """
        clusters = []
        
        try:
            # List all clusters
            response = self.eks.list_clusters()
            cluster_names = response.get('clusters', [])
            
            logger.info(f"Found {len(cluster_names)} EKS clusters in {self.region}")
            
            for cluster_name in cluster_names:
                try:
                    cluster_data = self._describe_cluster(cluster_name)
                    if cluster_data:
                        clusters.append(cluster_data)
                except Exception as e:
                    logger.error(f"Failed to describe cluster {cluster_name}: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Failed to list EKS clusters: {e}")
        
        return clusters
    
    def _describe_cluster(self, cluster_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about an EKS cluster
        
        Args:
            cluster_name: Name of the EKS cluster
            
        Returns:
            Cluster data with OIDC provider and node roles
        """
        try:
            response = self.eks.describe_cluster(name=cluster_name)
            cluster = response['cluster']
            
            # Extract OIDC issuer URL
            oidc_issuer = cluster.get('identity', {}).get('oidc', {}).get('issuer', '')
            
            cluster_data = {
                'type': 'eks_cluster',
                'name': cluster_name,
                'arn': cluster['arn'],
                'region': self.region,
                'version': cluster.get('version'),
                'status': cluster.get('status'),
                'endpoint': cluster.get('endpoint'),
                'created': cluster.get('createdAt').isoformat() if cluster.get('createdAt') else None,
                'oidc_issuer_url': oidc_issuer,
                'oidc_provider_arn': self._get_oidc_provider_arn(oidc_issuer),
                'node_roles': self._get_node_roles(cluster_name),
                'service_accounts': [],  # To be populated by kubectl in Phase 2
            }
            
            # Get VPC and security group info
            resources_vpc_config = cluster.get('resourcesVpcConfig', {})
            cluster_data['vpc_id'] = resources_vpc_config.get('vpcId')
            cluster_data['subnet_ids'] = resources_vpc_config.get('subnetIds', [])
            cluster_data['security_group_ids'] = resources_vpc_config.get('securityGroupIds', [])
            
            return cluster_data
            
        except Exception as e:
            logger.error(f"Failed to describe cluster {cluster_name}: {e}")
            return None
    
    def _get_oidc_provider_arn(self, oidc_issuer: str) -> Optional[str]:
        """
        Get the OIDC provider ARN for a given issuer URL
        
        Args:
            oidc_issuer: OIDC issuer URL from EKS cluster
            
        Returns:
            OIDC provider ARN if found, None otherwise
        """
        if not oidc_issuer:
            return None
        
        try:
            # Extract the OIDC ID from the issuer URL
            # Format: https://oidc.eks.{region}.amazonaws.com/id/{OIDC_ID}
            oidc_id = oidc_issuer.split('/')[-1]
            
            # List OIDC providers and find matching one
            response = self.iam.list_open_id_connect_providers()
            
            for provider in response.get('OpenIDConnectProviderList', []):
                provider_arn = provider['Arn']
                # Check if this provider matches our OIDC ID
                if oidc_id in provider_arn:
                    return provider_arn
            
            logger.warning(f"OIDC provider not found for issuer: {oidc_issuer}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to get OIDC provider ARN: {e}")
            return None
    
    def _get_node_roles(self, cluster_name: str) -> List[str]:
        """
        Get IAM roles used by EKS node groups
        
        Args:
            cluster_name: Name of the EKS cluster
            
        Returns:
            List of node role ARNs
        """
        node_roles = []
        
        try:
            # Get node groups
            response = self.eks.list_nodegroups(clusterName=cluster_name)
            nodegroup_names = response.get('nodegroups', [])
            
            for nodegroup_name in nodegroup_names:
                try:
                    ng_response = self.eks.describe_nodegroup(
                        clusterName=cluster_name,
                        nodegroupName=nodegroup_name
                    )
                    
                    node_role_arn = ng_response.get('nodegroup', {}).get('nodeRole')
                    if node_role_arn and node_role_arn not in node_roles:
                        node_roles.append(node_role_arn)
                        
                except Exception as e:
                    logger.error(f"Failed to describe nodegroup {nodegroup_name}: {e}")
                    continue
            
            # Also check for Fargate profiles (they have execution roles)
            try:
                fargate_response = self.eks.list_fargate_profiles(clusterName=cluster_name)
                fargate_profiles = fargate_response.get('fargateProfileNames', [])
                
                for profile_name in fargate_profiles:
                    try:
                        profile_response = self.eks.describe_fargate_profile(
                            clusterName=cluster_name,
                            fargateProfileName=profile_name
                        )
                        
                        pod_execution_role = profile_response.get('fargateProfile', {}).get('podExecutionRoleArn')
                        if pod_execution_role and pod_execution_role not in node_roles:
                            node_roles.append(pod_execution_role)
                            
                    except Exception as e:
                        logger.error(f"Failed to describe Fargate profile {profile_name}: {e}")
                        continue
                        
            except Exception as e:
                # Fargate may not be available in all regions
                logger.debug(f"Failed to list Fargate profiles: {e}")
            
        except Exception as e:
            logger.error(f"Failed to get node roles for cluster {cluster_name}: {e}")
        
        return node_roles
    
    def get_irsa_roles(self, oidc_provider_arn: str) -> List[Dict[str, Any]]:
        """
        Find IAM roles that can be assumed via IRSA (IAM Roles for Service Accounts)
        
        Args:
            oidc_provider_arn: ARN of the OIDC provider
            
        Returns:
            List of IAM roles with IRSA trust relationships
        """
        if not oidc_provider_arn:
            return []
        
        irsa_roles = []
        
        try:
            # List all roles
            paginator = self.iam.get_paginator('list_roles')
            
            for page in paginator.paginate():
                for role in page['Roles']:
                    try:
                        # Check trust policy for OIDC provider
                        trust_policy = role['AssumeRolePolicyDocument']
                        
                        # Check if this role trusts the OIDC provider
                        if self._is_irsa_role(trust_policy, oidc_provider_arn):
                            irsa_roles.append({
                                'role_name': role['RoleName'],
                                'role_arn': role['Arn'],
                                'trust_policy': trust_policy,
                                'created': role['CreateDate'].isoformat(),
                            })
                            
                    except Exception as e:
                        logger.debug(f"Error checking role {role.get('RoleName')}: {e}")
                        continue
            
        except Exception as e:
            logger.error(f"Failed to get IRSA roles: {e}")
        
        return irsa_roles
    
    def _is_irsa_role(self, trust_policy: Dict[str, Any], oidc_provider_arn: str) -> bool:
        """
        Check if a trust policy allows IRSA (assumes role via OIDC provider)
        
        Args:
            trust_policy: IAM role trust policy document
            oidc_provider_arn: ARN of the OIDC provider to check for
            
        Returns:
            True if this role can be assumed via IRSA
        """
        if not trust_policy or not oidc_provider_arn:
            return False
        
        # Extract OIDC provider URL from ARN
        # ARN format: arn:aws:iam::ACCOUNT:oidc-provider/oidc.eks.REGION.amazonaws.com/id/OIDC_ID
        oidc_url = oidc_provider_arn.split(':oidc-provider/')[-1]
        
        statements = trust_policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            # Check for AssumeRoleWithWebIdentity action
            action = statement.get('Action', '')
            if isinstance(action, list):
                action = action[0] if action else ''
            
            if 'AssumeRoleWithWebIdentity' not in action:
                continue
            
            # Check if principal is the OIDC provider
            principal = statement.get('Principal', {})
            federated = principal.get('Federated', '')
            
            if oidc_url in federated or oidc_provider_arn in federated:
                return True
        
        return False
    
    def scan_all(self) -> Dict[str, Any]:
        """
        Comprehensive scan of all EKS resources
        
        Returns:
            Dictionary containing clusters and IRSA roles
        """
        logger.info(f"Starting EKS scan for account {self.account_id} in region {self.region}")
        
        clusters = self.scan_clusters()
        
        # For each cluster, get IRSA roles
        all_irsa_roles = {}
        for cluster in clusters:
            oidc_provider_arn = cluster.get('oidc_provider_arn')
            if oidc_provider_arn:
                irsa_roles = self.get_irsa_roles(oidc_provider_arn)
                all_irsa_roles[cluster['name']] = irsa_roles
                logger.info(f"Found {len(irsa_roles)} IRSA roles for cluster {cluster['name']}")
        
        return {
            'clusters': clusters,
            'irsa_roles': all_irsa_roles,
            'account_id': self.account_id,
            'region': self.region,
        }
