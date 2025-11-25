"""
Resource Analyzer - Maps IAM roles to real AWS resources (EC2, Lambda, etc.)

This module identifies which real AWS resources are impacted by IAM privilege
escalation findings, providing "real world impact" context.

DESIGN PHILOSOPHY (v0.8.0):
---------------------------
This is NOT a generic resource security scanner (like ScoutSuite/Prowler).
This is an IAM-centered impact analyzer that answers:
  "When an attacker escalates via this IAM path, which real resources do they gain access to?"

Flow: IAM Privesc Finding → Target Role → Resource Access Mapping
Example: user/contractor → passrole_lambda → AdminRole
         → EC2: 3 bastion hosts
         → Lambda: 2 prod functions  
         → S3: prod-customer-data (PII), prod-financial-records (Financial)
         
The S3/RDS/Secrets analysis is always in the context of a privilege escalation
finding, not standalone resource configuration issues.

UNIQUE VALUE vs. Other Tools:
- ScoutSuite/Prowler: Generic resource misconfig (S3 public, RDS unencrypted)
- PMapper: IAM privesc paths only (no resource context)
- Heimdall: IAM privesc paths + real resource impact = attack scenario intelligence
"""

from typing import List, Dict, Any, Optional
from heimdall.iam.policy_resolver import PolicyResolver


class ResourceAnalyzer:
    """
    Analyzes real AWS resources impacted by IAM findings.
    
    Maps IAM roles to:
    - EC2 instances (via instance profiles)
    - Lambda functions (via execution roles)
    - S3 buckets (via IAM permissions) - v0.8.0
    - Future: RDS instances, Secrets Manager, etc.
    """
    
    def __init__(
        self,
        ec2_instances: List[Dict[str, Any]],
        lambda_functions: List[Dict[str, Any]],
        instance_profiles: Dict[str, Dict[str, Any]],
        s3_client=None,
        rds_client=None,
        secrets_client=None,
        ssm_client=None,
        policy_resolver: Optional[PolicyResolver] = None
    ):
        """
        Initialize resource analyzer with AWS resource data.
        
        Args:
            ec2_instances: List of EC2 instance data from describe_instances
            lambda_functions: List of Lambda function data from list_functions
            instance_profiles: Dict mapping instance profile ARN to role data
            s3_client: Optional boto3 S3 client for bucket scanning (v0.8.0)
            rds_client: Optional boto3 RDS client for database scanning (v0.8.0)
            secrets_client: Optional boto3 Secrets Manager client (v0.8.1)
            ssm_client: Optional boto3 SSM client for parameter scanning (v0.8.1)
            policy_resolver: Optional PolicyResolver for accurate permission checking
        """
        self.ec2_instances = ec2_instances
        self.lambda_functions = lambda_functions
        self.instance_profiles = instance_profiles
        self.s3_client = s3_client
        self.rds_client = rds_client
        self.secrets_client = secrets_client
        self.ssm_client = ssm_client
        self.policy_resolver = policy_resolver
        
        # Cache for S3 buckets (lazy-loaded)
        self._s3_buckets_cache = None
        
        # Cache for RDS instances (lazy-loaded) - v0.8.0 Phase 2
        self._rds_instances_cache = None
        
        # Build reverse indexes for fast lookup
        self._build_indexes()
    
    def _build_indexes(self):
        """Build reverse indexes for efficient role → resource lookups"""
        
        # Role ARN → EC2 instances
        self.role_to_instances = {}
        for instance in self.ec2_instances:
            if 'IamInstanceProfile' in instance:
                profile_arn = instance['IamInstanceProfile']['Arn']
                
                # Get role from instance profile
                if profile_arn in self.instance_profiles:
                    roles = self.instance_profiles[profile_arn].get('Roles', [])
                    for role in roles:
                        role_arn = role['Arn']
                        if role_arn not in self.role_to_instances:
                            self.role_to_instances[role_arn] = []
                        self.role_to_instances[role_arn].append(instance)
        
        # Role ARN → Lambda functions
        self.role_to_lambdas = {}
        for function in self.lambda_functions:
            role_arn = function.get('Role')
            if role_arn:
                if role_arn not in self.role_to_lambdas:
                    self.role_to_lambdas[role_arn] = []
                self.role_to_lambdas[role_arn].append(function)
    
    def map_role_to_instances(self, role_arn: str) -> List[Dict[str, Any]]:
        """
        Find EC2 instances using this IAM role (via instance profile).
        
        Args:
            role_arn: ARN of the IAM role
            
        Returns:
            List of simplified EC2 instance data
        """
        instances = self.role_to_instances.get(role_arn, [])
        
        return [self._simplify_instance(inst) for inst in instances]
    
    def map_role_to_lambdas(self, role_arn: str) -> List[Dict[str, Any]]:
        """
        Find Lambda functions using this IAM role as execution role.
        
        Args:
            role_arn: ARN of the IAM role
            
        Returns:
            List of simplified Lambda function data
        """
        functions = self.role_to_lambdas.get(role_arn, [])
        
        return [self._simplify_lambda(func) for func in functions]
    
    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add impacted_resources field to a privilege escalation finding.
        
        Args:
            finding: Privilege escalation finding dict
            
        Returns:
            Finding dict with added 'impacted_resources' field
        """
        principal_type = finding.get('principal_type')
        
        # Only roles can have EC2/Lambda resources
        if principal_type != 'role':
            return finding
        
        principal_arn = finding.get('principal')
        if not principal_arn:
            return finding
        
        # Get impacted resources
        ec2_instances = self.map_role_to_instances(principal_arn)
        lambda_functions = self.map_role_to_lambdas(principal_arn)
        
        # Skip if no resources
        if not ec2_instances and not lambda_functions:
            return finding
        
        # Generate impact summary
        impact_summary = self._generate_impact_summary(
            ec2_instances, 
            lambda_functions,
            finding.get('privesc_method', '')
        )
        
        # Add to finding
        finding['impacted_resources'] = {
            'ec2_instances': ec2_instances,
            'lambda_functions': lambda_functions,
            'impact_summary': impact_summary
        }
        
        return finding
    
    def _simplify_instance(self, instance: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key fields from EC2 instance data"""
        
        # Extract tags as dict
        tags = {}
        for tag in instance.get('Tags', []):
            tags[tag['Key']] = tag['Value']
        
        return {
            'instance_id': instance['InstanceId'],
            'name': tags.get('Name', instance['InstanceId']),
            'instance_profile': instance.get('IamInstanceProfile', {}).get('Arn', ''),
            'public_ip': instance.get('PublicIpAddress'),
            'private_ip': instance.get('PrivateIpAddress'),
            'vpc_id': instance.get('VpcId'),
            'state': instance.get('State', {}).get('Name', 'unknown'),
            'tags': tags
        }
    
    def _simplify_lambda(self, function: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key fields from Lambda function data"""
        
        vpc_config = function.get('VpcConfig', {})
        
        return {
            'function_name': function['FunctionName'],
            'function_arn': function.get('FunctionArn'),
            'runtime': function.get('Runtime'),
            'role': function.get('Role'),
            'vpc_id': vpc_config.get('VpcId'),
            'environment': function.get('Environment', {}).get('Variables', {})
        }
    
    def _generate_impact_summary(
        self,
        ec2_instances: List[Dict],
        lambda_functions: List[Dict],
        privesc_method: str
    ) -> str:
        """
        Generate a concise human-readable impact summary.
        
        Args:
            ec2_instances: List of impacted EC2 instances
            lambda_functions: List of impacted Lambda functions
            privesc_method: Privilege escalation method
            
        Returns:
            Impact summary string
        """
        parts = []
        
        # EC2 impact
        if ec2_instances:
            count = len(ec2_instances)
            
            # Check if instances are production
            prod_count = sum(
                1 for inst in ec2_instances 
                if 'production' in inst.get('tags', {}).get('Environment', '').lower()
            )
            
            # Check for bastion/jump hosts
            bastion_count = sum(
                1 for inst in ec2_instances
                if any(keyword in inst.get('name', '').lower() 
                      for keyword in ['bastion', 'jump', 'jumpbox'])
            )
            
            if bastion_count > 0:
                parts.append(f"shell access to {bastion_count} bastion host{'s' if bastion_count > 1 else ''}")
            elif prod_count > 0:
                parts.append(f"shell access to {prod_count} production instance{'s' if prod_count > 1 else ''}")
            else:
                parts.append(f"shell access to {count} EC2 instance{'s' if count > 1 else ''}")
        
        # Lambda impact
        if lambda_functions:
            count = len(lambda_functions)
            parts.append(f"code execution in {count} Lambda function{'s' if count > 1 else ''}")
        
        # Combine
        if not parts:
            return "No direct resource impact identified"
        
        impact = " + ".join(parts)
        return f"This path gives you {impact}"
    
    # =========================================================================
    # S3 Bucket Analysis (v0.8.0)
    # =========================================================================
    
    def scan_s3_buckets(self, max_buckets: int = 1000) -> List[Dict[str, Any]]:
        """
        Scan all S3 buckets in the AWS account and extract metadata.
        
        Args:
            max_buckets: Maximum number of buckets to scan (default 1000, prevents memory issues)
        
        Returns:
            List of S3 bucket data with tags and metadata
        """
        if not self.s3_client:
            return []
        
        # Use cache if available
        if self._s3_buckets_cache is not None:
            return self._s3_buckets_cache
        
        buckets = []
        
        try:
            # List all buckets
            response = self.s3_client.list_buckets()
            
            for bucket in response.get('Buckets', []):
                # Apply max limit (v0.9.1 guardrail)
                if len(buckets) >= max_buckets:
                    break
                bucket_name = bucket['Name']
                bucket_data = {
                    'name': bucket_name,
                    'creation_date': bucket.get('CreationDate')
                }
                
                # Get bucket region
                try:
                    location_response = self.s3_client.get_bucket_location(Bucket=bucket_name)
                    region = location_response.get('LocationConstraint') or 'us-east-1'
                    bucket_data['region'] = region
                except Exception:
                    bucket_data['region'] = 'unknown'
                
                # Get bucket tags
                try:
                    tag_response = self.s3_client.get_bucket_tagging(Bucket=bucket_name)
                    tags = {}
                    for tag in tag_response.get('TagSet', []):
                        tags[tag['Key']] = tag['Value']
                    
                    # Extract key metadata from tags
                    bucket_data['environment'] = tags.get('Environment')
                    bucket_data['data_class'] = tags.get('DataClass') or tags.get('Classification')
                    bucket_data['owner'] = tags.get('Owner')
                    bucket_data['tags'] = tags
                    
                except Exception as e:
                    # NoSuchTagSet or access denied - bucket has no tags
                    bucket_data['environment'] = None
                    bucket_data['data_class'] = None
                    bucket_data['owner'] = None
                    bucket_data['tags'] = {}
                
                buckets.append(bucket_data)
        
        except Exception as e:
            # If S3 listing fails, return empty list
            print(f"Warning: Failed to scan S3 buckets: {e}")
            return []
        
        # Cache the results
        self._s3_buckets_cache = buckets
        return buckets
    
    def map_role_to_s3_buckets(
        self, 
        role_arn: str, 
        s3_buckets: List[Dict[str, Any]],
        role_data: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Map an IAM role to S3 buckets it can access based on permissions.
        
        Args:
            role_arn: ARN of the IAM role
            s3_buckets: List of S3 buckets from scan_s3_buckets()
            role_data: Optional role data with policies (for permission analysis)
            
        Returns:
            List of S3 buckets with access level information
        """
        if not role_data:
            return []
        
        accessible_buckets = []
        
        # Analyze role's S3 permissions
        s3_permissions = self._extract_s3_permissions(role_data)
        
        if not s3_permissions['has_any_s3_access']:
            return []
        
        # Check each bucket
        for bucket in s3_buckets:
            bucket_name = bucket['name']
            
            # Check if role can access this bucket
            access_level = self._determine_s3_access_level(
                bucket_name, 
                s3_permissions
            )
            
            if access_level != 'none':
                accessible_bucket = bucket.copy()
                accessible_bucket['access_level'] = access_level
                accessible_buckets.append(accessible_bucket)
        
        return accessible_buckets
    
    def _extract_s3_permissions(self, role_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract S3-related permissions from role policies.
        
        Uses PolicyResolver if available for accurate permission checking
        (handles managed policies, Conditions, NotResource, etc.)
        Falls back to simple inline policy parsing otherwise.
        
        Args:
            role_data: IAM role data with policies
            
        Returns:
            Dict with S3 permission info
        """
        permissions = {
            'has_any_s3_access': False,
            'has_s3_wildcard': False,
            'resource_patterns': [],
            'actions': []
        }
        
        # If PolicyResolver available, use it for more accurate analysis
        if self.policy_resolver:
            return self._extract_s3_permissions_with_resolver(role_data)
        
        # Fallback: Simple inline policy parsing
        # Check inline policies
        for policy_name, policy_doc in role_data.get('inline_policies', {}).items():
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') != 'Allow':
                    continue
                
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                # Check for S3 actions
                s3_actions = [a for a in actions if a.startswith('s3:') or a == '*']
                if s3_actions:
                    permissions['has_any_s3_access'] = True
                    permissions['actions'].extend(s3_actions)
                    
                    # Check resources
                    resources = statement.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    
                    for resource in resources:
                        if resource == '*':
                            permissions['has_s3_wildcard'] = True
                        permissions['resource_patterns'].append(resource)
        
        return permissions
    
    def _extract_s3_permissions_with_resolver(self, role_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract S3 permissions using PolicyResolver for accurate analysis.
        
        This handles:
        - Managed policies
        - Policy conditions (StringLike, IpAddress, etc.)
        - NotResource exclusions
        - Permission boundaries
        
        Args:
            role_data: IAM role data with policies
            
        Returns:
            Dict with S3 permission info
        """
        permissions = {
            'has_any_s3_access': False,
            'has_s3_wildcard': False,
            'resource_patterns': [],
            'actions': []
        }
        
        role_arn = role_data.get('arn')
        if not role_arn:
            return permissions
        
        # Test common S3 actions using PolicyResolver
        test_actions = [
            's3:ListBucket',
            's3:GetObject', 
            's3:PutObject',
            's3:DeleteObject',
            's3:*'
        ]
        
        for action in test_actions:
            # Check if role has this permission (simplified check)
            # In real implementation, would check against specific bucket ARNs
            has_permission = self._check_s3_permission_via_resolver(
                role_data, 
                action
            )
            
            if has_permission:
                permissions['has_any_s3_access'] = True
                permissions['actions'].append(action)
                
                if action == 's3:*' or action == '*':
                    permissions['has_s3_wildcard'] = True
                    permissions['resource_patterns'].append('*')
        
        return permissions
    
    def _check_s3_permission_via_resolver(
        self, 
        role_data: Dict[str, Any], 
        action: str
    ) -> bool:
        """
        Check if role has a specific S3 permission using PolicyResolver.
        
        Args:
            role_data: IAM role data
            action: S3 action to check (e.g., 's3:GetObject')
            
        Returns:
            True if role has the permission
        """
        # Simple check: look through policies
        # TODO v0.8.1: Use PolicyResolver.check_permission() with proper context
        # For now, fallback to inline policy check
        for policy_name, policy_doc in role_data.get('inline_policies', {}).items():
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') != 'Allow':
                    continue
                
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                if action in actions or '*' in actions or 's3:*' in actions:
                    return True
        
        return False
    
    def _determine_s3_access_level(
        self, 
        bucket_name: str, 
        s3_permissions: Dict[str, Any]
    ) -> str:
        """
        Determine access level (full/write/read/none) for a specific bucket.
        
        Args:
            bucket_name: Name of the S3 bucket
            s3_permissions: S3 permissions from _extract_s3_permissions()
            
        Returns:
            Access level string: 'full', 'write', 'read', or 'none'
        """
        actions = s3_permissions['actions']
        resource_patterns = s3_permissions['resource_patterns']
        
        # Check if bucket matches resource patterns
        matches_resource = False
        if s3_permissions['has_s3_wildcard']:
            matches_resource = True
        else:
            for pattern in resource_patterns:
                # Simple wildcard matching
                if '*' in pattern:
                    # Extract bucket name from ARN pattern
                    # arn:aws:s3:::prod-*/* matches prod-data-bucket
                    bucket_pattern = pattern.replace('arn:aws:s3:::', '').split('/')[0]
                    if self._matches_pattern(bucket_name, bucket_pattern):
                        matches_resource = True
                        break
                elif bucket_name in pattern:
                    matches_resource = True
                    break
        
        if not matches_resource:
            return 'none'
        
        # Determine access level based on actions
        has_full = any(a in ['s3:*', '*'] for a in actions)
        has_write = any(a in ['s3:PutObject', 's3:DeleteObject'] or a.startswith('s3:Put') or a.startswith('s3:Delete') for a in actions)
        has_read = any(a in ['s3:GetObject', 's3:ListBucket'] or a.startswith('s3:Get') or a.startswith('s3:List') for a in actions)
        
        if has_full:
            return 'full'
        elif has_write:
            return 'write'
        elif has_read:
            return 'read'
        else:
            return 'none'
    
    def _matches_pattern(self, text: str, pattern: str) -> bool:
        """Simple wildcard pattern matching for bucket names"""
        if '*' not in pattern:
            return text == pattern
        
        # Convert wildcard to regex
        import re
        regex_pattern = pattern.replace('*', '.*')
        return bool(re.match(f'^{regex_pattern}$', text))
    
    def enrich_finding_with_s3(
        self, 
        finding: Dict[str, Any],
        role_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Add S3 bucket impact to a privilege escalation finding.
        
        Args:
            finding: Privilege escalation finding dict
            role_data: Role data dict with policies (required for mapping)
            
        Returns:
            Finding dict with S3 buckets in 'impacted_resources'
        """
        # Get target role ARN
        target_role_arn = finding.get('target_role_arn')
        if not target_role_arn or not role_data:
            return finding
        
        # Scan S3 buckets if not already cached
        if self._s3_buckets_cache is None:
            self.scan_s3_buckets()
        
        s3_buckets = self._s3_buckets_cache or []
        
        # Map role to accessible S3 buckets
        accessible_buckets = self.map_role_to_s3_buckets(
            target_role_arn,
            s3_buckets,
            role_data
        )
        
        if 'impacted_resources' not in finding:
            finding['impacted_resources'] = {}
        
        finding['impacted_resources']['s3_buckets'] = accessible_buckets
        
        # Update impact summary
        if accessible_buckets:
            s3_summary = self.generate_s3_impact_summary(accessible_buckets)
            
            existing_summary = finding.get('impact_summary', '')
            if existing_summary and 'No direct resource impact' not in existing_summary:
                finding['impact_summary'] = f"{existing_summary} + {s3_summary}"
            else:
                finding['impact_summary'] = s3_summary
        
        return finding
    
    def generate_s3_impact_summary(self, s3_buckets: List[Dict[str, Any]]) -> str:
        """
        Generate human-readable S3 impact summary.
        
        Args:
            s3_buckets: List of S3 buckets with access info
            
        Returns:
            Impact summary string
        """
        if not s3_buckets:
            return "No S3 bucket access"
        
        count = len(s3_buckets)
        
        # Count production buckets
        prod_count = sum(
            1 for b in s3_buckets
            if b.get('environment') and 'prod' in b['environment'].lower()
        )
        
        # Count sensitive buckets
        sensitive_count = sum(
            1 for b in s3_buckets
            if b.get('data_class') and b['data_class'] in ['Sensitive', 'PII', 'Financial', 'PHI']
        )
        
        parts = [f"{count} S3 bucket{'s' if count > 1 else ''}"]
        
        if prod_count > 0:
            parts.append(f"{prod_count} Production")
        
        if sensitive_count > 0:
            parts.append(f"{sensitive_count} Sensitive")
        
        return "Access to " + ", ".join(parts)
    
    # =========================================================================
    # RDS Database Analysis (v0.8.0 Phase 2)
    # =========================================================================
    
    def scan_rds_instances(self, max_instances: int = 1000) -> List[Dict[str, Any]]:
        """
        Scan all RDS database instances in the AWS account and extract metadata.
        
        Args:
            max_instances: Maximum number of instances to scan (default 1000)
        
        Returns:
            List of RDS instance data with tags and metadata
        """
        if not self.rds_client:
            return []
        
        # Use cache if available
        if self._rds_instances_cache is not None:
            return self._rds_instances_cache
        
        instances = []
        
        try:
            # List all RDS instances
            response = self.rds_client.describe_db_instances()
            
            for db_instance in response.get('DBInstances', []):
                # Apply max limit (v0.9.1 guardrail)
                if len(instances) >= max_instances:
                    break
                instance_data = {
                    'identifier': db_instance['DBInstanceIdentifier'],
                    'arn': db_instance.get('DBInstanceArn'),
                    'engine': db_instance.get('Engine'),
                    'engine_version': db_instance.get('EngineVersion'),
                    'instance_class': db_instance.get('DBInstanceClass'),
                    'status': db_instance.get('DBInstanceStatus'),
                    'multi_az': db_instance.get('MultiAZ', False),
                    'encrypted': db_instance.get('StorageEncrypted', False),
                    'publicly_accessible': db_instance.get('PubliclyAccessible', False)
                }
                
                # Get endpoint
                if 'Endpoint' in db_instance:
                    endpoint = db_instance['Endpoint']
                    address = endpoint.get('Address')
                    port = endpoint.get('Port')
                    instance_data['endpoint'] = f"{address}:{port}" if address and port else None
                else:
                    instance_data['endpoint'] = None
                
                # Parse tags
                tags = {}
                for tag in db_instance.get('TagList', []):
                    tags[tag['Key']] = tag['Value']
                
                # Extract key metadata from tags
                instance_data['environment'] = tags.get('Environment')
                instance_data['data_class'] = tags.get('DataClass') or tags.get('Classification')
                instance_data['owner'] = tags.get('Owner')
                instance_data['tags'] = tags
                
                instances.append(instance_data)
        
        except Exception as e:
            # If RDS listing fails, return empty list
            print(f"Warning: Failed to scan RDS instances: {e}")
            return []
        
        # Cache the results
        self._rds_instances_cache = instances
        return instances
    
    def map_role_to_rds_instances(
        self, 
        role_arn: str, 
        rds_instances: List[Dict[str, Any]],
        role_data: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Map an IAM role to RDS instances it can access based on permissions.
        
        Args:
            role_arn: ARN of the IAM role
            rds_instances: List of RDS instances from scan_rds_instances()
            role_data: Optional role data with policies (for permission analysis)
            
        Returns:
            List of RDS instances with access level information
        """
        if not role_data:
            return []
        
        accessible_instances = []
        
        # Analyze role's RDS permissions
        rds_permissions = self._extract_rds_permissions(role_data)
        
        if not rds_permissions['has_any_rds_access']:
            return []
        
        # Check each RDS instance
        for instance in rds_instances:
            instance_arn = instance.get('arn')
            instance_id = instance.get('identifier')
            
            if not instance_arn:
                continue
            
            # Check if role can access this instance
            access_level = self._determine_rds_access_level(
                instance_arn,
                instance_id,
                rds_permissions
            )
            
            if access_level != 'none':
                accessible_instance = instance.copy()
                accessible_instance['access_level'] = access_level
                accessible_instances.append(accessible_instance)
        
        return accessible_instances
    
    def _extract_rds_permissions(self, role_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract RDS-related permissions from role policies.
        
        Args:
            role_data: IAM role data with policies
            
        Returns:
            Dict with RDS permission info
        """
        permissions = {
            'has_any_rds_access': False,
            'has_rds_wildcard': False,
            'resource_patterns': [],
            'actions': []
        }
        
        # Check inline policies
        for policy_name, policy_doc in role_data.get('inline_policies', {}).items():
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') != 'Allow':
                    continue
                
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                # Check for RDS actions (rds:* or rds-db:*)
                rds_actions = [
                    a for a in actions 
                    if a.startswith('rds:') or a.startswith('rds-db:') or a == '*'
                ]
                
                if rds_actions:
                    permissions['has_any_rds_access'] = True
                    permissions['actions'].extend(rds_actions)
                    
                    # Check resources
                    resources = statement.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    
                    for resource in resources:
                        if resource == '*':
                            permissions['has_rds_wildcard'] = True
                        permissions['resource_patterns'].append(resource)
        
        return permissions
    
    def _determine_rds_access_level(
        self, 
        instance_arn: str,
        instance_id: str,
        rds_permissions: Dict[str, Any]
    ) -> str:
        """
        Determine access level (full/connect/none) for a specific RDS instance.
        
        Args:
            instance_arn: ARN of the RDS instance
            instance_id: Identifier of the RDS instance
            rds_permissions: RDS permissions from _extract_rds_permissions()
            
        Returns:
            Access level string: 'full', 'connect', or 'none'
        """
        actions = rds_permissions['actions']
        resource_patterns = rds_permissions['resource_patterns']
        
        # Check if instance matches resource patterns
        matches_resource = False
        if rds_permissions['has_rds_wildcard']:
            matches_resource = True
        else:
            for pattern in resource_patterns:
                # Check ARN patterns
                if '*' in pattern:
                    # Extract DB identifier pattern from ARN
                    # arn:aws:rds:*:*:db:prod-* matches prod-mysql-01
                    if ':db:' in pattern:
                        db_pattern = pattern.split(':db:')[-1]
                        if self._matches_pattern(instance_id, db_pattern):
                            matches_resource = True
                            break
                elif instance_arn in pattern or instance_id in pattern:
                    matches_resource = True
                    break
        
        if not matches_resource:
            return 'none'
        
        # Determine access level based on actions
        has_full = any(a in ['rds:*', '*'] for a in actions)
        has_connect = any(a == 'rds-db:connect' or a.startswith('rds-db:') for a in actions)
        
        if has_full:
            return 'full'
        elif has_connect:
            return 'connect'
        else:
            return 'none'
    
    def enrich_finding_with_rds(
        self, 
        finding: Dict[str, Any],
        role_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Add RDS database impact to a privilege escalation finding.
        
        Args:
            finding: Privilege escalation finding dict
            role_data: Role data dict with policies (required for mapping)
            
        Returns:
            Finding dict with RDS instances in 'impacted_resources'
        """
        # Get target role ARN
        target_role_arn = finding.get('target_role_arn')
        if not target_role_arn or not role_data:
            return finding
        
        # Scan RDS instances if not already cached
        if self._rds_instances_cache is None:
            self.scan_rds_instances()
        
        rds_instances = self._rds_instances_cache or []
        
        # Map role to accessible RDS instances
        accessible_instances = self.map_role_to_rds_instances(
            target_role_arn,
            rds_instances,
            role_data
        )
        
        if 'impacted_resources' not in finding:
            finding['impacted_resources'] = {}
        
        finding['impacted_resources']['rds_instances'] = accessible_instances
        
        # Update impact summary
        if accessible_instances:
            rds_summary = self.generate_rds_impact_summary(accessible_instances)
            
            existing_summary = finding.get('impact_summary', '')
            if existing_summary and 'No direct resource impact' not in existing_summary:
                finding['impact_summary'] = f"{existing_summary} + {rds_summary}"
            else:
                finding['impact_summary'] = rds_summary
        
        return finding
    
    def generate_rds_impact_summary(self, rds_instances: List[Dict[str, Any]]) -> str:
        """
        Generate human-readable RDS impact summary.
        
        Args:
            rds_instances: List of RDS instances with access info
            
        Returns:
            Impact summary string
        """
        if not rds_instances:
            return "No RDS database access"
        
        count = len(rds_instances)
        
        # Count production databases
        prod_count = sum(
            1 for db in rds_instances
            if db.get('environment') and 'prod' in db['environment'].lower()
        )
        
        # Count sensitive databases
        sensitive_count = sum(
            1 for db in rds_instances
            if db.get('data_class') and db['data_class'] in ['Sensitive', 'PII', 'Financial', 'PHI']
        )
        
        # Count by engine
        engines = {}
        for db in rds_instances:
            engine = db.get('engine', 'unknown')
            engines[engine] = engines.get(engine, 0) + 1
        
        parts = [f"{count} database{'s' if count > 1 else ''}"]
        
        if prod_count > 0:
            parts.append(f"{prod_count} Production")
        
        if sensitive_count > 0:
            parts.append(f"{sensitive_count} Sensitive")
        
        # Add engine types
        engine_strs = [f"{count} {engine.upper()}" for engine, count in engines.items()]
        if engine_strs:
            parts.append(", ".join(engine_strs))
        
        return "Access to " + ", ".join(parts)
    
    #
    # === SECRETS MANAGER RESOURCE CONTEXT (v0.8.1) ===
    #
    
    def scan_secrets(self, max_secrets: int = 1000) -> List[Dict[str, Any]]:
        """
        Scan Secrets Manager for all secrets.
        
        Args:
            max_secrets: Maximum number of secrets to scan (default 1000)
        
        Returns:
            List of secret metadata with environment and type detection
        """
        if not self.secrets_client:
            return []
        
        secrets = []
        try:
            response = self.secrets_client.list_secrets()
            
            for secret in response.get('SecretList', []):
                # Apply max limit (v0.9.1 guardrail)
                if len(secrets) >= max_secrets:
                    break
                # Extract tags
                tags_dict = {tag['Key']: tag['Value'] for tag in secret.get('Tags', [])}
                
                # Detect environment (support multiple tag key variations)
                environment = (
                    tags_dict.get('Environment') or 
                    tags_dict.get('environment') or
                    tags_dict.get('env') or
                    tags_dict.get('Env') or
                    ''
                )
                
                # Detect data classification
                data_class = (
                    tags_dict.get('DataClass') or
                    tags_dict.get('data_class') or
                    tags_dict.get('Classification') or
                    ''
                )
                
                # Detect secret type from tags or name
                secret_type = tags_dict.get('Type') or tags_dict.get('type')
                if not secret_type:
                    # Infer from name
                    name_lower = secret.get('Name', '').lower()
                    if any(x in name_lower for x in ['password', 'passwd', 'pwd']):
                        secret_type = 'DB_PASSWORD'
                    elif any(x in name_lower for x in ['api-key', 'apikey', 'api_key']):
                        secret_type = 'API_KEY'
                    elif 'token' in name_lower:
                        secret_type = 'TOKEN'
                    elif any(x in name_lower for x in ['connection', 'conn', 'database-url', 'db-url']):
                        secret_type = 'DB_CONNECTION'
                    else:
                        secret_type = 'GENERIC'
                
                secrets.append({
                    'arn': secret.get('ARN', ''),
                    'name': secret.get('Name', ''),
                    'description': secret.get('Description', ''),
                    'environment': environment,
                    'data_class': data_class,
                    'secret_type': secret_type,
                    'tags': tags_dict
                })
        
        except Exception as e:
            # Log error but don't fail the entire scan
            print(f"Warning: Failed to scan Secrets Manager: {e}")
        
        return secrets
    
    def _check_secrets_permission_via_resolver(
        self,
        role_data: Dict[str, Any],
        action: str,
        resource_arn: str
    ) -> bool:
        """
        Check if role has specific Secrets Manager permission.
        
        Args:
            role_data: IAM role data
            action: Secrets Manager action (e.g., 'secretsmanager:GetSecretValue')
            resource_arn: Secret ARN
        
        Returns:
            True if role has the permission
        """
        import fnmatch
        
        # Check through inline policies
        for policy_name, policy_doc in role_data.get('inline_policies', {}).items():
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') != 'Allow':
                    continue
                
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                # Check if action matches
                if action in actions or '*' in actions or 'secretsmanager:*' in actions:
                    # Check if resource matches
                    resources = statement.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    
                    for resource_pattern in resources:
                        if resource_pattern == '*':
                            return True
                        # Use fnmatch for wildcard matching
                        if fnmatch.fnmatch(resource_arn, resource_pattern):
                            return True
        
        return False
    
    def map_role_to_secrets(
        self,
        role_arn: str,
        secrets: List[Dict[str, Any]],
        role_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Map role permissions to Secrets Manager secrets.
        
        Args:
            role_arn: ARN of the role
            secrets: List of secrets from scan_secrets()
            role_data: Full role data with policies
        
        Returns:
            List of secrets the role can access with permission details
        """
        accessible_secrets = []
        
        for secret in secrets:
            secret_arn = secret['arn']
            permissions = []
            
            # Check secretsmanager:GetSecretValue
            if self._check_secrets_permission_via_resolver(role_data, 'secretsmanager:GetSecretValue', secret_arn):
                permissions.append('GetSecretValue')
            
            # Check secretsmanager:DescribeSecret
            if self._check_secrets_permission_via_resolver(role_data, 'secretsmanager:DescribeSecret', secret_arn):
                permissions.append('DescribeSecret')
            
            # If role has any permissions on this secret, add to accessible list
            if permissions:
                accessible_secrets.append({
                    **secret,
                    'access_level': 'read',  # Secrets are read-only
                    'permissions': permissions
                })
        
        return accessible_secrets
    
    def enrich_finding_with_secrets(
        self,
        finding: Dict[str, Any],
        role_data: Dict[str, Any],
        secrets: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Enrich a privesc finding with Secrets Manager impact data.
        
        Args:
            finding: The finding to enrich
            role_data: Role data for the finding's principal
            secrets: List of secrets from scan_secrets()
        
        Returns:
            Enriched finding with 'impacted_resources' -> 'secrets'
        """
        # Map role to secrets
        accessible_secrets = self.map_role_to_secrets(
            role_data['arn'],
            secrets,
            role_data
        )
        
        # Add to finding
        if 'impacted_resources' not in finding:
            finding['impacted_resources'] = {}
        
        finding['impacted_resources']['secrets'] = accessible_secrets
        
        return finding
    
    def generate_secrets_impact_summary(self, secrets: List[Dict[str, Any]]) -> str:
        """
        Generate human-readable summary of Secrets Manager impact.
        
        Args:
            secrets: List of accessible secrets
        
        Returns:
            Human-readable impact string
        """
        if not secrets:
            return ""
        
        count = len(secrets)
        
        # Count production secrets
        prod_count = sum(
            1 for s in secrets
            if s.get('environment') and 'prod' in s['environment'].lower()
        )
        
        # Count sensitive secrets
        sensitive_count = sum(
            1 for s in secrets
            if s.get('data_class') and s['data_class'] in ['Sensitive', 'PII', 'Financial', 'PHI']
        )
        
        # Count by type
        types = {}
        for s in secrets:
            secret_type = s.get('secret_type', 'GENERIC')
            types[secret_type] = types.get(secret_type, 0) + 1
        
        parts = [f"{count} secret{'s' if count > 1 else ''}"]
        
        if prod_count > 0:
            parts.append(f"{prod_count} Production")
        
        if sensitive_count > 0:
            parts.append(f"{sensitive_count} Sensitive")
        
        # Add type breakdown
        type_labels = {
            'DB_PASSWORD': 'DB password',
            'API_KEY': 'API key',
            'TOKEN': 'token',
            'DB_CONNECTION': 'DB connection',
            'GENERIC': 'config'
        }
        
        type_strs = []
        for secret_type, count in types.items():
            label = type_labels.get(secret_type, secret_type.lower())
            plural = 's' if count > 1 else ''
            type_strs.append(f"{count} {label}{plural}")
        
        if type_strs:
            parts.append(", ".join(type_strs))
        
        return "Access to " + ", ".join(parts)
    
    #
    # === SSM PARAMETER STORE RESOURCE CONTEXT (v0.8.1) ===
    #
    
    def scan_ssm_parameters(self, max_parameters: int = 1000) -> List[Dict[str, Any]]:
        """
        Scan SSM Parameter Store for all parameters.
        
        Args:
            max_parameters: Maximum number of parameters to scan (default 1000)
        
        Returns:
            List of parameter metadata with environment and type detection
        """
        if not hasattr(self, 'ssm_client') or not self.ssm_client:
            return []
        
        parameters = []
        try:
            # Try paginator first (real AWS client), fall back to direct call (mock)
            try:
                paginator = self.ssm_client.get_paginator('describe_parameters')
                pages = paginator.paginate()
            except AttributeError:
                # Mock client without paginator - call describe_parameters directly
                pages = [self.ssm_client.describe_parameters()]
            
            for page in pages:
                for param in page.get('Parameters', []):
                    # Apply max limit (v0.9.1 guardrail)
                    if len(parameters) >= max_parameters:
                        break
                    param_name = param.get('Name', '')
                    
                    # Get tags for this parameter
                    try:
                        tags_response = self.ssm_client.list_tags_for_resource(
                            ResourceType='Parameter',
                            ResourceId=param.get('ARN', '')
                        )
                        tags_list = tags_response.get('TagList', [])
                        tags_dict = {tag['Key']: tag['Value'] for tag in tags_list}
                    except:
                        tags_dict = {}
                    
                    # Detect environment
                    environment = (
                        tags_dict.get('Environment') or
                        tags_dict.get('environment') or
                        tags_dict.get('env') or
                        tags_dict.get('Env') or
                        ''
                    )
                    
                    # Detect data classification
                    data_class = (
                        tags_dict.get('DataClass') or
                        tags_dict.get('data_class') or
                        tags_dict.get('Classification') or
                        ''
                    )
                    
                    # Detect parameter type from tags or name
                    parameter_type = tags_dict.get('Type') or tags_dict.get('type')
                    if not parameter_type:
                        # Infer from name
                        name_lower = param_name.lower()
                        if any(x in name_lower for x in ['password', 'passwd', 'pwd', 'secret']):
                            parameter_type = 'DB_CREDENTIAL'
                        elif any(x in name_lower for x in ['api-key', 'apikey', 'api_key']):
                            parameter_type = 'API_KEY'
                        elif 'token' in name_lower:
                            parameter_type = 'TOKEN'
                        elif any(x in name_lower for x in ['db/', '/db/', 'database', 'rds']):
                            parameter_type = 'DB_CONFIG'
                        elif any(x in name_lower for x in ['config', 'setting']):
                            parameter_type = 'CONFIG'
                        else:
                            parameter_type = 'GENERIC'
                    
                    parameters.append({
                        'arn': param.get('ARN', ''),
                        'name': param_name,
                        'type': param.get('Type', 'String'),  # String, StringList, SecureString
                        'tier': param.get('Tier', 'Standard'),  # Standard or Advanced
                        'description': param.get('Description', ''),
                        'environment': environment,
                        'data_class': data_class,
                        'parameter_type': parameter_type,
                        'tags': tags_dict
                    })
        
        except Exception as e:
            # Log error but don't fail the entire scan
            print(f"Warning: Failed to scan SSM Parameter Store: {e}")
        
        return parameters
    
    def _check_ssm_permission_via_resolver(
        self,
        role_data: Dict[str, Any],
        action: str,
        resource_arn: str
    ) -> bool:
        """
        Check if role has specific SSM permission.
        
        Args:
            role_data: IAM role data
            action: SSM action (e.g., 'ssm:GetParameter')
            resource_arn: Parameter ARN
        
        Returns:
            True if role has the permission
        """
        import fnmatch
        
        # Check through inline policies
        for policy_name, policy_doc in role_data.get('inline_policies', {}).items():
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') != 'Allow':
                    continue
                
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                # Check if action matches
                if action in actions or '*' in actions or 'ssm:*' in actions:
                    # Check if resource matches
                    resources = statement.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    
                    for resource_pattern in resources:
                        if resource_pattern == '*':
                            return True
                        # Use fnmatch for wildcard matching
                        if fnmatch.fnmatch(resource_arn, resource_pattern):
                            return True
        
        return False
    
    def map_role_to_ssm(
        self,
        role_arn: str,
        parameters: List[Dict[str, Any]],
        role_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Map role permissions to SSM parameters.
        
        Args:
            role_arn: ARN of the role
            parameters: List of parameters from scan_ssm_parameters()
            role_data: Full role data with policies
        
        Returns:
            List of parameters the role can access with permission details
        """
        accessible_parameters = []
        
        for param in parameters:
            param_arn = param['arn']
            permissions = []
            
            # Check ssm:GetParameter
            if self._check_ssm_permission_via_resolver(role_data, 'ssm:GetParameter', param_arn):
                permissions.append('GetParameter')
            
            # Check ssm:GetParameters
            if self._check_ssm_permission_via_resolver(role_data, 'ssm:GetParameters', param_arn):
                permissions.append('GetParameters')
            
            # Check ssm:DescribeParameters
            if self._check_ssm_permission_via_resolver(role_data, 'ssm:DescribeParameters', param_arn):
                permissions.append('DescribeParameters')
            
            # If role has any permissions on this parameter, add to accessible list
            if permissions:
                accessible_parameters.append({
                    **param,
                    'access_level': 'read',  # SSM parameters are read-only
                    'permissions': permissions
                })
        
        return accessible_parameters
    
    def enrich_finding_with_ssm(
        self,
        finding: Dict[str, Any],
        role_data: Dict[str, Any],
        parameters: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Enrich a privesc finding with SSM Parameter Store impact data.
        
        Args:
            finding: The finding to enrich
            role_data: Role data for the finding's principal
            parameters: List of parameters from scan_ssm_parameters()
        
        Returns:
            Enriched finding with 'impacted_resources' -> 'ssm_parameters'
        """
        # Map role to parameters
        accessible_parameters = self.map_role_to_ssm(
            role_data['arn'],
            parameters,
            role_data
        )
        
        # Add to finding
        if 'impacted_resources' not in finding:
            finding['impacted_resources'] = {}
        
        finding['impacted_resources']['ssm_parameters'] = accessible_parameters
        
        return finding
    
    def generate_ssm_impact_summary(self, parameters: List[Dict[str, Any]]) -> str:
        """
        Generate human-readable summary of SSM Parameter Store impact.
        
        Args:
            parameters: List of accessible parameters
        
        Returns:
            Human-readable impact string
        """
        if not parameters:
            return ""
        
        count = len(parameters)
        
        # Count production parameters
        prod_count = sum(
            1 for p in parameters
            if p.get('environment') and 'prod' in p['environment'].lower()
        )
        
        # Count sensitive parameters
        sensitive_count = sum(
            1 for p in parameters
            if p.get('data_class') and p['data_class'] in ['Sensitive', 'PII', 'Financial', 'PHI']
        )
        
        # Count by type
        types = {}
        for p in parameters:
            param_type = p.get('parameter_type', 'GENERIC')
            types[param_type] = types.get(param_type, 0) + 1
        
        parts = [f"{count} parameter{'s' if count > 1 else ''}"]
        
        if prod_count > 0:
            parts.append(f"{prod_count} Production")
        
        if sensitive_count > 0:
            parts.append(f"{sensitive_count} Sensitive")
        
        # Add type breakdown
        type_labels = {
            'DB_CREDENTIAL': 'DB credential',
            'DB_CONFIG': 'DB config',
            'API_KEY': 'API key',
            'TOKEN': 'token',
            'CONFIG': 'config',
            'GENERIC': 'setting'
        }
        
        type_strs = []
        for param_type, count in types.items():
            label = type_labels.get(param_type, param_type.lower())
            plural = 's' if count > 1 else ''
            type_strs.append(f"{count} {label}{plural}")
        
        if type_strs:
            parts.append(", ".join(type_strs))
        
        return "Access to " + ", ".join(parts)
