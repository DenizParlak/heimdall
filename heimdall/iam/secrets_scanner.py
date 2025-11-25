"""
Secrets Manager and SSM Parameter Store Scanner

Discovers sensitive secrets and parameters accessible to IAM principals
to show real impact of privilege escalation paths.

Author: Heimdall Security
Version: v1.2.0
"""

import re
from typing import Dict, List, Optional, Set, Any

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    # Allow import for testing without boto3
    boto3 = None  # type: ignore
    ClientError = Exception


class SecretsScanner:
    """
    Scanner for AWS Secrets Manager and SSM Parameter Store
    
    Discovers:
    - Secrets Manager secrets
    - SSM Parameter Store parameters
    - High-value detection via naming patterns and tags
    """
    
    # Patterns indicating high-value secrets
    HIGH_VALUE_PATTERNS = [
        r'prod',
        r'production',
        r'api[_-]?key',
        r'password',
        r'passwd',
        r'token',
        r'secret',
        r'credential',
        r'auth',
        r'private[_-]?key',
        r'db',
        r'database',
        r'stripe',
        r'oauth',
        r'jwt',
        r'certificate',
        r'cert',
    ]
    
    # Tags indicating high value
    HIGH_VALUE_TAGS = {
        'Environment': ['production', 'prod', 'live'],
        'Sensitivity': ['high', 'critical', 'confidential'],
        'Type': ['credential', 'api-key', 'database'],
    }
    
    def __init__(self, session: Any, region: str = 'us-east-1'):
        """
        Initialize scanner
        
        Args:
            session: Boto3 session
            region: AWS region to scan
        """
        self.session = session
        self.region = region
        self.secrets_client = session.client('secretsmanager', region_name=region)
        self.ssm_client = session.client('ssm', region_name=region)
        
    def scan(self) -> Dict[str, any]:
        """
        Scan both Secrets Manager and SSM Parameter Store
        
        Returns:
            Dictionary with secrets and parameters data
        """
        print(f"🔐 Scanning secrets in {self.region}...")
        
        secrets = self._scan_secrets_manager()
        parameters = self._scan_ssm_parameters()
        
        # Statistics
        total_secrets = len(secrets)
        high_value_secrets = sum(1 for s in secrets if s['high_value'])
        total_params = len(parameters)
        high_value_params = sum(1 for p in parameters if p['high_value'])
        
        print(f"✅ Found {total_secrets} secrets ({high_value_secrets} high-value)")
        print(f"✅ Found {total_params} parameters ({high_value_params} high-value)")
        
        return {
            'secrets': secrets,
            'parameters': parameters,
            'statistics': {
                'total_secrets': total_secrets,
                'high_value_secrets': high_value_secrets,
                'total_parameters': total_params,
                'high_value_parameters': high_value_params,
                'region': self.region
            }
        }
    
    def _scan_secrets_manager(self) -> List[Dict]:
        """
        Scan Secrets Manager for all secrets
        
        Returns:
            List of secret metadata dicts
        """
        secrets = []
        
        try:
            # Paginate through all secrets
            paginator = self.secrets_client.get_paginator('list_secrets')
            
            for page in paginator.paginate():
                for secret in page.get('SecretList', []):
                    try:
                        # Get detailed metadata
                        secret_arn = secret['ARN']
                        secret_name = secret['Name']
                        
                        # Describe for full details
                        details = self.secrets_client.describe_secret(SecretId=secret_arn)
                        
                        # Extract metadata
                        secret_data = {
                            'arn': secret_arn,
                            'name': secret_name,
                            'description': details.get('Description', ''),
                            'kms_key_id': details.get('KmsKeyId'),
                            'rotation_enabled': details.get('RotationEnabled', False),
                            'last_accessed': details.get('LastAccessedDate'),
                            'created_date': details.get('CreatedDate'),
                            'tags': self._parse_tags(details.get('Tags', [])),
                            'version_stages': details.get('VersionIdsToStages', {}),
                        }
                        
                        # High-value detection
                        secret_data['high_value'] = self._is_high_value_secret(secret_data)
                        secret_data['value_indicators'] = self._get_value_indicators(secret_name)
                        
                        secrets.append(secret_data)
                        
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'AccessDeniedException':
                            print(f"⚠️  Access denied to secret: {secret.get('Name', 'unknown')}")
                        else:
                            print(f"⚠️  Error describing secret {secret.get('Name')}: {e}")
                        continue
                        
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                print(f"⚠️  Access denied to Secrets Manager in {self.region}")
            else:
                print(f"❌ Error scanning Secrets Manager: {e}")
        
        return secrets
    
    def _scan_ssm_parameters(self) -> List[Dict]:
        """
        Scan SSM Parameter Store for parameters
        
        Returns:
            List of parameter metadata dicts
        """
        parameters = []
        
        try:
            # Paginate through all parameters
            paginator = self.ssm_client.get_paginator('describe_parameters')
            
            for page in paginator.paginate():
                for param in page.get('Parameters', []):
                    try:
                        param_name = param['Name']
                        
                        # Extract metadata
                        param_data = {
                            'name': param_name,
                            'type': param.get('Type'),  # String, StringList, SecureString
                            'description': param.get('Description', ''),
                            'key_id': param.get('KeyId'),  # KMS key for SecureString
                            'last_modified': param.get('LastModifiedDate'),
                            'version': param.get('Version'),
                            'tier': param.get('Tier', 'Standard'),
                            'tags': {},  # SSM tags require separate API call
                        }
                        
                        # Try to get tags (may fail due to permissions)
                        try:
                            tags_response = self.ssm_client.list_tags_for_resource(
                                ResourceType='Parameter',
                                ResourceId=param_name
                            )
                            param_data['tags'] = self._parse_tags(tags_response.get('TagList', []))
                        except ClientError:
                            pass  # Tags not accessible, continue
                        
                        # High-value detection
                        param_data['high_value'] = self._is_high_value_parameter(param_data)
                        param_data['value_indicators'] = self._get_value_indicators(param_name)
                        
                        parameters.append(param_data)
                        
                    except ClientError as e:
                        print(f"⚠️  Error describing parameter {param.get('Name')}: {e}")
                        continue
                        
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                print(f"⚠️  Access denied to SSM Parameter Store in {self.region}")
            else:
                print(f"❌ Error scanning SSM Parameter Store: {e}")
        
        return parameters
    
    def _is_high_value_secret(self, secret: Dict) -> bool:
        """
        Detect if secret is high-value based on name, tags, and attributes
        
        Args:
            secret: Secret metadata dict
            
        Returns:
            True if high-value
        """
        # Check name patterns
        name_lower = secret['name'].lower()
        for pattern in self.HIGH_VALUE_PATTERNS:
            if re.search(pattern, name_lower):
                return True
        
        # Check tags
        for tag_key, tag_values in self.HIGH_VALUE_TAGS.items():
            if tag_key in secret['tags']:
                tag_value = secret['tags'][tag_key].lower()
                if any(val in tag_value for val in tag_values):
                    return True
        
        # KMS-encrypted secrets are often high-value
        if secret.get('kms_key_id'):
            return True
        
        # Rotation enabled suggests importance
        if secret.get('rotation_enabled'):
            return True
        
        return False
    
    def _is_high_value_parameter(self, param: Dict) -> bool:
        """
        Detect if parameter is high-value
        
        Args:
            param: Parameter metadata dict
            
        Returns:
            True if high-value
        """
        # Check name patterns
        name_lower = param['name'].lower()
        for pattern in self.HIGH_VALUE_PATTERNS:
            if re.search(pattern, name_lower):
                return True
        
        # Check tags
        for tag_key, tag_values in self.HIGH_VALUE_TAGS.items():
            if tag_key in param['tags']:
                tag_value = param['tags'][tag_key].lower()
                if any(val in tag_value for val in tag_values):
                    return True
        
        # SecureString type with KMS indicates high value
        if param.get('type') == 'SecureString' and param.get('key_id'):
            return True
        
        return False
    
    def _get_value_indicators(self, name: str) -> List[str]:
        """
        Extract value indicators from secret/parameter name
        
        Args:
            name: Secret or parameter name
            
        Returns:
            List of matched patterns
        """
        indicators = []
        name_lower = name.lower()
        
        for pattern in self.HIGH_VALUE_PATTERNS:
            if re.search(pattern, name_lower):
                # Extract the actual matched word
                match = re.search(pattern, name_lower)
                if match:
                    indicators.append(match.group(0))
        
        return list(set(indicators))  # Deduplicate
    
    def _parse_tags(self, tags: List[Dict]) -> Dict[str, str]:
        """
        Parse AWS tags list to dict
        
        Args:
            tags: List of {Key, Value} dicts
            
        Returns:
            Dict of tag key-value pairs
        """
        return {tag['Key']: tag['Value'] for tag in tags if 'Key' in tag and 'Value' in tag}
