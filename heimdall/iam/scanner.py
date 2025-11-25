"""
IAM Scanner - Scans AWS IAM resources and extracts trust relationships.

This module provides the IAMScanner class for comprehensive AWS IAM analysis,
including roles, users, policies, and their interconnections.

Typical usage:
    scanner = IAMScanner(profile_name='production')
    roles = scanner.scan_roles()
    users = scanner.scan_users()
"""

import logging
from typing import List, Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

# Configure module logger
logger = logging.getLogger(__name__)

# Constants
DEFAULT_REGION = 'us-east-1'
MAX_RETRIES = 3  # Reserved for future retry logic implementation
PAGINATION_PAGE_SIZE = 100  # AWS IAM pagination (currently using boto3 defaults)


class IAMScanner:
    """Scans AWS IAM resources and extracts assume-role relationships"""
    
    def __init__(self, profile_name: str = 'default', region_name: str = None):
        """
        Initialize IAM scanner with AWS credentials
        
        Args:
            profile_name: AWS profile name from ~/.aws/credentials
            region_name: AWS region (optional, uses profile default)
        """
        # Configure retry strategy
        boto_config = Config(
            retries={'max_attempts': MAX_RETRIES, 'mode': 'standard'}
        )
        
        # If profile is 'default' and no AWS config exists, use environment variables
        import os
        if profile_name == 'default' and not os.path.exists(os.path.expanduser('~/.aws/config')):
            # Use environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
            self.session = boto3.Session(region_name=region_name or DEFAULT_REGION)
        else:
            self.session = boto3.Session(
                profile_name=profile_name,
                region_name=region_name
            )
        
        # Auto-detect region if not provided
        if region_name is None:
            # Try to get region from session/profile config
            region_name = self.session.region_name
            # If still None, use default region
            if region_name is None:
                region_name = DEFAULT_REGION
                logger.info("No region specified, using default: %s", DEFAULT_REGION)
            
        self.iam = self.session.client('iam', config=boto_config)
        self.sts = self.session.client('sts', config=boto_config)
        self.ec2 = self.session.client('ec2', region_name=region_name, config=boto_config)
        self.lambda_client = self.session.client('lambda', region_name=region_name, config=boto_config)
        
        # Get account ID
        try:
            self.account_id = self.sts.get_caller_identity()['Account']
        except ClientError as e:
            logger.critical("Failed to get AWS account ID: %s", e)
            raise RuntimeError(f"AWS authentication failed: {e}")
        except Exception as e:
            logger.critical("Unexpected error getting account ID: %s", e, exc_info=True)
            raise RuntimeError(f"Failed to get AWS account ID: {e}")
    
    def scan_roles(self) -> List[Dict[str, Any]]:
        """
        Scan all IAM roles in the account
        
        Returns:
            List of role data including trust policies
        """
        roles = []
        
        try:
            paginator = self.iam.get_paginator('list_roles')
            pagination_config = {'PageSize': PAGINATION_PAGE_SIZE}
            
            for page in paginator.paginate(PaginationConfig=pagination_config):
                for role in page['Roles']:
                    role_data = {
                        'type': 'role',
                        'arn': role['Arn'],
                        'name': role['RoleName'],
                        'path': role['Path'],
                        'trust_policy': role['AssumeRolePolicyDocument'],
                        'max_session_duration': role.get('MaxSessionDuration'),
                        'created': role['CreateDate'].isoformat(),
                    }
                    
                    # Get attached managed policies (with documents for full accuracy)
                    try:
                        attached_policies = self.iam.list_attached_role_policies(
                            RoleName=role['RoleName']
                        )
                        role_data['attached_policies'] = []
                        
                        for p in attached_policies.get('AttachedPolicies', []):
                            policy_info = {
                                'PolicyName': p['PolicyName'],
                                'PolicyArn': p['PolicyArn']
                            }
                            
                            # Fetch policy document for complete permission analysis
                            try:
                                policy_arn = p['PolicyArn']
                                
                                # Get policy version
                                policy = self.iam.get_policy(PolicyArn=policy_arn)
                                default_version_id = policy['Policy']['DefaultVersionId']
                                
                                # Get policy document
                                policy_version = self.iam.get_policy_version(
                                    PolicyArn=policy_arn,
                                    VersionId=default_version_id
                                )
                                policy_info['PolicyDocument'] = policy_version['PolicyVersion']['Document']
                            except ClientError as e:
                                logger.warning("Failed to fetch policy document for %s: %s", p['PolicyArn'], e)
                                policy_info['PolicyDocument'] = None
                            except Exception as e:
                                logger.debug("Unexpected error fetching policy %s: %s", p['PolicyArn'], e)
                                policy_info['PolicyDocument'] = None
                            
                            role_data['attached_policies'].append(policy_info)
                    except ClientError as e:
                        logger.error("Failed to list attached policies for role %s: %s", role['RoleName'], e)
                        role_data['attached_policies'] = []
                    except Exception as e:
                        logger.error("Unexpected error listing policies for role %s: %s", role['RoleName'], e, exc_info=True)
                        role_data['attached_policies'] = []
                    
                    # Get inline policies (with documents for Phase 2A-1)
                    try:
                        policy_names = self.iam.list_role_policies(
                            RoleName=role['RoleName']
                        ).get('PolicyNames', [])
                        
                        inline_policies = {}
                        for policy_name in policy_names:
                            try:
                                policy_doc = self.iam.get_role_policy(
                                    RoleName=role['RoleName'],
                                    PolicyName=policy_name
                                )
                                inline_policies[policy_name] = policy_doc.get('PolicyDocument', {})
                            except ClientError as e:
                                logger.warning("Failed to fetch inline policy %s for role %s: %s", policy_name, role['RoleName'], e)
                            except Exception as e:
                                logger.debug("Unexpected error fetching inline policy %s: %s", policy_name, e)
                        
                        role_data['inline_policies'] = inline_policies
                    except ClientError as e:
                        logger.error("Failed to list inline policies for role %s: %s", role['RoleName'], e)
                        role_data['inline_policies'] = {}
                    except Exception as e:
                        logger.error("Unexpected error processing inline policies for %s: %s", role['RoleName'], e, exc_info=True)
                        role_data['inline_policies'] = {}
                    
                    roles.append(role_data)
        
        except ClientError as e:
            logger.critical("AWS API error scanning roles: %s", e)
            raise RuntimeError(f"Failed to scan IAM roles: {e}")
        except Exception as e:
            logger.critical("Fatal error scanning IAM roles: %s", e, exc_info=True)
            raise RuntimeError(f"Failed to scan IAM roles: {e}")
        
        return roles
    
    def scan_users(self) -> List[Dict[str, Any]]:
        """
        Scan all IAM users in the account
        
        Returns:
            List of user data
        """
        users = []
        
        try:
            paginator = self.iam.get_paginator('list_users')
            pagination_config = {'PageSize': PAGINATION_PAGE_SIZE}
            
            for page in paginator.paginate(PaginationConfig=pagination_config):
                for user in page['Users']:
                    user_data = {
                        'type': 'user',
                        'arn': user['Arn'],
                        'name': user['UserName'],
                        'path': user['Path'],
                        'created': user['CreateDate'].isoformat(),
                    }
                    
                    # Get attached managed policies (with documents for full accuracy)
                    try:
                        attached_policies = self.iam.list_attached_user_policies(
                            UserName=user['UserName']
                        )
                        user_data['attached_policies'] = []
                        
                        for p in attached_policies.get('AttachedPolicies', []):
                            policy_info = {
                                'PolicyName': p['PolicyName'],
                                'PolicyArn': p['PolicyArn']
                            }
                            
                            # Fetch policy document for complete permission analysis
                            try:
                                policy_arn = p['PolicyArn']
                                
                                # Get policy version
                                policy = self.iam.get_policy(PolicyArn=policy_arn)
                                default_version_id = policy['Policy']['DefaultVersionId']
                                
                                # Get policy document
                                policy_version = self.iam.get_policy_version(
                                    PolicyArn=policy_arn,
                                    VersionId=default_version_id
                                )
                                policy_info['PolicyDocument'] = policy_version['PolicyVersion']['Document']
                            except ClientError as e:
                                logger.warning("Failed to fetch policy document for %s: %s", p['PolicyArn'], e)
                                policy_info['PolicyDocument'] = None
                            except Exception as e:
                                logger.debug("Unexpected error fetching policy %s: %s", p['PolicyArn'], e)
                                policy_info['PolicyDocument'] = None
                            
                            user_data['attached_policies'].append(policy_info)
                    except ClientError as e:
                        logger.error("Failed to list attached policies for user %s: %s", user['UserName'], e)
                        user_data['attached_policies'] = []
                    except Exception as e:
                        logger.error("Unexpected error listing policies for user %s: %s", user['UserName'], e, exc_info=True)
                        user_data['attached_policies'] = []
                    
                    # Get inline policies (with documents for Phase 2A-1)
                    try:
                        policy_names = self.iam.list_user_policies(
                            UserName=user['UserName']
                        ).get('PolicyNames', [])
                        
                        inline_policies = {}
                        for policy_name in policy_names:
                            try:
                                policy_doc = self.iam.get_user_policy(
                                    UserName=user['UserName'],
                                    PolicyName=policy_name
                                )
                                inline_policies[policy_name] = policy_doc.get('PolicyDocument', {})
                            except ClientError as e:
                                logger.warning("Failed to fetch inline policy %s for user %s: %s", policy_name, user['UserName'], e)
                            except Exception as e:
                                logger.debug("Unexpected error fetching inline policy %s: %s", policy_name, e)
                        
                        user_data['inline_policies'] = inline_policies
                    except ClientError as e:
                        logger.error("Failed to list inline policies for user %s: %s", user['UserName'], e)
                        user_data['inline_policies'] = {}
                    except Exception as e:
                        logger.error("Unexpected error processing inline policies for user %s: %s", user['UserName'], e, exc_info=True)
                        user_data['inline_policies'] = {}
                    
                    # Get groups
                    try:
                        groups = self.iam.list_groups_for_user(
                            UserName=user['UserName']
                        )
                        user_data['groups'] = [
                            g['GroupName'] for g in groups.get('Groups', [])
                        ]
                    except ClientError as e:
                        logger.error("Failed to list groups for user %s: %s", user['UserName'], e)
                        user_data['groups'] = []
                    except Exception as e:
                        logger.error("Unexpected error listing groups for user %s: %s", user['UserName'], e, exc_info=True)
                        user_data['groups'] = []
                    
                    users.append(user_data)
        
        except ClientError as e:
            logger.critical("AWS API error scanning users: %s", e)
            raise RuntimeError(f"Failed to scan IAM users: {e}")
        except Exception as e:
            logger.critical("Fatal error scanning IAM users: %s", e, exc_info=True)
            raise RuntimeError(f"Failed to scan IAM users: {e}")
        
        return users
    
    def get_policy_document(self, policy_arn: str) -> Dict[str, Any]:
        """
        Get the policy document for a managed policy
        
        Args:
            policy_arn: ARN of the policy
            
        Returns:
            Policy document as dict
        """
        try:
            # Get default version
            policy = self.iam.get_policy(PolicyArn=policy_arn)
            version_id = policy['Policy']['DefaultVersionId']
            
            # Get policy document
            version = self.iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )
            
            return version['PolicyVersion']['Document']
        
        except ClientError as e:
            logger.error("Failed to get policy document %s: %s", policy_arn, e, exc_info=True)
            return {'error': str(e)}
        except Exception as e:
            logger.error("Unexpected error getting policy document %s: %s", policy_arn, e, exc_info=True)
            return {'error': str(e)}
    
    def scan_ec2_instances(self) -> List[Dict[str, Any]]:
        """
        Scan all EC2 instances in the region.
        
        Returns:
            List of EC2 instance data including instance profiles
        """
        instances = []
        
        try:
            paginator = self.ec2.get_paginator('describe_instances')
            
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        # Only include running/stopped instances (skip terminated)
                        if instance['State']['Name'] not in ['terminated', 'terminating']:
                            instances.append(instance)
        
        except ClientError as e:
            # Log but don't fail - resource enrichment is optional
            logger.warning("Failed to scan EC2 instances: %s", e)
            return []
        except Exception as e:
            logger.error("Unexpected error scanning EC2: %s", e, exc_info=True)
            return []
        
        return instances
    
    def scan_lambda_functions(self) -> List[Dict[str, Any]]:
        """
        Scan all Lambda functions in the region.
        
        Returns:
            List of Lambda function data including execution roles
        """
        functions = []
        
        try:
            paginator = self.lambda_client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                for function in page['Functions']:
                    functions.append(function)
        
        except ClientError as e:
            # Log but don't fail - resource enrichment is optional
            logger.warning("Failed to scan Lambda functions: %s", e)
            return []
        except Exception as e:
            logger.error("Unexpected error scanning Lambda: %s", e, exc_info=True)
            return []
        
        return functions
    
    def get_instance_profiles(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all instance profiles and their associated roles.
        
        Returns:
            Dict mapping instance profile ARN to profile data (including roles)
        """
        instance_profiles = {}
        
        try:
            paginator = self.iam.get_paginator('list_instance_profiles')
            
            for page in paginator.paginate():
                for profile in page['InstanceProfiles']:
                    instance_profiles[profile['Arn']] = profile
        
        except ClientError as e:
            # Log but don't fail - instance profile scan is optional
            logger.warning("Failed to get instance profiles: %s", e)
            return {}
        except Exception as e:
            logger.error("Unexpected error scanning instance profiles: %s", e, exc_info=True)
            return {}
        
        return instance_profiles
