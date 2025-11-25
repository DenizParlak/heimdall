"""
ARN parsing utilities for cross-account detection.

v1.0.0 - Account ID extraction from AWS ARNs
"""

from typing import Optional
import re


def extract_account_id(arn: str) -> Optional[str]:
    """
    Extract account ID from AWS ARN.
    
    ARN format: arn:partition:service:region:account-id:resource-type/resource-id
    
    Examples:
        arn:aws:iam::123456789012:role/MyRole -> 123456789012
        arn:aws:iam::123456789012:user/Alice -> 123456789012
        arn:aws:s3:::my-bucket -> None (S3 buckets don't have account IDs)
    
    Args:
        arn: AWS ARN string
    
    Returns:
        Account ID (12-digit string) or None if not found/invalid
    """
    if not arn or not isinstance(arn, str):
        return None
    
    # ARN format: arn:partition:service:region:account-id:resource
    parts = arn.split(':')
    
    # Need at least 6 parts
    if len(parts) < 6:
        return None
    
    account_id = parts[4]
    
    # Validate: should be 12-digit number
    if account_id and re.match(r'^\d{12}$', account_id):
        return account_id
    
    return None


def is_cross_account(source_arn: str, target_arn: str) -> bool:
    """
    Check if two ARNs belong to different AWS accounts.
    
    Args:
        source_arn: Source principal ARN
        target_arn: Target resource/role ARN
    
    Returns:
        True if accounts differ, False if same or cannot determine
    """
    source_account = extract_account_id(source_arn)
    target_account = extract_account_id(target_arn)
    
    # If either is None, cannot determine - treat as same account
    if not source_account or not target_account:
        return False
    
    return source_account != target_account
