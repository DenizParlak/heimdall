# ᛗᛁᛞᚷᚨᚱᛞ • Midgard - The Realm of Cross-Service Analysis
# Where IAM meets other AWS services, revealing hidden attack paths
"""
Cross-Service Privilege Escalation Engine.

This module analyzes privilege escalation paths that span multiple AWS services,
combining IAM policies with resource-based policies from S3, Lambda, KMS, etc.
"""

from .scanner import CrossServiceScanner
from .registry import ServiceRegistry
from .models import (
    CrossServiceFinding,
    ResourcePolicy,
    ServicePermission,
    AttackVector,
    CrossServiceChain,
)

# Import analyzers to trigger registration
from .analyzers import (
    S3Analyzer, LambdaAnalyzer, KMSAnalyzer, STSAnalyzer, 
    SecretsManagerAnalyzer, EC2Analyzer, SNSAnalyzer, 
    SQSAnalyzer, DynamoDBAnalyzer, RDSAnalyzer
)

__all__ = [
    'CrossServiceScanner',
    'ServiceRegistry',
    'CrossServiceFinding',
    'ResourcePolicy',
    'ServicePermission',
    'AttackVector',
    'CrossServiceChain',
    'S3Analyzer',
    'LambdaAnalyzer',
    'KMSAnalyzer',
    'STSAnalyzer',
    'SecretsManagerAnalyzer',
    'EC2Analyzer',
    'SNSAnalyzer',
    'SQSAnalyzer',
    'DynamoDBAnalyzer',
    'RDSAnalyzer',
]
