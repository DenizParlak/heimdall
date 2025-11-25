# ᚨᚾᚨᛚᛁᛉᛖᚱᛊ • Analyzers - Service-Specific Analysis Modules
"""
Service-specific analyzers for cross-service privilege escalation detection.

Each analyzer implements the ServiceAnalyzerBase interface and registers
itself with the ServiceRegistry.
"""

from .s3_analyzer import S3Analyzer
from .lambda_analyzer import LambdaAnalyzer
from .kms_analyzer import KMSAnalyzer
from .sts_analyzer import STSAnalyzer
from .secrets_analyzer import SecretsManagerAnalyzer
from .ec2_analyzer import EC2Analyzer
from .sns_analyzer import SNSAnalyzer
from .sqs_analyzer import SQSAnalyzer
from .dynamodb_analyzer import DynamoDBAnalyzer
from .rds_analyzer import RDSAnalyzer

__all__ = [
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
