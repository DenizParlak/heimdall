# ᚺᛖᛁᛗᛞᚨᛚᛚ • Gjallarhorn - The Sounding Horn (SNS Analyzer)
"""SNS Topic Analyzer for cross-service privilege escalation detection."""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging
import json

from ..models import ServiceType, Severity, ServicePermission, ResourcePolicy
from ..registry import ServiceRegistry, ServiceAnalyzerBase, ServiceCapabilities

logger = logging.getLogger(__name__)


@dataclass
class SNSTopicInfo:
    """SNS topic information."""
    topic_arn: str
    name: str = ""
    
    # Policy
    policy: Optional[Dict] = None
    allows_public: bool = False
    allows_cross_account: bool = False
    cross_account_principals: List[str] = field(default_factory=list)
    
    # Subscriptions
    subscription_count: int = 0
    lambda_subscriptions: List[str] = field(default_factory=list)
    
    # Encryption
    kms_key_id: str = ""
    
    # Risk
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@ServiceRegistry.register(ServiceType.SNS)
class SNSAnalyzer(ServiceAnalyzerBase):
    """SNS Topic Analyzer."""
    
    SERVICE_TYPE = ServiceType.SNS
    
    def __init__(self, session: Any = None, account_id: str = "", region: str = ""):
        super().__init__(session, account_id, region)
        self._topics: Dict[str, SNSTopicInfo] = {}
    
    @classmethod
    def get_capabilities(cls) -> ServiceCapabilities:
        return ServiceCapabilities(
            service=ServiceType.SNS,
            required_permissions=["sns:ListTopics", "sns:GetTopicAttributes"],
            features={"topic_policy_analysis": True, "cross_account_detection": True},
        )
    
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """Enumerate SNS topics."""
        if not self.client:
            return []
        
        topics = []
        try:
            paginator = self.client.get_paginator('list_topics')
            for page in paginator.paginate():
                for topic in page.get('Topics', []):
                    arn = topic.get('TopicArn', '')
                    info = self._analyze_topic(arn)
                    if info:
                        self._topics[arn] = info
                        topics.append({
                            "topic_arn": arn,
                            "name": info.name,
                            "allows_public": info.allows_public,
                            "risk_score": info.risk_score,
                        })
            logger.info(f"Enumerated {len(topics)} SNS topics")
        except Exception as e:
            logger.error(f"Failed to enumerate SNS topics: {e}")
        return topics
    
    def _analyze_topic(self, topic_arn: str) -> Optional[SNSTopicInfo]:
        """Analyze a single SNS topic."""
        try:
            name = topic_arn.split(':')[-1]
            info = SNSTopicInfo(topic_arn=topic_arn, name=name)
            
            # Get attributes
            attrs = self.client.get_topic_attributes(TopicArn=topic_arn)
            attributes = attrs.get('Attributes', {})
            
            # Policy
            policy_str = attributes.get('Policy', '{}')
            info.policy = json.loads(policy_str)
            self._analyze_policy(info)
            
            # KMS
            info.kms_key_id = attributes.get('KmsMasterKeyId', '')
            
            # Subscriptions
            info.subscription_count = int(attributes.get('SubscriptionsConfirmed', 0))
            
            self._calculate_risk(info)
            return info
        except Exception as e:
            logger.debug(f"Failed to analyze topic {topic_arn}: {e}")
            return None
    
    def _analyze_policy(self, info: SNSTopicInfo) -> None:
        """Analyze topic policy."""
        if not info.policy:
            return
        
        for stmt in info.policy.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue
            
            principal = stmt.get('Principal', {})
            if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                cond = stmt.get('Condition', {})
                if not cond:
                    info.allows_public = True
                    info.risk_factors.append("Public topic access")
            
            # Cross-account
            if isinstance(principal, dict):
                for p in self._flatten_principals(principal):
                    if self._is_cross_account(p):
                        info.allows_cross_account = True
                        info.cross_account_principals.append(p)
    
    def _flatten_principals(self, principal: Any) -> List[str]:
        if isinstance(principal, str):
            return [principal]
        if isinstance(principal, dict):
            result = []
            for v in principal.values():
                if isinstance(v, list):
                    result.extend(v)
                else:
                    result.append(v)
            return result
        return []
    
    def _is_cross_account(self, principal: str) -> bool:
        if not self.account_id or principal == '*':
            return False
        parts = principal.split(':')
        return len(parts) >= 5 and parts[4] != self.account_id and parts[4] != ''
    
    def _calculate_risk(self, info: SNSTopicInfo) -> None:
        score = 0
        if info.allows_public:
            score += 40
        if info.allows_cross_account:
            score += 25
        if not info.kms_key_id:
            score += 10
        info.risk_score = min(100, score)
    
    def get_resource_policy(self, resource_arn: str) -> Optional[ResourcePolicy]:
        info = self._topics.get(resource_arn)
        if not info or not info.policy:
            return None
        policy = ResourcePolicy(
            resource_arn=resource_arn,
            resource_type=ServiceType.SNS,
            policy_document=info.policy,
            resource_name=info.name,
        )
        policy.parse_policy()
        policy.is_public = info.allows_public
        policy.allows_cross_account = info.allows_cross_account
        return policy
    
    def find_escalation_paths(self, principal_arn: str, permissions: List[ServicePermission]) -> List[Dict]:
        return []
    
    def get_public_topics(self) -> List[SNSTopicInfo]:
        return [t for t in self._topics.values() if t.allows_public]
    
    def get_cross_account_topics(self) -> List[SNSTopicInfo]:
        return [t for t in self._topics.values() if t.allows_cross_account]
