# ᚱᚨᛏᚨᛏᛟᛊᚲ • Ratatoskr - The Messenger Squirrel (SQS Analyzer)
"""SQS Queue Analyzer for cross-service privilege escalation detection."""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging
import json

from ..models import ServiceType, Severity, ServicePermission, ResourcePolicy
from ..registry import ServiceRegistry, ServiceAnalyzerBase, ServiceCapabilities

logger = logging.getLogger(__name__)


@dataclass
class SQSQueueInfo:
    """SQS queue information."""
    queue_url: str
    queue_arn: str = ""
    name: str = ""
    
    # Policy
    policy: Optional[Dict] = None
    allows_public: bool = False
    allows_cross_account: bool = False
    cross_account_principals: List[str] = field(default_factory=list)
    
    # Encryption
    kms_key_id: str = ""
    
    # DLQ
    dlq_arn: str = ""
    
    # Risk
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@ServiceRegistry.register(ServiceType.SQS)
class SQSAnalyzer(ServiceAnalyzerBase):
    """SQS Queue Analyzer."""
    
    SERVICE_TYPE = ServiceType.SQS
    
    def __init__(self, session: Any = None, account_id: str = "", region: str = ""):
        super().__init__(session, account_id, region)
        self._queues: Dict[str, SQSQueueInfo] = {}
    
    @classmethod
    def get_capabilities(cls) -> ServiceCapabilities:
        return ServiceCapabilities(
            service=ServiceType.SQS,
            required_permissions=["sqs:ListQueues", "sqs:GetQueueAttributes"],
            features={"queue_policy_analysis": True, "cross_account_detection": True},
        )
    
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """Enumerate SQS queues."""
        if not self.client:
            return []
        
        queues = []
        try:
            response = self.client.list_queues()
            for queue_url in response.get('QueueUrls', []):
                info = self._analyze_queue(queue_url)
                if info:
                    self._queues[queue_url] = info
                    queues.append({
                        "queue_url": queue_url,
                        "name": info.name,
                        "allows_public": info.allows_public,
                        "risk_score": info.risk_score,
                    })
            logger.info(f"Enumerated {len(queues)} SQS queues")
        except Exception as e:
            logger.error(f"Failed to enumerate SQS queues: {e}")
        return queues
    
    def _analyze_queue(self, queue_url: str) -> Optional[SQSQueueInfo]:
        """Analyze a single SQS queue."""
        try:
            name = queue_url.split('/')[-1]
            info = SQSQueueInfo(queue_url=queue_url, name=name)
            
            # Get attributes
            attrs = self.client.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['All']
            )
            attributes = attrs.get('Attributes', {})
            
            info.queue_arn = attributes.get('QueueArn', '')
            
            # Policy
            policy_str = attributes.get('Policy', '')
            if policy_str:
                info.policy = json.loads(policy_str)
                self._analyze_policy(info)
            
            # KMS
            info.kms_key_id = attributes.get('KmsMasterKeyId', '')
            
            # DLQ
            dlq_config = attributes.get('RedrivePolicy', '')
            if dlq_config:
                dlq = json.loads(dlq_config)
                info.dlq_arn = dlq.get('deadLetterTargetArn', '')
            
            self._calculate_risk(info)
            return info
        except Exception as e:
            logger.debug(f"Failed to analyze queue {queue_url}: {e}")
            return None
    
    def _analyze_policy(self, info: SQSQueueInfo) -> None:
        """Analyze queue policy."""
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
                    info.risk_factors.append("Public queue access")
            
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
    
    def _calculate_risk(self, info: SQSQueueInfo) -> None:
        score = 0
        if info.allows_public:
            score += 40
        if info.allows_cross_account:
            score += 25
        if not info.kms_key_id:
            score += 10
        info.risk_score = min(100, score)
    
    def get_resource_policy(self, resource_arn: str) -> Optional[ResourcePolicy]:
        for info in self._queues.values():
            if info.queue_arn == resource_arn:
                if not info.policy:
                    return None
                policy = ResourcePolicy(
                    resource_arn=resource_arn,
                    resource_type=ServiceType.SQS,
                    policy_document=info.policy,
                    resource_name=info.name,
                )
                policy.parse_policy()
                policy.is_public = info.allows_public
                policy.allows_cross_account = info.allows_cross_account
                return policy
        return None
    
    def find_escalation_paths(self, principal_arn: str, permissions: List[ServicePermission]) -> List[Dict]:
        return []
    
    def get_public_queues(self) -> List[SQSQueueInfo]:
        return [q for q in self._queues.values() if q.allows_public]
    
    def get_cross_account_queues(self) -> List[SQSQueueInfo]:
        return [q for q in self._queues.values() if q.allows_cross_account]
