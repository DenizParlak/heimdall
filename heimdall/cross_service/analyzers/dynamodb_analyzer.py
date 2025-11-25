# ᚢᚱᛞ • Urðr - The Well of Fate (DynamoDB Analyzer)
"""DynamoDB Table Analyzer for data access detection."""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging

from ..models import ServiceType, Severity, ServicePermission, ResourcePolicy
from ..registry import ServiceRegistry, ServiceAnalyzerBase, ServiceCapabilities

logger = logging.getLogger(__name__)

# Sensitive table name patterns
SENSITIVE_PATTERNS = ["user", "customer", "account", "credential", "password", 
                      "token", "session", "auth", "payment", "order", "pii"]


@dataclass
class DynamoDBTableInfo:
    """DynamoDB table information."""
    table_name: str
    table_arn: str = ""
    status: str = ""
    
    # Size
    item_count: int = 0
    size_bytes: int = 0
    
    # Encryption
    sse_enabled: bool = False
    sse_type: str = ""  # AES256, KMS
    kms_key_arn: str = ""
    
    # Backup
    pitr_enabled: bool = False
    
    # Streams
    stream_enabled: bool = False
    stream_arn: str = ""
    
    # Sensitivity
    is_sensitive: bool = False
    
    # Risk
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@ServiceRegistry.register(ServiceType.DYNAMODB)
class DynamoDBAnalyzer(ServiceAnalyzerBase):
    """DynamoDB Table Analyzer."""
    
    SERVICE_TYPE = ServiceType.DYNAMODB
    
    def __init__(self, session: Any = None, account_id: str = "", region: str = ""):
        super().__init__(session, account_id, region)
        self._tables: Dict[str, DynamoDBTableInfo] = {}
    
    @classmethod
    def get_capabilities(cls) -> ServiceCapabilities:
        return ServiceCapabilities(
            service=ServiceType.DYNAMODB,
            required_permissions=["dynamodb:ListTables", "dynamodb:DescribeTable"],
            features={"encryption_analysis": True, "sensitive_data_detection": True},
        )
    
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """Enumerate DynamoDB tables."""
        if not self.client:
            return []
        
        tables = []
        try:
            paginator = self.client.get_paginator('list_tables')
            for page in paginator.paginate():
                for table_name in page.get('TableNames', []):
                    info = self._analyze_table(table_name)
                    if info:
                        self._tables[table_name] = info
                        tables.append({
                            "table_name": table_name,
                            "table_arn": info.table_arn,
                            "is_sensitive": info.is_sensitive,
                            "sse_enabled": info.sse_enabled,
                            "risk_score": info.risk_score,
                        })
            logger.info(f"Enumerated {len(tables)} DynamoDB tables")
        except Exception as e:
            logger.error(f"Failed to enumerate DynamoDB tables: {e}")
        return tables
    
    def _analyze_table(self, table_name: str) -> Optional[DynamoDBTableInfo]:
        """Analyze a single DynamoDB table."""
        try:
            response = self.client.describe_table(TableName=table_name)
            table = response.get('Table', {})
            
            info = DynamoDBTableInfo(
                table_name=table_name,
                table_arn=table.get('TableArn', ''),
                status=table.get('TableStatus', ''),
                item_count=table.get('ItemCount', 0),
                size_bytes=table.get('TableSizeBytes', 0),
            )
            
            # SSE
            sse = table.get('SSEDescription', {})
            info.sse_enabled = sse.get('Status') == 'ENABLED'
            info.sse_type = sse.get('SSEType', '')
            info.kms_key_arn = sse.get('KMSMasterKeyArn', '')
            
            # Streams
            stream_spec = table.get('StreamSpecification', {})
            info.stream_enabled = stream_spec.get('StreamEnabled', False)
            info.stream_arn = table.get('LatestStreamArn', '')
            
            # Check sensitivity
            self._check_sensitivity(info)
            
            # Check PITR
            try:
                pitr = self.client.describe_continuous_backups(TableName=table_name)
                pitr_desc = pitr.get('ContinuousBackupsDescription', {})
                pitr_status = pitr_desc.get('PointInTimeRecoveryDescription', {})
                info.pitr_enabled = pitr_status.get('PointInTimeRecoveryStatus') == 'ENABLED'
            except:
                pass
            
            self._calculate_risk(info)
            return info
        except Exception as e:
            logger.debug(f"Failed to analyze table {table_name}: {e}")
            return None
    
    def _check_sensitivity(self, info: DynamoDBTableInfo) -> None:
        """Check if table name indicates sensitive data."""
        name_lower = info.table_name.lower()
        for pattern in SENSITIVE_PATTERNS:
            if pattern in name_lower:
                info.is_sensitive = True
                info.risk_factors.append(f"Sensitive name: {pattern}")
                break
    
    def _calculate_risk(self, info: DynamoDBTableInfo) -> None:
        score = 0
        if info.is_sensitive:
            score += 25
        if not info.sse_enabled:
            score += 20
            info.risk_factors.append("No encryption")
        if not info.pitr_enabled:
            score += 10
            info.risk_factors.append("No point-in-time recovery")
        if info.item_count > 100000:
            score += 10
            info.risk_factors.append(f"Large table: {info.item_count} items")
        info.risk_score = min(100, score)
    
    def get_resource_policy(self, resource_arn: str) -> Optional[ResourcePolicy]:
        return None  # DynamoDB doesn't have resource policies
    
    def find_escalation_paths(self, principal_arn: str, permissions: List[ServicePermission]) -> List[Dict]:
        paths = []
        for perm in permissions:
            if perm.service != ServiceType.DYNAMODB or perm.effect != "Allow":
                continue
            action = perm.action.lower()
            if 'dynamodb:*' in action or '*' in action:
                for name, info in self._tables.items():
                    if info.is_sensitive:
                        paths.append({
                            "type": "sensitive_data_access",
                            "table": name,
                            "severity": "HIGH",
                            "description": f"Full access to sensitive table: {name}",
                        })
        return paths
    
    def get_sensitive_tables(self) -> List[DynamoDBTableInfo]:
        return [t for t in self._tables.values() if t.is_sensitive]
    
    def get_unencrypted_tables(self) -> List[DynamoDBTableInfo]:
        return [t for t in self._tables.values() if not t.sse_enabled]
    
    def get_high_risk_tables(self, threshold: int = 30) -> List[DynamoDBTableInfo]:
        return [t for t in self._tables.values() if t.risk_score >= threshold]
