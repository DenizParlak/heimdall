# ᛗᛁᛗᛁᚱᛊᛒᚱᚢᚾᚾᚱ • Mímisbrunnr - The Well of Wisdom (RDS Analyzer)
"""RDS Database Analyzer for data access and snapshot detection."""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging

from ..models import ServiceType, Severity, ServicePermission, ResourcePolicy
from ..registry import ServiceRegistry, ServiceAnalyzerBase, ServiceCapabilities

logger = logging.getLogger(__name__)


@dataclass
class RDSInstanceInfo:
    """RDS instance information."""
    db_instance_id: str
    db_instance_arn: str = ""
    engine: str = ""
    engine_version: str = ""
    status: str = ""
    
    # Network
    publicly_accessible: bool = False
    vpc_id: str = ""
    endpoint: str = ""
    port: int = 0
    
    # Security
    encrypted: bool = False
    kms_key_id: str = ""
    iam_auth_enabled: bool = False
    
    # Backup
    backup_retention: int = 0
    
    # Risk
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@dataclass
class RDSSnapshotInfo:
    """RDS snapshot information."""
    snapshot_id: str
    snapshot_arn: str = ""
    db_instance_id: str = ""
    engine: str = ""
    
    # Sharing
    is_public: bool = False
    shared_accounts: List[str] = field(default_factory=list)
    
    # Encryption
    encrypted: bool = False
    
    # Risk
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@ServiceRegistry.register(ServiceType.RDS)
class RDSAnalyzer(ServiceAnalyzerBase):
    """RDS Database Analyzer."""
    
    SERVICE_TYPE = ServiceType.RDS
    
    def __init__(self, session: Any = None, account_id: str = "", region: str = ""):
        super().__init__(session, account_id, region)
        self._instances: Dict[str, RDSInstanceInfo] = {}
        self._snapshots: Dict[str, RDSSnapshotInfo] = {}
    
    @classmethod
    def get_capabilities(cls) -> ServiceCapabilities:
        return ServiceCapabilities(
            service=ServiceType.RDS,
            required_permissions=[
                "rds:DescribeDBInstances", "rds:DescribeDBSnapshots",
                "rds:DescribeDBSnapshotAttributes",
            ],
            features={
                "public_access_detection": True,
                "snapshot_sharing_analysis": True,
                "encryption_analysis": True,
            },
        )
    
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """Enumerate RDS instances and snapshots."""
        if not self.client:
            return []
        
        resources = []
        
        # Enumerate instances
        try:
            paginator = self.client.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for db in page.get('DBInstances', []):
                    info = self._analyze_instance(db)
                    if info:
                        self._instances[info.db_instance_id] = info
                        resources.append({
                            "type": "instance",
                            "id": info.db_instance_id,
                            "engine": info.engine,
                            "publicly_accessible": info.publicly_accessible,
                            "risk_score": info.risk_score,
                        })
        except Exception as e:
            logger.error(f"Failed to enumerate RDS instances: {e}")
        
        # Enumerate snapshots
        try:
            paginator = self.client.get_paginator('describe_db_snapshots')
            for page in paginator.paginate(SnapshotType='manual'):
                for snap in page.get('DBSnapshots', []):
                    info = self._analyze_snapshot(snap)
                    if info:
                        self._snapshots[info.snapshot_id] = info
                        if info.is_public or info.shared_accounts:
                            resources.append({
                                "type": "snapshot",
                                "id": info.snapshot_id,
                                "is_public": info.is_public,
                                "shared_count": len(info.shared_accounts),
                                "risk_score": info.risk_score,
                            })
        except Exception as e:
            logger.debug(f"Failed to enumerate RDS snapshots: {e}")
        
        logger.info(f"Enumerated {len(self._instances)} RDS instances, {len(self._snapshots)} snapshots")
        return resources
    
    def _analyze_instance(self, db_data: Dict) -> Optional[RDSInstanceInfo]:
        """Analyze a single RDS instance."""
        try:
            info = RDSInstanceInfo(
                db_instance_id=db_data.get('DBInstanceIdentifier', ''),
                db_instance_arn=db_data.get('DBInstanceArn', ''),
                engine=db_data.get('Engine', ''),
                engine_version=db_data.get('EngineVersion', ''),
                status=db_data.get('DBInstanceStatus', ''),
                publicly_accessible=db_data.get('PubliclyAccessible', False),
                vpc_id=db_data.get('DBSubnetGroup', {}).get('VpcId', ''),
                encrypted=db_data.get('StorageEncrypted', False),
                kms_key_id=db_data.get('KmsKeyId', ''),
                iam_auth_enabled=db_data.get('IAMDatabaseAuthenticationEnabled', False),
                backup_retention=db_data.get('BackupRetentionPeriod', 0),
            )
            
            endpoint = db_data.get('Endpoint', {})
            info.endpoint = endpoint.get('Address', '')
            info.port = endpoint.get('Port', 0)
            
            self._calculate_instance_risk(info)
            return info
        except Exception as e:
            logger.debug(f"Failed to analyze RDS instance: {e}")
            return None
    
    def _analyze_snapshot(self, snap_data: Dict) -> Optional[RDSSnapshotInfo]:
        """Analyze a single RDS snapshot."""
        try:
            snapshot_id = snap_data.get('DBSnapshotIdentifier', '')
            
            info = RDSSnapshotInfo(
                snapshot_id=snapshot_id,
                snapshot_arn=snap_data.get('DBSnapshotArn', ''),
                db_instance_id=snap_data.get('DBInstanceIdentifier', ''),
                engine=snap_data.get('Engine', ''),
                encrypted=snap_data.get('Encrypted', False),
            )
            
            # Check sharing
            try:
                attrs = self.client.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=snapshot_id
                )
                for attr in attrs.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', []):
                    if attr.get('AttributeName') == 'restore':
                        values = attr.get('AttributeValues', [])
                        if 'all' in values:
                            info.is_public = True
                            info.risk_factors.append("Public snapshot")
                        else:
                            info.shared_accounts = values
                            if values:
                                info.risk_factors.append(f"Shared with {len(values)} accounts")
            except:
                pass
            
            self._calculate_snapshot_risk(info)
            return info
        except Exception as e:
            logger.debug(f"Failed to analyze RDS snapshot: {e}")
            return None
    
    def _calculate_instance_risk(self, info: RDSInstanceInfo) -> None:
        score = 0
        if info.publicly_accessible:
            score += 40
            info.risk_factors.append("Publicly accessible")
        if not info.encrypted:
            score += 25
            info.risk_factors.append("Not encrypted")
        if info.backup_retention == 0:
            score += 15
            info.risk_factors.append("No backup retention")
        if not info.iam_auth_enabled:
            score += 10
        info.risk_score = min(100, score)
    
    def _calculate_snapshot_risk(self, info: RDSSnapshotInfo) -> None:
        score = 0
        if info.is_public:
            score += 60
        if info.shared_accounts:
            score += 30
        if not info.encrypted:
            score += 20
            info.risk_factors.append("Unencrypted snapshot")
        info.risk_score = min(100, score)
    
    def get_resource_policy(self, resource_arn: str) -> Optional[ResourcePolicy]:
        return None
    
    def find_escalation_paths(self, principal_arn: str, permissions: List[ServicePermission]) -> List[Dict]:
        paths = []
        for perm in permissions:
            action = perm.action.lower()
            if 'rds:restoredbinstancefromsnapshot' in action or 'rds:*' in action:
                for snap_id, snap in self._snapshots.items():
                    if snap.is_public or snap.shared_accounts:
                        paths.append({
                            "type": "snapshot_restore",
                            "snapshot_id": snap_id,
                            "severity": "HIGH",
                            "description": f"Can restore from shared snapshot: {snap_id}",
                        })
        return paths
    
    def get_public_instances(self) -> List[RDSInstanceInfo]:
        return [i for i in self._instances.values() if i.publicly_accessible]
    
    def get_unencrypted_instances(self) -> List[RDSInstanceInfo]:
        return [i for i in self._instances.values() if not i.encrypted]
    
    def get_public_snapshots(self) -> List[RDSSnapshotInfo]:
        return [s for s in self._snapshots.values() if s.is_public]
    
    def get_shared_snapshots(self) -> List[RDSSnapshotInfo]:
        return [s for s in self._snapshots.values() if s.shared_accounts]
    
    def get_high_risk_instances(self, threshold: int = 40) -> List[RDSInstanceInfo]:
        return [i for i in self._instances.values() if i.risk_score >= threshold]
