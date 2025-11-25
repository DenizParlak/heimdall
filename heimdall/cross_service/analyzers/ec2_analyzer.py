# ᛊᛚᛖᛁᛈᚾᛁᚱ • Sleipnir - Odin's Eight-Legged Steed (EC2 Analyzer)
"""EC2 Instance Analyzer for privilege escalation via instance profiles and SSM."""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging

from ..models import ServiceType, Severity, ServicePermission, ResourcePolicy
from ..registry import ServiceRegistry, ServiceAnalyzerBase, ServiceCapabilities

logger = logging.getLogger(__name__)

# Dangerous EC2/SSM actions
DANGEROUS_ACTIONS = {
    "ec2:RunInstances": (Severity.HIGH, "instance_creation"),
    "ec2:AssociateIamInstanceProfile": (Severity.CRITICAL, "profile_association"),
    "ec2:ReplaceIamInstanceProfileAssociation": (Severity.CRITICAL, "profile_replacement"),
    "ssm:SendCommand": (Severity.CRITICAL, "ssm_command"),
    "ssm:StartSession": (Severity.HIGH, "ssm_session"),
    "ssm:CreateDocument": (Severity.HIGH, "ssm_document"),
    "ec2:ModifyInstanceAttribute": (Severity.HIGH, "instance_modification"),
    "ec2:GetPasswordData": (Severity.HIGH, "password_retrieval"),
}


@dataclass
class EC2InstanceInfo:
    """EC2 instance information."""
    instance_id: str
    arn: str
    name: str = ""
    state: str = ""
    instance_type: str = ""
    
    # Instance profile
    instance_profile_arn: str = ""
    instance_profile_name: str = ""
    role_arn: str = ""
    role_name: str = ""
    
    # Network
    vpc_id: str = ""
    subnet_id: str = ""
    public_ip: str = ""
    private_ip: str = ""
    security_groups: List[str] = field(default_factory=list)
    
    # SSM
    ssm_managed: bool = False
    ssm_agent_version: str = ""
    
    # Metadata
    imds_v1_enabled: bool = True  # Security risk if true
    
    # Role analysis
    role_is_admin: bool = False
    role_policies: List[str] = field(default_factory=list)
    
    # Risk
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@dataclass
class InstanceProfileInfo:
    """IAM Instance Profile information."""
    profile_name: str
    profile_arn: str
    role_name: str = ""
    role_arn: str = ""
    
    # Role permissions
    is_admin: bool = False
    attached_policies: List[str] = field(default_factory=list)
    
    # Usage
    instance_count: int = 0
    
    # Risk
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@ServiceRegistry.register(ServiceType.EC2)
class EC2Analyzer(ServiceAnalyzerBase):
    """EC2 Instance Analyzer for privilege escalation detection."""
    
    SERVICE_TYPE = ServiceType.EC2
    
    def __init__(self, session: Any = None, account_id: str = "", region: str = ""):
        super().__init__(session, account_id, region)
        self._instances: Dict[str, EC2InstanceInfo] = {}
        self._profiles: Dict[str, InstanceProfileInfo] = {}
        self._ssm_instances: List[str] = []
    
    @classmethod
    def get_capabilities(cls) -> ServiceCapabilities:
        return ServiceCapabilities(
            service=ServiceType.EC2,
            required_permissions=[
                "ec2:DescribeInstances", "ec2:DescribeIamInstanceProfileAssociations",
                "iam:ListInstanceProfiles", "ssm:DescribeInstanceInformation",
            ],
            features={
                "instance_profile_analysis": True,
                "ssm_detection": True,
                "imds_analysis": True,
            },
        )
    
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """Enumerate EC2 instances and instance profiles."""
        if not self.session:
            return []
        
        resources = []
        
        # Get instance profiles first
        self._enumerate_instance_profiles()
        
        # Get EC2 instances
        try:
            ec2 = self.session.client('ec2', region_name=self.region)
            paginator = ec2.get_paginator('describe_instances')
            
            for page in paginator.paginate():
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        info = self._analyze_instance(instance)
                        if info:
                            self._instances[info.instance_id] = info
                            resources.append({
                                "instance_id": info.instance_id,
                                "name": info.name,
                                "state": info.state,
                                "instance_profile": info.instance_profile_name,
                                "ssm_managed": info.ssm_managed,
                                "risk_score": info.risk_score,
                            })
            
            # Check SSM managed instances
            self._check_ssm_instances()
            
            logger.info(f"Enumerated {len(resources)} EC2 instances")
        except Exception as e:
            logger.error(f"Failed to enumerate EC2 instances: {e}")
        
        return resources
    
    def _enumerate_instance_profiles(self) -> None:
        """Enumerate IAM instance profiles."""
        try:
            iam = self.session.client('iam')
            paginator = iam.get_paginator('list_instance_profiles')
            
            for page in paginator.paginate():
                for profile in page.get('InstanceProfiles', []):
                    info = self._analyze_profile(profile)
                    if info:
                        self._profiles[info.profile_name] = info
                        
        except Exception as e:
            logger.debug(f"Failed to enumerate instance profiles: {e}")
    
    def _analyze_profile(self, profile_data: Dict) -> Optional[InstanceProfileInfo]:
        """Analyze an instance profile."""
        try:
            profile_name = profile_data.get('InstanceProfileName', '')
            profile_arn = profile_data.get('Arn', '')
            
            info = InstanceProfileInfo(
                profile_name=profile_name,
                profile_arn=profile_arn,
            )
            
            # Get role info
            roles = profile_data.get('Roles', [])
            if roles:
                role = roles[0]
                info.role_name = role.get('RoleName', '')
                info.role_arn = role.get('Arn', '')
                
                # Analyze role permissions
                self._analyze_profile_role(info)
            
            return info
        except Exception as e:
            logger.debug(f"Failed to analyze profile: {e}")
            return None
    
    def _analyze_profile_role(self, info: InstanceProfileInfo) -> None:
        """Analyze instance profile role permissions."""
        if not info.role_name:
            return
        
        try:
            iam = self.session.client('iam')
            
            # Get attached policies
            attached = iam.list_attached_role_policies(RoleName=info.role_name)
            for policy in attached.get('AttachedPolicies', []):
                policy_name = policy.get('PolicyName', '')
                info.attached_policies.append(policy_name)
                
                # Check for admin
                if 'AdministratorAccess' in policy_name or 'PowerUserAccess' in policy_name:
                    info.is_admin = True
                    info.risk_factors.append(f"Admin policy: {policy_name}")
            
            # Calculate risk
            if info.is_admin:
                info.risk_score = 80
            elif len(info.attached_policies) > 5:
                info.risk_score = 40
                info.risk_factors.append(f"Many policies: {len(info.attached_policies)}")
            else:
                info.risk_score = 20
                
        except Exception as e:
            logger.debug(f"Failed to analyze profile role: {e}")
    
    def _analyze_instance(self, instance_data: Dict) -> Optional[EC2InstanceInfo]:
        """Analyze a single EC2 instance."""
        try:
            instance_id = instance_data.get('InstanceId', '')
            
            # Get name from tags
            name = ""
            for tag in instance_data.get('Tags', []):
                if tag.get('Key') == 'Name':
                    name = tag.get('Value', '')
                    break
            
            info = EC2InstanceInfo(
                instance_id=instance_id,
                arn=f"arn:aws:ec2:{self.region}:{self.account_id}:instance/{instance_id}",
                name=name,
                state=instance_data.get('State', {}).get('Name', ''),
                instance_type=instance_data.get('InstanceType', ''),
                vpc_id=instance_data.get('VpcId', ''),
                subnet_id=instance_data.get('SubnetId', ''),
                public_ip=instance_data.get('PublicIpAddress', ''),
                private_ip=instance_data.get('PrivateIpAddress', ''),
            )
            
            # Security groups
            for sg in instance_data.get('SecurityGroups', []):
                info.security_groups.append(sg.get('GroupId', ''))
            
            # Instance profile
            iam_profile = instance_data.get('IamInstanceProfile', {})
            if iam_profile:
                info.instance_profile_arn = iam_profile.get('Arn', '')
                # Extract profile name from ARN
                if info.instance_profile_arn:
                    info.instance_profile_name = info.instance_profile_arn.split('/')[-1]
                    
                    # Get role info from our profiles
                    profile = self._profiles.get(info.instance_profile_name)
                    if profile:
                        info.role_name = profile.role_name
                        info.role_arn = profile.role_arn
                        info.role_is_admin = profile.is_admin
                        info.role_policies = profile.attached_policies
            
            # Check metadata options
            metadata_options = instance_data.get('MetadataOptions', {})
            http_tokens = metadata_options.get('HttpTokens', 'optional')
            info.imds_v1_enabled = (http_tokens == 'optional')
            
            # Calculate risk
            self._calculate_risk(info)
            
            return info
        except Exception as e:
            logger.warning(f"Failed to analyze instance: {e}")
            return None
    
    def _check_ssm_instances(self) -> None:
        """Check which instances are SSM managed."""
        try:
            ssm = self.session.client('ssm', region_name=self.region)
            paginator = ssm.get_paginator('describe_instance_information')
            
            for page in paginator.paginate():
                for info in page.get('InstanceInformationList', []):
                    instance_id = info.get('InstanceId', '')
                    if instance_id in self._instances:
                        self._instances[instance_id].ssm_managed = True
                        self._instances[instance_id].ssm_agent_version = info.get('AgentVersion', '')
                        self._ssm_instances.append(instance_id)
                        
        except Exception as e:
            logger.debug(f"Failed to check SSM instances: {e}")
    
    def _calculate_risk(self, info: EC2InstanceInfo) -> None:
        """Calculate risk score for instance."""
        score = 0
        
        # Admin role (critical)
        if info.role_is_admin:
            score += 50
            info.risk_factors.append("Admin instance profile")
        
        # Has instance profile
        if info.instance_profile_arn:
            score += 10
        
        # Public IP
        if info.public_ip:
            score += 15
            info.risk_factors.append("Public IP assigned")
        
        # IMDSv1 enabled (credential theft risk)
        if info.imds_v1_enabled:
            score += 15
            info.risk_factors.append("IMDSv1 enabled (credential theft risk)")
        
        # SSM managed (can run commands)
        if info.ssm_managed:
            score += 10
        
        # Running state
        if info.state == 'running':
            score += 5
        
        info.risk_score = min(100, score)
    
    def get_resource_policy(self, resource_arn: str) -> Optional[ResourcePolicy]:
        """EC2 instances don't have resource policies."""
        return None
    
    def find_escalation_paths(
        self, principal_arn: str, permissions: List[ServicePermission]
    ) -> List[Dict[str, Any]]:
        """Find EC2/SSM-based privilege escalation paths."""
        paths = []
        
        for perm in permissions:
            if perm.effect != "Allow":
                continue
            
            action = perm.action.lower()
            
            # Check dangerous actions
            for dangerous, (severity, esc_type) in DANGEROUS_ACTIONS.items():
                if dangerous.lower() in action or action in ['*', 'ec2:*', 'ssm:*']:
                    paths.append({
                        "type": esc_type,
                        "action": dangerous,
                        "resource": perm.resource,
                        "severity": severity.value,
                        "description": f"Can {dangerous}",
                    })
            
            # SSM SendCommand to specific instances
            if 'ssm:sendcommand' in action or action in ['*', 'ssm:*']:
                for iid, inst in self._instances.items():
                    if inst.ssm_managed and inst.role_is_admin:
                        paths.append({
                            "type": "ssm_to_admin",
                            "action": "ssm:SendCommand",
                            "instance_id": iid,
                            "instance_name": inst.name,
                            "target_role": inst.role_name,
                            "severity": "CRITICAL",
                            "description": f"SSM to admin instance: {inst.name or iid}",
                        })
        
        return paths
    
    # Helper methods
    def get_instances_with_profiles(self) -> List[EC2InstanceInfo]:
        """Get instances with instance profiles."""
        return [i for i in self._instances.values() if i.instance_profile_arn]
    
    def get_admin_instances(self) -> List[EC2InstanceInfo]:
        """Get instances with admin roles."""
        return [i for i in self._instances.values() if i.role_is_admin]
    
    def get_ssm_instances(self) -> List[EC2InstanceInfo]:
        """Get SSM managed instances."""
        return [i for i in self._instances.values() if i.ssm_managed]
    
    def get_public_instances(self) -> List[EC2InstanceInfo]:
        """Get instances with public IPs."""
        return [i for i in self._instances.values() if i.public_ip]
    
    def get_imdsv1_instances(self) -> List[EC2InstanceInfo]:
        """Get instances with IMDSv1 enabled."""
        return [i for i in self._instances.values() if i.imds_v1_enabled]
    
    def get_high_risk_instances(self, threshold: int = 50) -> List[EC2InstanceInfo]:
        """Get instances above risk threshold."""
        return [i for i in self._instances.values() if i.risk_score >= threshold]
    
    def get_admin_profiles(self) -> List[InstanceProfileInfo]:
        """Get instance profiles with admin permissions."""
        return [p for p in self._profiles.values() if p.is_admin]
