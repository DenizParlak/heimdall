"""
CloudTrail Monitor - Real-time IAM change detection
Monitors CloudTrail events for IAM changes and triggers security analysis
"""

import boto3
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class CloudTrailMonitor:
    """Monitor CloudTrail for IAM security-relevant events"""
    
    # IAM events that could affect privilege escalation
    MONITORED_EVENTS = [
        # User events
        'CreateUser',
        'DeleteUser',
        'AttachUserPolicy',
        'DetachUserPolicy',
        'PutUserPolicy',
        'DeleteUserPolicy',
        'AddUserToGroup',
        'RemoveUserFromGroup',
        # Role events
        'CreateRole',
        'DeleteRole',
        'AttachRolePolicy',
        'DetachRolePolicy',
        'PutRolePolicy',
        'DeleteRolePolicy',
        'UpdateAssumeRolePolicy',
        # Access key events
        'CreateAccessKey',
        'DeleteAccessKey',
        # Group events
        'PutGroupPolicy',
        'DeleteGroupPolicy',
        'AttachGroupPolicy',
        'DetachGroupPolicy',
        'SetDefaultPolicyVersion',
        'CreatePolicyVersion',
    ]
    
    def __init__(self, profile_name: str = 'default', region: str = 'us-east-1'):
        """Initialize CloudTrail monitor"""
        self.session = boto3.Session(profile_name=profile_name, region_name=region)
        self.cloudtrail = self.session.client('cloudtrail')
        self.iam = self.session.client('iam')
        
    def get_recent_iam_events(
        self,
        lookback_minutes: int = 5,
        max_results: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get recent IAM events from CloudTrail
        
        Args:
            lookback_minutes: How far back to look for events
            max_results: Maximum number of events to return
            
        Returns:
            List of CloudTrail events
        """
        try:
            from datetime import timezone
            start_time = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
            
            logger.info(f"📡 Querying CloudTrail for IAM events since {start_time}")
            
            events = []
            paginator = self.cloudtrail.get_paginator('lookup_events')
            
            # Query CloudTrail for all IAM events
            for page in paginator.paginate(
                StartTime=start_time,
                MaxResults=max_results
            ):
                for event in page.get('Events', []):
                    event_name = event.get('EventName')
                    
                    # Filter for monitored events
                    if event_name in self.MONITORED_EVENTS:
                        events.append({
                            'event_id': event.get('EventId'),
                            'event_name': event_name,
                            'event_time': event.get('EventTime'),
                            'username': event.get('Username'),
                            'resources': event.get('Resources', []),
                            'cloud_trail_event': event.get('CloudTrailEvent'),
                            'read_only': event.get('ReadOnly', True),
                        })
            
            logger.info(f"✅ Found {len(events)} relevant IAM events")
            return events
            
        except ClientError as e:
            logger.error(f"❌ CloudTrail query failed: {e}")
            return []
        except Exception as e:
            logger.error(f"❌ Unexpected error: {e}", exc_info=True)
            return []
    
    def analyze_event_impact(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze if an IAM event creates new privilege escalation risks
        
        Args:
            event: CloudTrail event dict
            
        Returns:
            Impact analysis or None if no new risk
        """
        try:
            event_name = event['event_name']
            username = event.get('username')
            resources = event.get('resources', [])
            
            logger.info(f"🔍 Analyzing event: {event_name} by {username}")
            
            # Extract affected principal (prefer ARN over UserID)
            principal_arn = None
            user_name = None
            
            # First pass: look for ARN
            for resource in resources:
                resource_type = resource.get('ResourceType')
                resource_name = resource.get('ResourceName', '')
                
                if resource_type in ['AWS::IAM::User', 'AWS::IAM::Role']:
                    # Prefer ARN format (contains /)
                    if '/' in resource_name or ':' in resource_name:
                        principal_arn = resource_name
                        # Extract username from ARN (arn:aws:iam::123:user/username)
                        if '/' in resource_name:
                            user_name = resource_name.split('/')[-1]
                        break
            
            # Second pass: if no ARN found, get the plain username
            if not principal_arn:
                for resource in resources:
                    resource_type = resource.get('ResourceType')
                    resource_name = resource.get('ResourceName', '')
                    
                    if resource_type in ['AWS::IAM::User', 'AWS::IAM::Role']:
                        # Skip UserIDs (start with AIDA/AROA)
                        if not resource_name.startswith(('AIDA', 'AROA', 'AIDAI', 'AROAI')):
                            user_name = resource_name
                            principal_arn = resource_name
                            break
            
            if not principal_arn:
                logger.debug(f"No principal found in event {event['event_id']}")
                return None
            
            # Determine risk level based on event type
            risk_level = self._assess_risk_level(event_name)
            
            # Use extracted username for display, or fall back to principal_arn
            display_name = user_name if user_name else principal_arn
            
            return {
                'event_id': event['event_id'],
                'event_name': event_name,
                'event_time': event['event_time'],
                'principal': principal_arn,
                'username': username,
                'risk_level': risk_level,
                'description': self._get_event_description(event_name, display_name),
                'requires_scan': self._requires_full_scan(event_name),
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze event: {e}", exc_info=True)
            return None
    
    def _assess_risk_level(self, event_name: str) -> str:
        """Assess risk level based on event type"""
        high_risk_events = [
            'AttachUserPolicy',
            'PutUserPolicy',
            'AttachRolePolicy',
            'PutRolePolicy',
            'UpdateAssumeRolePolicy',
            'SetDefaultPolicyVersion',
        ]
        
        if event_name in high_risk_events:
            return 'HIGH'
        return 'MEDIUM'
    
    def _get_event_description(self, event_name: str, principal: str) -> str:
        """Generate human-readable event description"""
        principal_name = principal.split('/')[-1] if '/' in principal else principal
        
        descriptions = {
            # User events
            'CreateUser': f"New IAM user created: {principal_name}",
            'DeleteUser': f"IAM user deleted: {principal_name}",
            'AttachUserPolicy': f"Policy attached to user: {principal_name}",
            'DetachUserPolicy': f"Policy detached from user: {principal_name}",
            'PutUserPolicy': f"Inline policy added to user: {principal_name}",
            'DeleteUserPolicy': f"Inline policy removed from user: {principal_name}",
            'AddUserToGroup': f"User added to group: {principal_name}",
            'RemoveUserFromGroup': f"User removed from group: {principal_name}",
            # Role events
            'CreateRole': f"New IAM role created: {principal_name}",
            'DeleteRole': f"IAM role deleted: {principal_name}",
            'AttachRolePolicy': f"Policy attached to role: {principal_name}",
            'DetachRolePolicy': f"Policy detached from role: {principal_name}",
            'PutRolePolicy': f"Inline policy added to role: {principal_name}",
            'DeleteRolePolicy': f"Inline policy removed from role: {principal_name}",
            'UpdateAssumeRolePolicy': f"Trust policy modified on role: {principal_name}",
            # Access key events
            'CreateAccessKey': f"Access key created for: {principal_name}",
            'DeleteAccessKey': f"Access key deleted for: {principal_name}",
            # Group events
            'PutGroupPolicy': f"Inline policy added to group: {principal_name}",
            'DeleteGroupPolicy': f"Inline policy removed from group: {principal_name}",
            'AttachGroupPolicy': f"Policy attached to group: {principal_name}",
            'DetachGroupPolicy': f"Policy detached from group: {principal_name}",
        }
        
        return descriptions.get(event_name, f"IAM change: {event_name} on {principal_name}")
    
    def _requires_full_scan(self, event_name: str) -> bool:
        """Determine if event requires full privilege scan"""
        # Events that definitely need a scan
        scan_required_events = [
            'AttachUserPolicy',
            'PutUserPolicy',
            'AttachRolePolicy',
            'PutRolePolicy',
            'UpdateAssumeRolePolicy',
        ]
        return event_name in scan_required_events
    
    def monitor_and_analyze(self, lookback_minutes: int = 5) -> List[Dict[str, Any]]:
        """
        Full monitoring workflow: get events and analyze impact
        
        Returns:
            List of security-relevant event impacts
        """
        logger.info("🚀 Starting CloudTrail monitoring cycle")
        
        # Get recent events
        events = self.get_recent_iam_events(lookback_minutes=lookback_minutes)
        
        # Analyze each event
        impacts = []
        for event in events:
            impact = self.analyze_event_impact(event)
            if impact:
                impacts.append(impact)
        
        logger.info(f"📊 Found {len(impacts)} security-relevant changes")
        return impacts


def test_monitor():
    """Test CloudTrail monitoring"""
    import sys
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    profile = sys.argv[1] if len(sys.argv) > 1 else 'default'
    
    print(f"\n🔍 Testing CloudTrail Monitor with profile: {profile}\n")
    
    monitor = CloudTrailMonitor(profile_name=profile)
    impacts = monitor.monitor_and_analyze(lookback_minutes=60)
    
    print(f"\n📋 Found {len(impacts)} IAM changes:\n")
    for impact in impacts:
        print(f"  🕐 {impact['event_time']}")
        print(f"     {impact['description']}")
        print(f"     Risk: {impact['risk_level']}")
        print(f"     Scan required: {impact['requires_scan']}")
        print()


if __name__ == '__main__':
    test_monitor()
