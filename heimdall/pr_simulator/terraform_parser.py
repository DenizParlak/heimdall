"""
Terraform Plan Parser

Extracts IAM-related changes from Terraform plan JSON output.

Usage:
    terraform plan -out=tfplan
    terraform show -json tfplan > tfplan.json
    
    parser = TerraformParser()
    changes = parser.parse_plan_file('tfplan.json')
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class IAMChange:
    """Represents a single IAM-related change in Terraform plan"""
    resource_type: str  # aws_iam_user, aws_iam_role, aws_iam_policy, etc.
    resource_name: str  # Terraform resource name
    action: str  # create, update, delete, no-op
    before: Optional[Dict]  # State before change
    after: Optional[Dict]  # State after change
    address: str  # Full resource address in Terraform


@dataclass
class TerraformPlanSummary:
    """Summary of all IAM changes in a Terraform plan"""
    iam_users: List[IAMChange]
    iam_roles: List[IAMChange]
    iam_policies: List[IAMChange]
    iam_policy_attachments: List[IAMChange]
    iam_role_policies: List[IAMChange]
    iam_user_policies: List[IAMChange]
    iam_group_policies: List[IAMChange]
    all_changes: List[IAMChange]
    
    @property
    def total_changes(self) -> int:
        return len(self.all_changes)
    
    @property
    def has_critical_changes(self) -> bool:
        """Check if plan contains high-risk IAM changes"""
        critical_types = [
            'aws_iam_user',
            'aws_iam_role',
            'aws_iam_policy',
            'aws_iam_policy_attachment',
            'aws_iam_role_policy',
            'aws_iam_user_policy'
        ]
        return any(c.resource_type in critical_types for c in self.all_changes)


class TerraformParser:
    """Parse Terraform plan JSON to extract IAM changes"""
    
    # IAM resource types we care about
    IAM_RESOURCE_TYPES = {
        'aws_iam_user',
        'aws_iam_role',
        'aws_iam_policy',
        'aws_iam_policy_attachment',
        'aws_iam_role_policy',
        'aws_iam_user_policy',
        'aws_iam_group_policy',
        'aws_iam_group',
        'aws_iam_role_policy_attachment',
        'aws_iam_user_policy_attachment',
        'aws_iam_group_policy_attachment',
        'aws_iam_access_key',
        'aws_iam_user_login_profile',
    }
    
    def parse_plan_file(self, plan_path: str) -> TerraformPlanSummary:
        """Parse Terraform plan JSON file"""
        with open(plan_path, 'r') as f:
            plan_data = json.load(f)
        
        return self.parse_plan(plan_data)
    
    def parse_plan(self, plan_data: Dict[str, Any]) -> TerraformPlanSummary:
        """Parse Terraform plan JSON data"""
        
        changes = []
        
        # Extract resource changes
        resource_changes = plan_data.get('resource_changes', [])
        
        for resource in resource_changes:
            resource_type = resource.get('type', '')
            
            # Only process IAM resources
            if resource_type not in self.IAM_RESOURCE_TYPES:
                continue
            
            # Extract change details
            change = resource.get('change', {})
            actions = change.get('actions', [])
            
            # Determine primary action
            if 'create' in actions:
                action = 'create'
            elif 'delete' in actions:
                action = 'delete'
            elif 'update' in actions:
                action = 'update'
            elif 'no-op' in actions:
                action = 'no-op'
            else:
                action = 'unknown'
            
            # Create IAMChange object
            iam_change = IAMChange(
                resource_type=resource_type,
                resource_name=resource.get('name', ''),
                action=action,
                before=change.get('before'),
                after=change.get('after'),
                address=resource.get('address', '')
            )
            
            changes.append(iam_change)
        
        # Categorize changes
        return TerraformPlanSummary(
            iam_users=self._filter_by_type(changes, 'aws_iam_user'),
            iam_roles=self._filter_by_type(changes, 'aws_iam_role'),
            iam_policies=self._filter_by_type(changes, 'aws_iam_policy'),
            iam_policy_attachments=self._filter_by_type(changes, 'aws_iam_policy_attachment'),
            iam_role_policies=self._filter_by_type(changes, 'aws_iam_role_policy'),
            iam_user_policies=self._filter_by_type(changes, 'aws_iam_user_policy'),
            iam_group_policies=self._filter_by_type(changes, 'aws_iam_group_policy'),
            all_changes=changes
        )
    
    def _filter_by_type(self, changes: List[IAMChange], resource_type: str) -> List[IAMChange]:
        """Filter changes by resource type"""
        return [c for c in changes if c.resource_type == resource_type]
    
    def extract_policy_document(self, change: IAMChange) -> Optional[Dict]:
        """Extract IAM policy document from a change"""
        
        # For inline policies
        if change.resource_type in ['aws_iam_role_policy', 'aws_iam_user_policy', 'aws_iam_group_policy']:
            if change.after and 'policy' in change.after:
                policy_str = change.after['policy']
                if isinstance(policy_str, str):
                    try:
                        return json.loads(policy_str)
                    except json.JSONDecodeError:
                        return None
                return policy_str
        
        # For managed policies
        if change.resource_type == 'aws_iam_policy':
            if change.after and 'policy' in change.after:
                policy_str = change.after['policy']
                if isinstance(policy_str, str):
                    try:
                        return json.loads(policy_str)
                    except json.JSONDecodeError:
                        return None
                return policy_str
        
        # For assume role policy
        if change.resource_type == 'aws_iam_role':
            if change.after and 'assume_role_policy' in change.after:
                policy_str = change.after['assume_role_policy']
                if isinstance(policy_str, str):
                    try:
                        return json.loads(policy_str)
                    except json.JSONDecodeError:
                        return None
                return policy_str
        
        return None
    
    def get_changed_principals(self, summary: TerraformPlanSummary) -> List[str]:
        """Get list of IAM principals (users, roles) that are being changed"""
        principals = []
        
        for change in summary.iam_users:
            if change.action in ['create', 'update']:
                user_name = change.after.get('name') if change.after else change.resource_name
                principals.append(f"arn:aws:iam::*:user/{user_name}")
        
        for change in summary.iam_roles:
            if change.action in ['create', 'update']:
                role_name = change.after.get('name') if change.after else change.resource_name
                principals.append(f"arn:aws:iam::*:role/{role_name}")
        
        return principals
    
    def format_summary(self, summary: TerraformPlanSummary) -> str:
        """Format summary as human-readable text"""
        lines = []
        lines.append(f"📋 Terraform Plan IAM Changes Summary")
        lines.append(f"=" * 60)
        lines.append(f"")
        lines.append(f"Total IAM changes: {summary.total_changes}")
        lines.append(f"")
        
        if summary.iam_users:
            lines.append(f"👤 Users: {len(summary.iam_users)}")
            for c in summary.iam_users:
                lines.append(f"  - {c.action:8s} {c.resource_name}")
        
        if summary.iam_roles:
            lines.append(f"🎭 Roles: {len(summary.iam_roles)}")
            for c in summary.iam_roles:
                lines.append(f"  - {c.action:8s} {c.resource_name}")
        
        if summary.iam_policies:
            lines.append(f"📜 Policies: {len(summary.iam_policies)}")
            for c in summary.iam_policies:
                lines.append(f"  - {c.action:8s} {c.resource_name}")
        
        if summary.iam_policy_attachments:
            lines.append(f"📎 Policy Attachments: {len(summary.iam_policy_attachments)}")
            for c in summary.iam_policy_attachments:
                lines.append(f"  - {c.action:8s} {c.resource_name}")
        
        return "\n".join(lines)


# Quick test function
def main():
    """Test the parser with sample data"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python terraform_parser.py <tfplan.json>")
        sys.exit(1)
    
    parser = TerraformParser()
    summary = parser.parse_plan_file(sys.argv[1])
    
    print(parser.format_summary(summary))
    print()
    
    if summary.has_critical_changes:
        print("⚠️  CRITICAL: This plan contains IAM changes that should be reviewed!")
    else:
        print("✅ No critical IAM changes detected")


if __name__ == '__main__':
    main()
