"""
State Diff Engine

Compares current AWS IAM state with proposed Terraform changes
to calculate what will change if the PR is merged.

This is the core of PR simulation - understanding the delta.
"""

import json
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field
from copy import deepcopy


@dataclass
class PermissionDiff:
    """Represents a change in permissions"""
    principal: str  # ARN of user/role
    principal_name: str  # Human-readable name
    added_permissions: List[str] = field(default_factory=list)
    removed_permissions: List[str] = field(default_factory=list)
    
    @property
    def is_escalation(self) -> bool:
        """Check if this is a privilege escalation (more permissions added than removed)"""
        return len(self.added_permissions) > len(self.removed_permissions)
    
    @property
    def net_change(self) -> int:
        """Net change in permission count"""
        return len(self.added_permissions) - len(self.removed_permissions)


@dataclass
class StateDiff:
    """Complete diff between current and proposed IAM state"""
    new_principals: List[str] = field(default_factory=list)  # Users/roles being created
    deleted_principals: List[str] = field(default_factory=list)  # Users/roles being deleted
    modified_principals: List[PermissionDiff] = field(default_factory=list)  # Users/roles with changed permissions
    new_policies: Dict[str, Dict] = field(default_factory=dict)  # New managed policies
    modified_policies: Dict[str, Dict] = field(default_factory=dict)  # Modified managed policies
    
    @property
    def has_critical_changes(self) -> bool:
        """Check if diff contains critical security changes"""
        return (
            len(self.new_principals) > 0 or
            any(diff.is_escalation for diff in self.modified_principals) or
            len(self.new_policies) > 0
        )
    
    @property
    def summary(self) -> str:
        """Human-readable summary"""
        parts = []
        if self.new_principals:
            parts.append(f"{len(self.new_principals)} new principals")
        if self.deleted_principals:
            parts.append(f"{len(self.deleted_principals)} deleted principals")
        if self.modified_principals:
            parts.append(f"{len(self.modified_principals)} modified principals")
        
        return ", ".join(parts) if parts else "No changes"


class StateDiffEngine:
    """Calculate diff between current AWS state and proposed Terraform changes"""
    
    def __init__(self):
        self.current_state: Dict[str, Any] = {}
        self.proposed_state: Dict[str, Any] = {}
        self.account_id: str = '*'  # Will be set from scan metadata
    
    def load_current_state(self, scan_output_path: str):
        """Load current AWS state from Heimdall scan output"""
        with open(scan_output_path, 'r') as f:
            data = json.load(f)
        
        # Extract account ID from metadata
        if 'metadata' in data and 'account_id' in data['metadata']:
            self.account_id = data['metadata']['account_id']
        
        self.current_state = self._normalize_scan_output(data)
    
    def apply_terraform_changes(self, terraform_summary) -> Dict[str, Any]:
        """Apply Terraform changes to current state to get proposed state"""
        # Start with copy of current state
        self.proposed_state = deepcopy(self.current_state)
        
        # Apply each change
        for change in terraform_summary.all_changes:
            if change.action == 'create':
                self._apply_create(change)
            elif change.action == 'delete':
                self._apply_delete(change)
            elif change.action == 'update':
                self._apply_update(change)
        
        return self.proposed_state
    
    def calculate_diff(self) -> StateDiff:
        """Calculate diff between current and proposed state"""
        diff = StateDiff()
        
        # Find new principals
        current_principals = set(self.current_state.get('principals', {}).keys())
        proposed_principals = set(self.proposed_state.get('principals', {}).keys())
        
        diff.new_principals = list(proposed_principals - current_principals)
        diff.deleted_principals = list(current_principals - proposed_principals)
        
        # Find modified principals
        for principal_arn in current_principals & proposed_principals:
            perm_diff = self._calculate_permission_diff(principal_arn)
            if perm_diff.added_permissions or perm_diff.removed_permissions:
                diff.modified_principals.append(perm_diff)
        
        # Find policy changes
        current_policies = self.current_state.get('policies', {})
        proposed_policies = self.proposed_state.get('policies', {})
        
        for policy_arn in set(proposed_policies.keys()) - set(current_policies.keys()):
            diff.new_policies[policy_arn] = proposed_policies[policy_arn]
        
        for policy_arn in set(proposed_policies.keys()) & set(current_policies.keys()):
            if proposed_policies[policy_arn] != current_policies[policy_arn]:
                diff.modified_policies[policy_arn] = {
                    'before': current_policies[policy_arn],
                    'after': proposed_policies[policy_arn]
                }
        
        return diff
    
    def _normalize_scan_output(self, scan_data: Dict) -> Dict[str, Any]:
        """
        Normalize Heimdall scan output to internal format.
        
        Extracts principals and their permissions from either:
        - graph.nodes (if available) - FULL ACCURACY with complete policy data
        - findings (fallback) - BEST EFFORT with aggregated required_actions
        """
        normalized = {
            'principals': {}
        }
        
        # Extract from graph if available (PREFERRED - Full accuracy)
        if 'graph' in scan_data and scan_data['graph'] and 'nodes' in scan_data['graph']:
            nodes = scan_data['graph']['nodes']
            # Handle both dict and list formats
            if isinstance(nodes, dict):
                nodes_iter = nodes.items()
            else:
                # List format: use node['id'] as key
                nodes_iter = [(node.get('id', f"node_{i}"), node) for i, node in enumerate(nodes)]
            
            for node_id, node_data in nodes_iter:
                if node_data.get('type') in ['user', 'role']:
                    # Full policy data extraction
                    normalized['principals'][node_id] = {
                        'type': node_data['type'],
                        'name': node_data.get('name', node_id),
                        'permissions': self._extract_permissions_from_policies(node_data),
                        'attached_policies': node_data.get('attached_policies', []),
                        'inline_policies': node_data.get('inline_policies', {}),
                        'policy_source': 'graph',  # Track data source
                        'removed_permissions': []
                    }
        
        # Fallback: Extract principals from findings (for scan outputs without graph)
        elif 'findings' in scan_data:
            principals_map = {}
            
            # First pass: Collect ALL findings per principal to build complete permission set
            for finding in scan_data['findings']:
                principal = finding.get('principal', '')
                principal_name = finding.get('principal_name', principal)
                principal_type = finding.get('principal_type', 'unknown')
                
                if not principal:
                    continue
                
                if principal not in principals_map:
                    principals_map[principal] = {
                        'type': principal_type,
                        'name': principal_name,
                        'permissions': set(),  # Use set to avoid duplicates
                        'findings': [],  # Track all findings
                        'removed_permissions': []  # Track permissions removed by Terraform
                    }
                
                # Aggregate permissions from ALL findings for this principal
                required_actions = finding.get('required_actions', [])
                principals_map[principal]['permissions'].update(required_actions)
                principals_map[principal]['findings'].append(finding)
            
            # Convert sets to lists for JSON serialization
            for principal_arn, data in principals_map.items():
                data['permissions'] = list(data['permissions'])
            
            normalized['principals'] = principals_map
        
        return normalized
    
    def _extract_permissions_from_policies(self, node_data: Dict) -> List[str]:
        """
        Extract ALL permissions from attached and inline policies.
        This provides complete permission set for accurate diff calculation.
        """
        permissions = set()
        
        # Extract from inline policies (full policy documents available)
        inline_policies = node_data.get('inline_policies', {})
        for policy_name, policy_doc in inline_policies.items():
            if isinstance(policy_doc, dict):
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            permissions.add(actions)
                        elif isinstance(actions, list):
                            permissions.update(actions)
        
        # Extract from attached managed policies (NOW WITH FULL DOCUMENTS!)
        attached = node_data.get('attached_policies', [])
        for policy_info in attached:
            policy_doc = policy_info.get('PolicyDocument')
            if isinstance(policy_doc, dict):
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            permissions.add(actions)
                        elif isinstance(actions, list):
                            permissions.update(actions)
        
        return list(permissions)
    
    def _extract_permissions(self, node_data: Dict) -> List[str]:
        """Extract permission list from node data (legacy fallback)"""
        permissions = []
        
        # Extract from attached policies
        for policy in node_data.get('attached_policies', []):
            if 'statements' in policy:
                for stmt in policy['statements']:
                    if stmt.get('Effect') == 'Allow':
                        actions = stmt.get('Action', [])
                        if isinstance(actions, str):
                            permissions.append(actions)
                        else:
                            permissions.extend(actions)
        
        return list(set(permissions))  # Deduplicate
    
    def _calculate_permission_diff(self, principal_arn: str) -> PermissionDiff:
        """Calculate permission diff for a single principal"""
        current_perms = set(
            self.current_state['principals'][principal_arn].get('permissions', [])
        )
        proposed_perms = set(
            self.proposed_state['principals'][principal_arn].get('permissions', [])
        )
        
        return PermissionDiff(
            principal=principal_arn,
            principal_name=self.current_state['principals'][principal_arn].get('name', principal_arn),
            added_permissions=list(proposed_perms - current_perms),
            removed_permissions=list(current_perms - proposed_perms)
        )
    
    def _apply_create(self, change):
        """Apply a CREATE change to proposed state"""
        if change.resource_type == 'aws_iam_user':
            user_name = change.after.get('name', change.resource_name)
            principal_arn = f"arn:aws:iam::{self.account_id}:user/{user_name}"
            
            self.proposed_state['principals'][principal_arn] = {
                'type': 'user',
                'name': user_name,
                'permissions': [],
                'tags': change.after.get('tags', {}),
                'terraform_modified': True,  # New principal
                'removed_permissions': []  # Track permissions removed by Terraform
            }
        
        elif change.resource_type == 'aws_iam_role':
            role_name = change.after.get('name', change.resource_name)
            principal_arn = f"arn:aws:iam::{self.account_id}:role/{role_name}"
            
            self.proposed_state['principals'][principal_arn] = {
                'type': 'role',
                'name': role_name,
                'permissions': [],
                'assume_role_policy': change.after.get('assume_role_policy', {}),
                'terraform_modified': True  # New principal
            }
        
        elif change.resource_type in ['aws_iam_user_policy', 'aws_iam_role_policy']:
            # Add inline policy permissions
            self._add_inline_policy_permissions(change)
    
    def _apply_delete(self, change):
        """Apply a DELETE change to proposed state"""
        if change.resource_type == 'aws_iam_user':
            user_name = change.before.get('name', change.resource_name)
            principal_arn = f"arn:aws:iam::{self.account_id}:user/{user_name}"
            self.proposed_state['principals'].pop(principal_arn, None)
        
        elif change.resource_type == 'aws_iam_role':
            role_name = change.before.get('name', change.resource_name)
            principal_arn = f"arn:aws:iam::{self.account_id}:role/{role_name}"
            self.proposed_state['principals'].pop(principal_arn, None)
        
        elif change.resource_type in ['aws_iam_user_policy', 'aws_iam_role_policy']:
            # Remove inline policy permissions
            self._remove_inline_policy_permissions(change)
    
    def _apply_update(self, change):
        """Apply an UPDATE change to proposed state"""
        # For updates, we need to modify the existing principal
        if change.resource_type in ['aws_iam_user_policy', 'aws_iam_role_policy']:
            self._update_inline_policy_permissions(change)
    
    def _add_inline_policy_permissions(self, change):
        """Add permissions from inline policy to principal"""
        if change.resource_type == 'aws_iam_user_policy':
            user_name = change.after.get('user')
            principal_arn = f"arn:aws:iam::{self.account_id}:user/{user_name}"
        elif change.resource_type == 'aws_iam_role_policy':
            role_name = change.after.get('role')
            principal_arn = f"arn:aws:iam::{self.account_id}:role/{role_name}"
        else:
            return
        
        if principal_arn not in self.proposed_state['principals']:
            return
        
        # Parse policy document
        policy_str = change.after.get('policy', '')
        if isinstance(policy_str, str):
            try:
                policy_doc = json.loads(policy_str)
                permissions = self._extract_permissions_from_policy(policy_doc)
                
                current_perms = self.proposed_state['principals'][principal_arn].get('permissions', [])
                self.proposed_state['principals'][principal_arn]['permissions'] = list(
                    set(current_perms + permissions)
                )
                # Mark as modified by Terraform
                self.proposed_state['principals'][principal_arn]['terraform_modified'] = True
            except json.JSONDecodeError:
                pass
    
    def _remove_inline_policy_permissions(self, change):
        """
        Remove permissions from deleted inline policy.
        
        POLICY-AWARE: Only marks permissions as removed if they're not
        provided by other policies on the same principal.
        """
        if change.resource_type == 'aws_iam_user_policy':
            user_name = change.before.get('user')
            principal_arn = f"arn:aws:iam::{self.account_id}:user/{user_name}"
        elif change.resource_type == 'aws_iam_role_policy':
            role_name = change.before.get('role')
            principal_arn = f"arn:aws:iam::{self.account_id}:role/{role_name}"
        else:
            return
        
        if principal_arn not in self.proposed_state['principals']:
            return
        
        principal_data = self.proposed_state['principals'][principal_arn]
        policy_source = principal_data.get('policy_source', 'findings')
        
        # Parse policy document from 'before' state
        policy_str = change.before.get('policy', '')
        if isinstance(policy_str, str):
            try:
                policy_doc = json.loads(policy_str)
                permissions_from_deleted_policy = self._extract_permissions_from_policy(policy_doc)
                
                if policy_source == 'graph':
                    # FULL ACCURACY: Check remaining policies (inline + managed)
                    policy_name = change.before.get('name', change.resource_name)
                    
                    # Remove this policy from inline_policies
                    inline_policies = principal_data.get('inline_policies', {})
                    if policy_name in inline_policies:
                        del inline_policies[policy_name]
                    
                    # Recalculate permissions from ALL remaining policies
                    remaining_permissions = set()
                    
                    # From remaining inline policies
                    for remaining_policy_name, remaining_policy_doc in inline_policies.items():
                        if isinstance(remaining_policy_doc, dict):
                            for statement in remaining_policy_doc.get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    if isinstance(actions, str):
                                        remaining_permissions.add(actions)
                                    elif isinstance(actions, list):
                                        remaining_permissions.update(actions)
                    
                    # From managed policies (CRITICAL!)
                    attached_policies = principal_data.get('attached_policies', [])
                    for policy_info in attached_policies:
                        policy_doc = policy_info.get('PolicyDocument')
                        if isinstance(policy_doc, dict):
                            for statement in policy_doc.get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    if isinstance(actions, str):
                                        remaining_permissions.add(actions)
                                    elif isinstance(actions, list):
                                        remaining_permissions.update(actions)
                    
                    # Truly removed permissions = deleted - still_present
                    truly_removed = [p for p in permissions_from_deleted_policy 
                                   if p not in remaining_permissions]
                    
                    # Track truly removed permissions
                    removed_perms_list = principal_data.get('removed_permissions', [])
                    removed_perms_list.extend(truly_removed)
                    principal_data['removed_permissions'] = removed_perms_list
                    
                    # Update principal's permission list
                    principal_data['permissions'] = list(remaining_permissions)
                
                else:
                    # BEST EFFORT: Assume all permissions from policy are removed
                    removed_perms_list = principal_data.get('removed_permissions', [])
                    removed_perms_list.extend(permissions_from_deleted_policy)
                    principal_data['removed_permissions'] = removed_perms_list
                    
                    # Remove these permissions from principal
                    current_perms = principal_data.get('permissions', [])
                    updated_perms = [p for p in current_perms if p not in permissions_from_deleted_policy]
                    principal_data['permissions'] = updated_perms
                
                # Mark as modified by Terraform
                principal_data['terraform_modified'] = True
                
            except json.JSONDecodeError:
                pass
    
    def _update_inline_policy_permissions(self, change):
        """
        Update permissions from modified inline policy.
        
        DIFF-AWARE: Detects both added and removed permissions
        when a policy is updated (e.g., tightening permissions).
        """
        if change.resource_type == 'aws_iam_user_policy':
            user_name = change.after.get('user')
            principal_arn = f"arn:aws:iam::{self.account_id}:user/{user_name}"
        elif change.resource_type == 'aws_iam_role_policy':
            role_name = change.after.get('role')
            principal_arn = f"arn:aws:iam::{self.account_id}:role/{role_name}"
        else:
            return
        
        if principal_arn not in self.proposed_state['principals']:
            return
        
        principal_data = self.proposed_state['principals'][principal_arn]
        policy_source = principal_data.get('policy_source', 'findings')
        
        # Parse before and after policy documents
        before_str = change.before.get('policy', '')
        after_str = change.after.get('policy', '')
        
        if isinstance(before_str, str) and isinstance(after_str, str):
            try:
                before_doc = json.loads(before_str)
                after_doc = json.loads(after_str)
                
                before_perms = set(self._extract_permissions_from_policy(before_doc))
                after_perms = set(self._extract_permissions_from_policy(after_doc))
                
                # Calculate diff
                added_perms = after_perms - before_perms
                removed_perms = before_perms - after_perms
                
                if policy_source == 'graph':
                    # FULL ACCURACY: Update policy document and recalculate
                    policy_name = change.after.get('name', change.resource_name)
                    inline_policies = principal_data.get('inline_policies', {})
                    
                    # Update the policy document
                    inline_policies[policy_name] = after_doc
                    
                    # Recalculate all permissions from ALL policies (inline + managed)
                    all_permissions = set()
                    
                    # From inline policies
                    for policy_doc in inline_policies.values():
                        if isinstance(policy_doc, dict):
                            for statement in policy_doc.get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    if isinstance(actions, str):
                                        all_permissions.add(actions)
                                    elif isinstance(actions, list):
                                        all_permissions.update(actions)
                    
                    # From managed policies (CRITICAL!)
                    attached_policies = principal_data.get('attached_policies', [])
                    for policy_info in attached_policies:
                        policy_doc = policy_info.get('PolicyDocument')
                        if isinstance(policy_doc, dict):
                            for statement in policy_doc.get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    if isinstance(actions, str):
                                        all_permissions.add(actions)
                                    elif isinstance(actions, list):
                                        all_permissions.update(actions)
                    
                    # Check if removed permissions truly gone (not in other policies)
                    truly_removed = [p for p in removed_perms if p not in all_permissions]
                    
                    # Track truly removed permissions
                    removed_perms_list = principal_data.get('removed_permissions', [])
                    removed_perms_list.extend(truly_removed)
                    principal_data['removed_permissions'] = removed_perms_list
                    
                    # Update principal's permission list
                    principal_data['permissions'] = list(all_permissions)
                
                else:
                    # BEST EFFORT: Simple diff
                    removed_perms_list = principal_data.get('removed_permissions', [])
                    removed_perms_list.extend(list(removed_perms))
                    principal_data['removed_permissions'] = removed_perms_list
                    
                    # Update permissions
                    current_perms = set(principal_data.get('permissions', []))
                    current_perms -= removed_perms
                    current_perms |= added_perms
                    principal_data['permissions'] = list(current_perms)
                
                # Mark as modified by Terraform
                principal_data['terraform_modified'] = True
                
            except json.JSONDecodeError:
                pass
    
    def _extract_permissions_from_policy(self, policy_doc: Dict) -> List[str]:
        """Extract action list from IAM policy document"""
        permissions = []
        
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    permissions.append(actions)
                else:
                    permissions.extend(actions)
        
        return permissions
    
    def format_diff(self, diff: StateDiff) -> str:
        """Format diff as human-readable text"""
        lines = []
        lines.append("📊 IAM State Diff")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Summary: {diff.summary}")
        lines.append("")
        
        if diff.new_principals:
            lines.append("➕ New Principals:")
            for arn in diff.new_principals:
                lines.append(f"  - {arn}")
            lines.append("")
        
        if diff.deleted_principals:
            lines.append("➖ Deleted Principals:")
            for arn in diff.deleted_principals:
                lines.append(f"  - {arn}")
            lines.append("")
        
        if diff.modified_principals:
            lines.append("🔄 Modified Principals:")
            for perm_diff in diff.modified_principals:
                lines.append(f"  {perm_diff.principal_name}:")
                if perm_diff.added_permissions:
                    lines.append(f"    + {len(perm_diff.added_permissions)} new permissions")
                if perm_diff.removed_permissions:
                    lines.append(f"    - {len(perm_diff.removed_permissions)} removed permissions")
            lines.append("")
        
        if diff.has_critical_changes:
            lines.append("⚠️  CRITICAL: This change contains security-sensitive modifications!")
        else:
            lines.append("✅ No critical security changes detected")
        
        return "\n".join(lines)


# Quick test
def main():
    """Test the diff engine"""
    import sys
    from .terraform_parser import TerraformParser
    
    if len(sys.argv) < 3:
        print("Usage: python state_diff.py <current-scan.json> <tfplan.json>")
        sys.exit(1)
    
    # Parse Terraform plan
    parser = TerraformParser()
    tf_summary = parser.parse_plan_file(sys.argv[2])
    
    print(parser.format_summary(tf_summary))
    print()
    
    # Calculate diff
    engine = StateDiffEngine()
    engine.load_current_state(sys.argv[1])
    engine.apply_terraform_changes(tf_summary)
    diff = engine.calculate_diff()
    
    print(engine.format_diff(diff))


if __name__ == '__main__':
    main()
