"""
Service Control Policy (SCP) Resolver

v1.0.0 - Evaluates AWS Organizations SCPs to determine if actions are blocked
"""

from typing import List, Dict, Any, Set, Optional
import fnmatch


class SCPResolver:
    """
    Evaluates Service Control Policies to determine effective permissions.
    
    SCPs work as permission boundaries - they can deny but not grant access.
    An explicit SCP Deny overrides any IAM Allow.
    
    Implementation Notes:
    - v1.0.0: Supports Deny statements only (most common use case)
    - Action matching supports wildcards (iam:*, *)
    - Resource matching simplified (focuses on action denial)
    - Condition blocks not yet supported (Phase 2)
    """
    
    def __init__(self, scp_policies: List[Dict[str, Any]] = None):
        """
        Initialize SCP resolver with organization policies.
        
        Args:
            scp_policies: List of SCP policy documents with structure:
                [
                    {
                        "PolicyId": "scp-123",
                        "Name": "DenyDangerousActions",
                        "TargetType": "ACCOUNT",  # or "OU"
                        "TargetId": "123456789012",
                        "Content": {
                            "Version": "2012-10-17",
                            "Statement": [...]
                        }
                    }
                ]
        """
        self.scp_policies = scp_policies or []
        
        # Build account -> deny actions index for fast lookup
        self._account_denies = self._build_deny_index()
    
    def _build_deny_index(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Build index of deny statements per account.
        
        Returns:
            {
                "123456789012": [
                    {
                        "policy_name": "DenyDangerousIAM",
                        "actions": ["iam:AttachUserPolicy", "iam:*"],
                        "resources": ["*"]
                    }
                ]
            }
        """
        index = {}
        
        for policy in self.scp_policies:
            target_type = policy.get('TargetType')
            target_id = policy.get('TargetId')
            policy_name = policy.get('Name', 'Unknown')
            content = policy.get('Content', {})
            
            # Only handle account-level SCPs for now
            if target_type != 'ACCOUNT':
                continue
            
            if target_id not in index:
                index[target_id] = []
            
            # Extract Deny statements
            for statement in content.get('Statement', []):
                if statement.get('Effect') != 'Deny':
                    continue
                
                # Get actions (can be string or list)
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                # Get resources (can be string or list)
                resources = statement.get('Resource', ['*'])
                if isinstance(resources, str):
                    resources = [resources]
                
                index[target_id].append({
                    'policy_name': policy_name,
                    'policy_id': policy.get('PolicyId'),
                    'actions': actions,
                    'resources': resources
                })
        
        return index
    
    def is_action_blocked(
        self, 
        account_id: str, 
        action: str, 
        resource: str = "*"
    ) -> bool:
        """
        Check if an action is blocked by SCP in the given account.
        
        Args:
            account_id: Target AWS account ID (12 digits)
            action: IAM action to check (e.g., "iam:AttachUserPolicy")
            resource: Resource ARN (default "*", resource matching simplified in v1.0)
        
        Returns:
            True if action is explicitly denied by any SCP
        """
        if account_id not in self._account_denies:
            return False
        
        for deny_rule in self._account_denies[account_id]:
            # Check if action matches any deny pattern
            for deny_action in deny_rule['actions']:
                if self._action_matches(action, deny_action):
                    # v1.0: Simplified - if action matches, consider it blocked
                    # Phase 2 can add resource matching logic
                    return True
        
        return False
    
    def get_blocking_policies(
        self,
        account_id: str,
        actions: List[str]
    ) -> List[str]:
        """
        Get list of SCP policy names that block any of the given actions.
        
        Args:
            account_id: Target AWS account ID
            actions: List of IAM actions to check
        
        Returns:
            List of policy names that deny these actions
        """
        if account_id not in self._account_denies:
            return []
        
        blocking_policies = set()
        
        for action in actions:
            for deny_rule in self._account_denies[account_id]:
                for deny_action in deny_rule['actions']:
                    if self._action_matches(action, deny_action):
                        blocking_policies.add(deny_rule['policy_name'])
        
        return list(blocking_policies)
    
    def _action_matches(self, action: str, pattern: str) -> bool:
        """
        Check if action matches pattern with wildcard support.
        
        Examples:
            iam:AttachUserPolicy matches iam:AttachUserPolicy -> True
            iam:AttachUserPolicy matches iam:* -> True
            iam:AttachUserPolicy matches * -> True
            s3:GetObject matches iam:* -> False
        
        Args:
            action: Specific IAM action (e.g., "iam:AttachUserPolicy")
            pattern: Pattern with wildcards (e.g., "iam:*" or "*")
        
        Returns:
            True if action matches pattern
        """
        # Exact match
        if action == pattern:
            return True
        
        # Wildcard match using fnmatch (shell-style wildcards)
        return fnmatch.fnmatch(action, pattern)
    
    def are_all_actions_blocked(
        self,
        account_id: str,
        actions: List[str]
    ) -> bool:
        """
        Check if ALL actions in list are blocked.
        
        Useful for pattern detection: if a privesc pattern requires multiple
        actions (e.g., iam:PassRole + lambda:CreateFunction), only block if
        ALL are denied.
        
        Args:
            account_id: Target AWS account ID
            actions: List of required actions for a privesc pattern
        
        Returns:
            True if ALL actions are blocked by SCP
        """
        if not actions:
            return False
        
        for action in actions:
            if not self.is_action_blocked(account_id, action):
                return False
        
        return True
    
    def is_any_action_blocked(
        self,
        account_id: str,
        actions: List[str]
    ) -> bool:
        """
        Check if ANY action in list is blocked.
        
        More conservative approach: if any action is denied, consider
        the entire pattern blocked.
        
        Args:
            account_id: Target AWS account ID
            actions: List of actions
        
        Returns:
            True if at least one action is blocked
        """
        for action in actions:
            if self.is_action_blocked(account_id, action):
                return True
        
        return False
