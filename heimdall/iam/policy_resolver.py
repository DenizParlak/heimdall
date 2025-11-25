"""
IAM Policy Resolution Module

Combines all policies (managed + inline + group) attached to a principal
to produce effective permissions.
"""

from dataclasses import dataclass, field
from typing import List, Set, Dict, Any, Optional
import fnmatch


@dataclass
class PolicyStatement:
    """Single IAM policy statement"""
    effect: str  # "Allow" or "Deny"
    actions: Set[str]
    resources: Set[str]
    source_policy: str  # Name of the policy this came from
    not_actions: Set[str] = field(default_factory=set)  # Phase 2A-2 P3: NotAction support
    conditions: Dict[str, Any] = field(default_factory=dict)  # Phase 2A-2 P4: Condition support
    not_resources: Set[str] = field(default_factory=set)
    
    def matches_action(self, action: str) -> bool:
        """
        Check if this statement grants/denies the given action.
        Handles wildcards: iam:* matches iam:PassRole
        
        Phase 2A-2 P3: Supports NotAction
        - If NotAction is present, returns True if action is NOT in the list
        - Otherwise, returns True if action IS in the list
        """
        # NotAction: matches if action is NOT in the not_actions list
        if self.not_actions:
            for pattern in self.not_actions:
                if fnmatch.fnmatch(action.lower(), pattern.lower()):
                    # Action matches NotAction pattern, so statement does NOT apply
                    return False
            # Action doesn't match any NotAction pattern, so statement applies
            return True
        
        # Normal Action: matches if action IS in the actions list
        for pattern in self.actions:
            if fnmatch.fnmatch(action.lower(), pattern.lower()):
                return True
        return False
    
    def matches_resource(self, resource: str) -> bool:
        """
        Check if this statement applies to the given resource.
        
        Handles wildcards:
        - * matches everything
        - arn:aws:s3:::prod-* matches arn:aws:s3:::prod-bucket
        - arn:aws:iam::*:role/Admin* matches arn:aws:iam::123:role/AdminRole
        
        Phase 2A-2 P3: Resource ARN pattern matching
        """
        # NotResource semantics: statement applies to all resources that do NOT
        # match any NotResource pattern.
        if self.not_resources:
            for pattern in self.not_resources:
                # Direct or wildcard match
                if pattern == resource or fnmatch.fnmatch(resource, pattern):
                    return False
            # Resource did not match any NotResource pattern, so statement applies
            return True
        
        # If statement has no resource restriction, it applies to all resources
        if not self.resources or '*' in self.resources:
            return True
        
        # Check if resource matches any pattern in the statement
        for pattern in self.resources:
            # Direct match
            if pattern == resource:
                return True
            
            # Wildcard match using fnmatch (handles * and ?)
            if fnmatch.fnmatch(resource, pattern):
                return True
        
        return False

    def matches_conditions(self, context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if this statement's Condition block matches the given evaluation context.

        Notes:
        - If the statement has no Condition, it always matches.
        - If a Condition is present but no context is provided, we conservatively
          treat the statement as *not* applicable to avoid over-reporting privileges.
        - Only a small subset of operators is supported for now (StringEquals,
          StringLike, Bool, Null). Unknown operators cause the condition to fail.
        """

        # No conditions: applies in all contexts
        if not self.conditions:
            return True

        # With conditions but no context, be conservative and treat as non-matching
        if context is None:
            return False

        for operator, conds in self.conditions.items():
            if not isinstance(conds, dict):
                # Malformed condition block; fail-safe
                return False

            for key, expected in conds.items():
                actual = context.get(key)

                # Normalise expected values to list for easier handling
                expected_values = expected if isinstance(expected, list) else [expected]

                # StringEquals / StringEqualsIgnoreCase
                if operator in ("StringEquals", "StringEqualsIgnoreCase"):
                    if actual is None:
                        return False
                    actual_str = str(actual)
                    if operator == "StringEqualsIgnoreCase":
                        actual_str = actual_str.lower()
                        cmp_values = [str(v).lower() for v in expected_values]
                    else:
                        cmp_values = [str(v) for v in expected_values]
                    if actual_str not in cmp_values:
                        return False

                # StringLike (simple wildcard match using fnmatch)
                elif operator == "StringLike":
                    if actual is None:
                        return False
                    actual_str = str(actual)
                    if not any(fnmatch.fnmatch(actual_str, str(pattern)) for pattern in expected_values):
                        return False

                # Bool operator
                elif operator == "Bool":
                    if actual is None:
                        return False
                    # Convert both sides to booleans
                    def to_bool(val: Any) -> bool:
                        if isinstance(val, bool):
                            return val
                        return str(val).lower() == "true"

                    expected_bool = to_bool(expected_values[0])
                    actual_bool = to_bool(actual)
                    if actual_bool != expected_bool:
                        return False

                # Null condition: true if the key is (not) present
                elif operator == "Null":
                    want_null = str(expected_values[0]).lower() == "true"
                    is_null = key not in context or context.get(key) is None
                    if is_null != want_null:
                        return False

                else:
                    # Unsupported operator - be conservative and treat as non-match
                    return False

        # All condition clauses passed
        return True


@dataclass
class EffectivePermissions:
    """Effective permissions for a principal after combining all policies"""
    principal_arn: str
    principal_type: str  # "user" or "role"
    statements: List[PolicyStatement] = field(default_factory=list)
    
    def has_action(
        self,
        action: str,
        resource: str = "*",
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Check if principal can perform action on resource.
        
        Implements AWS IAM evaluation logic:
        1. Explicit Deny always wins (checked first)
        2. Then check for explicit Allow
        3. If no Allow found, implicit deny (return False)
        
        Phase 2A-2 P1: Added Deny precedence handling
        Phase 2A-2 P3: Added resource constraint checking
        """
        # Step 1: Check for explicit Deny (Deny always wins)
        for stmt in self.statements:
            if (
                stmt.effect == "Deny"
                and stmt.matches_action(action)
                and stmt.matches_resource(resource)
                and stmt.matches_conditions(context)
            ):
                # This action is explicitly denied for this resource
                return False
        
        # Step 2: Check for explicit Allow
        for stmt in self.statements:
            if (
                stmt.effect == "Allow"
                and stmt.matches_action(action)
                and stmt.matches_resource(resource)
                and stmt.matches_conditions(context)
            ):
                # Action is allowed for this resource
                return True
        
        # Step 3: Implicit deny (no explicit Allow found)
        return False
    
    def has_actions(
        self,
        actions: List[str],
        resource: str = "*",
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Check if principal has ALL the given actions for a given resource/context."""
        return all(self.has_action(action, resource=resource, context=context) for action in actions)
    
    def get_source_policies_for_actions(
        self,
        actions: List[str],
        resource: str = "*",
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        Get the source policy names that ALONE grant ALL the given actions.
        Returns only policies that can independently satisfy the entire requirement.
        
        Example:
            actions = ['iam:PassRole', 'lambda:CreateFunction']
            
            AdministratorAccess: grants BOTH → INCLUDED
            PowerUserAccess: grants lambda:* but NOT iam:PassRole → EXCLUDED
        """
        # Group statements by source policy
        policies_by_source = {}
        for stmt in self.statements:
            if stmt.effect == "Allow" and stmt.source_policy:
                if stmt.source_policy not in policies_by_source:
                    policies_by_source[stmt.source_policy] = []
                policies_by_source[stmt.source_policy].append(stmt)
        
        # Find policies that grant ALL actions
        sufficient_policies = []
        
        for policy_name, statements in policies_by_source.items():
            # Check if this policy alone grants ALL required actions
            grants_all = True
            for action in actions:
                action_granted = False
                for stmt in statements:
                    if (
                        stmt.matches_action(action)
                        and stmt.matches_resource(resource)
                        and stmt.matches_conditions(context)
                    ):
                        action_granted = True
                        break
                
                if not action_granted:
                    grants_all = False
                    break
            
            if grants_all:
                sufficient_policies.append(policy_name)
        
        return sufficient_policies
    
    def get_all_actions(self) -> Set[str]:
        """Get all allowed actions (for debugging/analysis)"""
        all_actions = set()
        for stmt in self.statements:
            if stmt.effect == "Allow":
                all_actions.update(stmt.actions)
        return all_actions


class PolicyResolver:
    """
    Resolves all policies attached to a principal into effective permissions.
    
    Phase 2A-1: Handles managed + inline policies
    Phase 2A-2: Custom managed policies, Deny handling, resource constraints
    """
    
    def __init__(self, iam_client=None):
        """
        Initialize PolicyResolver.
        
        Args:
            iam_client: boto3 IAM client for fetching custom managed policies
        """
        self.iam = iam_client
        self._policy_cache = {}  # Cache for custom managed policies
        self._group_policy_cache = {}  # Cache for group policies
    
    # AWS Managed Policies Database (top critical ones)
    # Phase 2A-2 P3: PowerUserAccess re-enabled with NotAction support
    MANAGED_POLICIES = {
        'AdministratorAccess': {
            'actions': {'*'},
            'resources': {'*'},
            'not_actions': set()
        },
        'PowerUserAccess': {
            # NotAction: All services EXCEPT iam and organizations
            'actions': set(),
            'resources': {'*'},
            'not_actions': {'iam:*', 'organizations:*'}
        },
        'IAMFullAccess': {
            'actions': {'iam:*'},
            'resources': {'*'},
            'not_actions': set()
        },
        'AWSLambda_FullAccess': {
            'actions': {'lambda:*', 'iam:PassRole'},
            'resources': {'*'},
            'not_actions': set()
        },
        'AmazonEC2FullAccess': {
            'actions': {'ec2:*', 'iam:PassRole'},
            'resources': {'*'},
            'not_actions': set()
        },
        # Additional high-risk managed policies
        'SecurityAudit': {
            'actions': {'iam:Get*', 'iam:List*', 'iam:Generate*'},
            'resources': {'*'},
            'not_actions': set()
        },
        'ReadOnlyAccess': {
            'actions': {'*:Get*', '*:List*', '*:Describe*'},
            'resources': {'*'},
            'not_actions': set()
        }
        # TODO: Expand to ~50 most common AWS managed policies
    }
    
    def resolve_principal_permissions(
        self, 
        principal_data: Dict[str, Any]
    ) -> EffectivePermissions:
        """
        Combine all policies attached to a principal.
        
        Args:
            principal_data: IAM user/role data from scanner
            
        Returns:
            EffectivePermissions object with all statements
        """
        principal_arn = principal_data['arn']
        principal_type = principal_data.get('type', 'role')
        
        statements = []
        
        # 1. Managed policies (AWS + custom)
        for policy in principal_data.get('attached_policies', []):
            policy_arn = policy.get('PolicyArn', '')
            policy_name = policy.get('PolicyName', '')
            
            # AWS managed policies (arn:aws:iam::aws:policy/...)
            if 'aws:policy/' in policy_arn:
                # Extract just the policy name from ARN
                if '/' in policy_name:
                    policy_name = policy_name.split('/')[-1]
                
                if policy_name in self.MANAGED_POLICIES:
                    policy_def = self.MANAGED_POLICIES[policy_name]
                    statements.append(PolicyStatement(
                        effect='Allow',
                        actions=policy_def['actions'],
                        resources=policy_def['resources'],
                        source_policy=policy_name,
                        not_actions=policy_def.get('not_actions', set())
                    ))
            
            # Custom managed policies (customer-created)
            else:
                custom_statements = self._resolve_custom_policy(policy_arn, policy_name)
                statements.extend(custom_statements)
        
        # 2. Inline policies
        for policy_name, policy_doc in principal_data.get('inline_policies', {}).items():
            # Mark inline policies with "(inline)" suffix
            parsed_statements = self._parse_policy_document(policy_doc, f"{policy_name} (inline)")
            statements.extend(parsed_statements)
        
        # 3. Group policies (for users only)
        if principal_type == 'user':
            for group in principal_data.get('groups', []):
                group_statements = self._resolve_group_policies(group)
                # Mark group-sourced policies with "via {group}" prefix
                for stmt in group_statements:
                    if not stmt.source_policy.startswith('via '):
                        stmt.source_policy = f"via {group}: {stmt.source_policy}"
                statements.extend(group_statements)
        
        return EffectivePermissions(
            principal_arn=principal_arn,
            principal_type=principal_type,
            statements=statements
        )
    
    def _parse_policy_document(
        self, 
        policy_doc: Dict[str, Any],
        policy_name: str
    ) -> List[PolicyStatement]:
        """
        Parse IAM policy JSON into PolicyStatement objects.
        
        Phase 2A-1: Basic parsing - Effect, Action, Resource
        Phase 2A-2 P3: Added NotAction support
        Phase 2A-2 P4: Will add Condition parsing
        """
        statements = []
        
        for stmt in policy_doc.get('Statement', []):
            effect = stmt.get('Effect', 'Allow')
            
            # Parse actions (Action or NotAction)
            actions = set()
            not_actions = set()
            
            if 'NotAction' in stmt:
                # NotAction takes precedence
                not_action_raw = stmt['NotAction']
                if isinstance(not_action_raw, str):
                    not_action_raw = [not_action_raw]
                not_actions = set(not_action_raw)
            elif 'Action' in stmt:
                # Normal Action
                action_raw = stmt['Action']
                if isinstance(action_raw, str):
                    action_raw = [action_raw]
                actions = set(action_raw)
            
            # Parse resources / NotResource
            resources_raw = stmt.get('Resource')
            not_resources_raw = stmt.get('NotResource')

            if isinstance(resources_raw, str):
                resources_raw = [resources_raw]
            if isinstance(not_resources_raw, str):
                not_resources_raw = [not_resources_raw]

            if resources_raw is None:
                resources = ['*']
            else:
                resources = resources_raw

            not_resources = set(not_resources_raw or [])
            
            # Parse conditions (kept as raw structure, evaluated later)
            conditions = stmt.get('Condition', {}) or {}
            
            statements.append(PolicyStatement(
                effect=effect,
                actions=actions,
                resources=set(resources),
                source_policy=policy_name,
                not_actions=not_actions,
                conditions=conditions,
                not_resources=not_resources,
            ))
        
        return statements
    
    def _resolve_group_policies(
        self,
        group_name: str
    ) -> List[PolicyStatement]:
        statements: List[PolicyStatement] = []
        
        # Return from cache if available
        if group_name in self._group_policy_cache:
            return self._group_policy_cache[group_name]
        
        # If no IAM client, we cannot resolve group policies
        if not self.iam:
            return []
        
        # Attached managed policies for the group
        try:
            attached = self.iam.list_attached_group_policies(GroupName=group_name)
            for policy in attached.get('AttachedPolicies', []):
                policy_arn = policy.get('PolicyArn', '')
                policy_name = policy.get('PolicyName', '')
                
                if 'aws:policy/' in policy_arn:
                    if '/' in policy_name:
                        policy_name = policy_name.split('/')[-1]
                    
                    if policy_name in self.MANAGED_POLICIES:
                        policy_def = self.MANAGED_POLICIES[policy_name]
                        statements.append(PolicyStatement(
                            effect='Allow',
                            actions=policy_def['actions'],
                            resources=policy_def['resources'],
                            source_policy=policy_name,
                            not_actions=policy_def.get('not_actions', set())
                        ))
                else:
                    custom_statements = self._resolve_custom_policy(policy_arn, policy_name)
                    statements.extend(custom_statements)
        except Exception:
            pass
        
        # Inline policies attached to the group
        try:
            policy_names = self.iam.list_group_policies(GroupName=group_name).get('PolicyNames', [])
            for policy_name in policy_names:
                try:
                    policy_doc_resp = self.iam.get_group_policy(
                        GroupName=group_name,
                        PolicyName=policy_name
                    )
                    policy_doc = policy_doc_resp.get('PolicyDocument', {})
                    parsed = self._parse_policy_document(policy_doc, policy_name)
                    statements.extend(parsed)
                except Exception:
                    pass
        except Exception:
            pass
        
        self._group_policy_cache[group_name] = statements
        return statements
    
    def _resolve_custom_policy(
        self,
        policy_arn: str,
        policy_name: str
    ) -> List[PolicyStatement]:
        """
        Fetch and parse custom managed policy from AWS.
        
        Phase 2A-2 P0: Implements get_policy + get_policy_version
        
        Args:
            policy_arn: ARN of the custom managed policy
            policy_name: Name of the policy (for source tracking)
        
        Returns:
            List of PolicyStatement objects
        """
        # Check cache first
        if policy_arn in self._policy_cache:
            return self._policy_cache[policy_arn]
        
        # If no IAM client, skip (shouldn't happen in normal flow)
        if not self.iam:
            return []
        
        try:
            # Fetch policy metadata to get default version ID
            policy_response = self.iam.get_policy(PolicyArn=policy_arn)
            version_id = policy_response['Policy']['DefaultVersionId']
            
            # Fetch the actual policy document
            policy_version = self.iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )
            
            # Parse the policy document
            policy_doc = policy_version['PolicyVersion']['Document']
            statements = self._parse_policy_document(policy_doc, policy_name)
            
            # Cache the result to avoid redundant API calls
            self._policy_cache[policy_arn] = statements
            
            return statements
            
        except Exception as e:
            # Log error but don't fail - continue with other policies
            # TODO: Add proper logging
            # print(f"Warning: Failed to fetch custom policy {policy_arn}: {e}")
            return []
