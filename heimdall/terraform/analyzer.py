# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   ᚺᛖᛁᛗᛞᚨᛚᛚ  •  TERRAFORM ATTACK PATH ANALYZER  •  ᚷᛃᚨᛚᛚᚨᚱᚺᛟᚱᚾ
#
#   "Heimdall kan höra gräset växa och ullen på fåren"
#                                        — Prose Edda
#
#   As Heimdall watches the Bifröst for threats approaching Asgard,
#   this analyzer watches Terraform plans for attack paths approaching
#   your AWS kingdom — detecting threats before they cross the bridge.
#
#   45+ attack patterns • Multi-hop detection • Before/After analysis
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING
from functools import cached_property
from itertools import chain

from heimdall.terraform.parser import TerraformPlanParser
from heimdall.terraform.models import (
    ResourceChange, TerraformImpactReport, MergedState, ChangeAction,
)
from heimdall.terraform.patterns import (
    ADMIN_POLICIES, ALWAYS_DANGEROUS, PASSROLE_COMPUTE_ACTIONS, 
    ALL_COMPUTE_ACTIONS, detect_patterns,
)
from heimdall.terraform.recommendations import generate_recommendations

if TYPE_CHECKING:
    from boto3 import Session

logger = logging.getLogger(__name__)


class TerraformAnalyzer:
    
    # Analyze Terraform plans for IAM privilege escalation paths.
    __slots__ = ('session', 'parser', '_current_state')
    
    def __init__(self, session: Session | None = None):
        self.session = session
        self.parser = TerraformPlanParser()
        self._current_state: MergedState | None = None
    
    # ════════════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ════════════════════════════════════════════════════════════════════════
    
    def analyze_plan(
        self,
        plan_path: str,
        current_state_json: str | None = None,
        fetch_aws_state: bool = True,
    ) -> TerraformImpactReport:
        
        # Analyze a Terraform plan for security implications.
        logger.info(f"Analyzing: {plan_path}")
        
        resource_changes = self.parser.parse_file(plan_path)
        prior_resources = self._load_prior_state(plan_path)
        
        # Build before state
        if prior_resources:
            current_state = self._build_state_from_prior(prior_resources)
        elif current_state_json:
            current_state = self._load_state_from_json(current_state_json)
        elif fetch_aws_state and self.session:
            current_state = self._fetch_current_state()
        else:
            current_state = MergedState()
        
        # Build after state
        proposed_state = self._merge_changes(current_state.copy(), resource_changes)
        
        # Detect attack paths
        before_paths = self._analyze_attack_paths(current_state)
        after_paths = self._analyze_attack_paths(proposed_state)
        after_paths.extend(self._detect_cross_service_chains(resource_changes, proposed_state))
        
        return self._build_report(
            plan_path, resource_changes, before_paths, after_paths, current_state, proposed_state
        )
    
    def analyze_plan_quick(self, plan_path: str) -> TerraformImpactReport:
        
        # Quick analysis without AWS state fetch.
        return self.analyze_plan(plan_path, fetch_aws_state=False)
    
    # ════════════════════════════════════════════════════════════════════════
    # STATE BUILDING
    # ════════════════════════════════════════════════════════════════════════
    
    def _load_prior_state(self, plan_path: str) -> list[dict] | None:
        
        # Extract prior_state from Terraform plan JSON.
        try:
            with open(plan_path) as f:
                plan_data = json.load(f)
            return self.parser.parse_prior_state(plan_data)
        except Exception:
            return None
    
    def _build_state_from_prior(self, prior_resources: list[dict]) -> MergedState:
        
        # Build MergedState from Terraform's prior_state.
        state = MergedState()
        
        for res in prior_resources:
            res_type, values = res.get("type"), res.get("values", {})
            
            if res_type == "aws_iam_role":
                role_name = values.get("name", "")
                state.roles[f"arn:aws:iam::ACCOUNT:role/{role_name}"] = {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": self._parse_policy(values.get("assume_role_policy")),
                }
            elif res_type == "aws_iam_role_policy":
                role_name = values.get("role", "")
                policy_doc = self._parse_policy(values.get("policy"))
                state.role_policies.setdefault(role_name, []).append({
                    "PolicyName": values.get("name", ""),
                    "PolicyDocument": policy_doc,
                })
            elif res_type == "aws_iam_role_policy_attachment":
                role_name = values.get("role", "")
                policy_arn = values.get("policy_arn", "")
                state.role_attachments.setdefault(role_name, []).append(policy_arn)
        
        return state
    
    def _fetch_current_state(self) -> MergedState:
        
        # Fetch current IAM state from AWS.
        if not self.session:
            return MergedState()
        
        state = MergedState()
        iam = self.session.client("iam")
        
        try:
            for page in iam.get_paginator("list_roles").paginate():
                for role in page["Roles"]:
                    role_name = role["RoleName"]
                    state.roles[role["Arn"]] = role
                    
                    # Attached policies
                    attached = iam.list_attached_role_policies(RoleName=role_name)
                    state.role_attachments[role_name] = [
                        p["PolicyArn"] for p in attached.get("AttachedPolicies", [])
                    ]
        except Exception as e:
            logger.warning(f"Failed to fetch AWS state: {e}")
        
        return state
    
    def _load_state_from_json(self, json_path: str) -> MergedState:
        
        # Load state from pre-fetched JSON file.
        state = MergedState()
        try:
            with open(json_path) as f:
                data = json.load(f)
            state.roles = {r.get("Arn", ""): r for r in data.get("roles", [])}
            for role in data.get("roles", []):
                name = role.get("RoleName", "")
                state.role_attachments[name] = role.get("AttachedPolicies", [])
        except Exception as e:
            logger.warning(f"Failed to load state JSON: {e}")
        return state
    
    # ════════════════════════════════════════════════════════════════════════
    # CHANGE MERGING
    # ════════════════════════════════════════════════════════════════════════
    
    def _merge_changes(self, state: MergedState, changes: list[ResourceChange]) -> MergedState:
        
        #Apply Terraform changes to state.
        for change in changes:
            if change.action in (ChangeAction.CREATE, ChangeAction.UPDATE):
                self._apply_change(state, change)
            elif change.action == ChangeAction.DELETE:
                self._apply_delete(state, change)
        return state
    
    def _apply_change(self, state: MergedState, change: ResourceChange):
        
        # Apply a CREATE/UPDATE change to state.
        res_type = change.resource_type
        after = change.after_state or {}
        
        if res_type == "aws_iam_role":
            role_name = after.get("name", "")
            # Extract terraform resource name from address (aws_iam_role.data_role -> data_role)
            tf_name = change.address.split(".")[-1] if "." in change.address else ""
            trust_doc = self._parse_policy(after.get("assume_role_policy"))
            state.roles[f"arn:aws:iam::ACCOUNT:role/{role_name}"] = {
                "RoleName": role_name,
                "TerraformName": tf_name,
                "AssumeRolePolicyDocument": trust_doc,
            }
        
        elif res_type == "aws_iam_policy":
            policy_name = after.get("name", "")
            policy_doc = self._parse_policy(after.get("policy"))
            state.policies[f"arn:aws:iam::ACCOUNT:policy/{policy_name}"] = {
                "PolicyName": policy_name,
                "PolicyDocument": policy_doc,
            }
        
        elif res_type == "aws_iam_role_policy":
            role_name = self._resolve_role_name(after, state)
            policy_doc = self._parse_policy(after.get("policy"))
            
            policies = state.role_policies.setdefault(role_name, [])
            policy_entry = {"PolicyName": after.get("name", ""), "PolicyDocument": policy_doc}
            
            # Update existing or append
            for i, p in enumerate(policies):
                if p.get("PolicyName") == policy_entry["PolicyName"]:
                    policies[i] = policy_entry
                    break
            else:
                policies.append(policy_entry)
        
        elif res_type == "aws_iam_role_policy_attachment":
            role_name = self._resolve_role_name(after, state)
            policy_arn = after.get("policy_arn", "")
            
            attachments = state.role_attachments.setdefault(role_name, [])
            if policy_arn and policy_arn not in attachments:
                attachments.append(policy_arn)
    
    def _apply_delete(self, state: MergedState, change: ResourceChange):
        
        # Apply a DELETE change to state.
        res_type = change.resource_type
        before = change.before_state or {}
        
        if res_type == "aws_iam_role":
            role_name = before.get("name", "")
            role_arn = f"arn:aws:iam::ACCOUNT:role/{role_name}"
            state.roles.pop(role_arn, None)
            state.role_policies.pop(role_name, None)
            state.role_attachments.pop(role_name, None)
        
        elif res_type == "aws_iam_policy":
            policy_name = before.get("name", "")
            state.policies.pop(f"arn:aws:iam::ACCOUNT:policy/{policy_name}", None)
        
        elif res_type == "aws_iam_role_policy":
            role_name = before.get("role", "")
            policy_name = before.get("name", "")
            if role_name in state.role_policies:
                state.role_policies[role_name] = [
                    p for p in state.role_policies[role_name]
                    if p.get("PolicyName") != policy_name
                ]
        
        elif res_type == "aws_iam_role_policy_attachment":
            role_name = before.get("role", "")
            policy_arn = before.get("policy_arn", "")
            if role_name in state.role_attachments:
                state.role_attachments[role_name] = [
                    p for p in state.role_attachments[role_name] if p != policy_arn
                ]
    
    # ════════════════════════════════════════════════════════════════════════
    # ATTACK PATH DETECTION
    # ════════════════════════════════════════════════════════════════════════
    
    def _analyze_attack_paths(self, state: MergedState) -> list[dict]:
        
        # Detect all attack paths in the given state.
        paths = []
        admin_roles = self._find_admin_roles(state)
        
        for role_arn, role_data in state.roles.items():
            role_name = role_data.get("RoleName", "")
            
            # Check admin policy attachments
            if path := self._check_admin_attachment(role_name, state, admin_roles):
                paths.append(path)
            
            # Check trust policy
            if path := self._check_trust_policy(role_name, role_data, admin_roles, state):
                paths.append(path)
            
            # Check inline policies
            for policy in state.role_policies.get(role_name, []):
                policy_doc = policy.get("PolicyDocument", {})
                paths.extend(self._analyze_policy(role_name, policy_doc, admin_roles, state))
        
        return paths
    
    def _find_admin_roles(self, state: MergedState) -> set[str]:
        
        # Find all roles with admin privileges.
        admin_roles = set()
        for role_arn, role_data in state.roles.items():
            role_name = role_data.get("RoleName", "")
            attachments = state.role_attachments.get(role_name, [])
            if any(p in ADMIN_POLICIES for p in attachments):
                admin_roles.add(role_name)
        return admin_roles
    
    def _check_admin_attachment(self, role_name: str, state: MergedState, admin_roles: set) -> dict | None:
        
        # Check if role has admin policy attached.
        for policy_arn in state.role_attachments.get(role_name, []):
            if policy_arn in ADMIN_POLICIES:
                return {
                    "type": "admin_policy_attachment",
                    "role": role_name,
                    "policy": policy_arn,
                    "severity": "CRITICAL",
                }
        return None
    
    def _check_trust_policy(self, role_name: str, role_data: dict, admin_roles: set, state: MergedState) -> dict | None:
        
        # Check trust policy for dangerous configurations.
        trust_doc = role_data.get("AssumeRolePolicyDocument", {})
        
        for stmt in trust_doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            
            principal = stmt.get("Principal", {})
            
            # Wildcard principal
            if principal == "*" or principal.get("AWS") == "*":
                return {
                    "type": "wildcard_trust_policy",
                    "role": role_name,
                    "severity": "CRITICAL",
                }
            
            # Compute service with admin access
            service = principal.get("Service", "")
            services = [service] if isinstance(service, str) else service
            
            for svc in services:
                if role_name in admin_roles:
                    if "lambda" in svc:
                        return {"type": "lambda_admin_access", "role": role_name, "severity": "CRITICAL"}
                    if any(c in svc for c in ["ec2", "ecs", "codebuild", "glue"]):
                        return {"type": "compute_to_admin", "role": role_name, "severity": "CRITICAL"}
        
        return None
    
    def _analyze_policy(self, role_name: str, policy_doc: dict, admin_roles: set, state: MergedState) -> list[dict]:
        
        # Analyze a policy document for attack patterns.
        paths = []
        
        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            
            actions = stmt.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            action_set = self._expand_actions(actions)
            
            resources = stmt.get("Resource", [])
            resources = [resources] if isinstance(resources, str) else resources
            
            # Dangerous actions
            dangerous = action_set & ALWAYS_DANGEROUS
            if dangerous:
                paths.append({
                    "type": "dangerous_permissions",
                    "role": role_name,
                    "actions": list(dangerous),
                    "severity": "HIGH",
                })
            
            # PassRole chains
            if "iam:PassRole" in action_set:
                if passrole_path := self._check_passrole_chain(role_name, action_set, resources, admin_roles, state):
                    paths.append(passrole_path)
            
            # AssumeRole chains
            if "sts:AssumeRole" in action_set:
                paths.extend(self._check_assume_role_chain(role_name, resources, admin_roles))
            
            # Pattern detection
            paths.extend([{**p, "role": role_name} for p in detect_patterns(action_set, resources)])
        
        return paths
    
    def _check_passrole_chain(self, role_name: str, actions: set, resources: list, admin_roles: set, state: MergedState) -> dict | None:
        
        # Check for PassRole + compute privilege escalation.
        compute_actions = actions & ALL_COMPUTE_ACTIONS
        if not compute_actions:
            return None
        
        # Check if PassRole target is admin
        for resource in resources:
            target_role = self._extract_role_name(resource)
            if target_role in admin_roles:
                return {
                    "type": "passrole_chain_to_admin",
                    "source_role": role_name,
                    "target_role": target_role,
                    "severity": "CRITICAL",
                }
        
        return {
            "type": "compute_passrole_chain",
            "role": role_name,
            "actions": list(compute_actions),
            "severity": "HIGH",
        }
    
    def _check_assume_role_chain(self, role_name: str, resources: list, admin_roles: set) -> list[dict]:
        
        # Check for AssumeRole to admin chains.
        paths = []
        for resource in resources:
            target = self._extract_role_name(resource)
            if target in admin_roles:
                paths.append({
                    "type": "assume_role_to_admin",
                    "source_role": role_name,
                    "target_role": target,
                    "severity": "CRITICAL",
                })
        return paths
    
    # ════════════════════════════════════════════════════════════════════════
    # CROSS-SERVICE DETECTION
    # ════════════════════════════════════════════════════════════════════════
    
    def _detect_cross_service_chains(self, changes: list[ResourceChange], state: MergedState) -> list[dict]:
        
        # Detect cross-service attack chains from resource changes.
        paths = []
        lambdas = {}
        triggers = []
        
        for change in changes:
            if change.action == ChangeAction.DELETE:
                continue
            
            after = change.after_state or {}
            res_type = change.resource_type
            
            if res_type == "aws_lambda_function":
                lambdas[change.address] = after.get("function_name", "")
            
            elif res_type == "aws_s3_bucket_notification":
                for config in after.get("lambda_function", []):
                    triggers.append(("s3_lambda", config.get("lambda_function_arn", "")))
            
            elif res_type == "aws_lambda_event_source_mapping":
                source = after.get("event_source_arn", "")
                if "sqs" in source.lower():
                    triggers.append(("sqs_lambda", after.get("function_name", "")))
                elif "dynamodb" in source.lower():
                    triggers.append(("dynamodb_lambda", after.get("function_name", "")))
            
            elif res_type == "aws_sns_topic_subscription":
                if after.get("protocol") == "lambda":
                    triggers.append(("sns_lambda", after.get("endpoint", "")))
            
            elif res_type == "aws_cloudwatch_event_target":
                triggers.append(("eventbridge_lambda", after.get("arn", "")))
            
            elif res_type == "aws_lambda_function_url":
                if after.get("authorization_type") == "NONE":
                    paths.append({
                        "type": "cross_service_public_lambda_url",
                        "resource": after.get("function_name", ""),
                        "severity": "HIGH",
                    })
        
        # Build cross-service paths
        for trigger_type, target in triggers:
            paths.append({
                "type": f"cross_service_{trigger_type}",
                "source": trigger_type.split("_")[0].upper(),
                "target": target,
                "severity": "HIGH",
            })
        
        return paths
    
    # ════════════════════════════════════════════════════════════════════════
    # REPORT GENERATION
    # ════════════════════════════════════════════════════════════════════════
    
    def _build_report(
        self,
        plan_path: str,
        changes: list[ResourceChange],
        before_paths: list[dict],
        after_paths: list[dict],
        current_state: MergedState,
        proposed_state: MergedState,
    ) -> TerraformImpactReport:
        
        # Build the final impact report.
        # Calculate diff
        before_set = {self._path_key(p) for p in before_paths}
        after_set = {self._path_key(p) for p in after_paths}
        
        new_paths = [p for p in after_paths if self._path_key(p) not in before_set]
        removed_paths = [p for p in before_paths if self._path_key(p) not in after_set]
        
        # Calculate risk scores
        risk_before = sum(self._path_risk(p) for p in before_paths)
        risk_after = sum(self._path_risk(p) for p in after_paths)
        
        # Generate recommendations
        blocking_issues, recommendations = generate_recommendations(new_paths)
        
        # Count resources
        iam_count = sum(1 for c in changes if "iam" in c.resource_type)
        compute_count = sum(1 for c in changes if c.resource_type in {
            "aws_lambda_function", "aws_instance", "aws_ecs_task_definition"
        })
        
        report = TerraformImpactReport(
            resource_changes=changes,
            before_paths=before_paths,
            after_paths=after_paths,
            before_path_count=len(before_paths),
            after_path_count=len(after_paths),
            new_paths=new_paths,
            removed_paths=removed_paths,
            risk_score_before=risk_before,
            risk_score_after=risk_after,
            risk_delta=risk_after - risk_before,
            blocking_issues=blocking_issues,
            recommendations=recommendations,
            new_critical_count=sum(1 for p in new_paths if p.get("severity") == "CRITICAL"),
            new_high_count=sum(1 for p in new_paths if p.get("severity") == "HIGH"),
            removed_path_count=len(removed_paths),
        )
        
        return report
    
    # ════════════════════════════════════════════════════════════════════════
    # UTILITIES
    # ════════════════════════════════════════════════════════════════════════
    
    @staticmethod
    def _parse_policy(policy: str | dict | None) -> dict:
        
        # Parse policy document from string or dict.
        if not policy:
            return {}
        if isinstance(policy, dict):
            return policy
        try:
            return json.loads(policy)
        except (json.JSONDecodeError, TypeError):
            return {}
    
    @staticmethod
    def _resolve_role_name(after: dict, state: MergedState) -> str:
        
        # Resolve role name from Terraform reference or direct value.
        role = after.get("role")
        if role and role != "<computed>":
            # Check if this is a Terraform name that needs mapping
            for role_data in state.roles.values():
                if role_data.get("TerraformName") == role:
                    return role_data.get("RoleName", role)
            return role
        
        # Handle _ref_role which is a list of references
        refs = after.get("_ref_role", [])
        if isinstance(refs, str):
            refs = [refs]
        
        for ref in refs:
            if "." in ref:
                # aws_iam_role.ssm_role.id -> ssm_role
                parts = ref.split(".")
                if len(parts) >= 2:
                    tf_name = parts[1]
                    # Try to find matching role by TerraformName
                    for role_data in state.roles.values():
                        if role_data.get("TerraformName") == tf_name:
                            return role_data.get("RoleName", tf_name)
                    # Fallback: return terraform name
                    return tf_name
        return ""
    
    @staticmethod
    def _extract_role_name(arn: str) -> str:
        
        # Extract role name from ARN.
        if ":role/" in arn:
            return arn.split(":role/")[-1].split("/")[0]
        return arn
    
    @staticmethod
    def _expand_actions(actions: list[str]) -> set[str]:
        
        # Expand action wildcards (basic).
        expanded = set()
        for action in actions:
            if action.endswith(":*"):
                # Add the wildcard itself
                expanded.add(action)
            else:
                expanded.add(action)
        return expanded
    
    @staticmethod
    def _path_key(path: dict) -> str:
        
        # Generate unique key for path deduplication.
        return f"{path.get('type')}:{path.get('role', '')}:{path.get('target_role', '')}"
    
    @staticmethod
    def _path_risk(path: dict) -> int:
        
        # Calculate risk score for a path.
        severity = path.get("severity", "LOW")
        return {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}.get(severity, 1)
