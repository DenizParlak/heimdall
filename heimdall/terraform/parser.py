# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                      TERRAFORM PLAN PARSER
#              Extracts security-relevant changes from TF plans
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple

from heimdall.terraform.models import (
    ResourceChange,
    IAMImplication,
    ChangeAction,
    ImplicationType,
)

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                         SUPPORTED RESOURCES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# MVP: Focus on high-impact IAM and compute resources
SUPPORTED_IAM_RESOURCES = {
    # Core IAM
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_role_policy_attachment",
    "aws_iam_user",
    "aws_iam_user_policy",
    "aws_iam_user_policy_attachment",
    "aws_iam_group",
    "aws_iam_group_policy",
    "aws_iam_group_policy_attachment",
    "aws_iam_group_membership",
    "aws_iam_instance_profile",
}

SUPPORTED_COMPUTE_RESOURCES = {
    # Compute with IAM role associations
    "aws_lambda_function",
    "aws_instance",
    "aws_ecs_task_definition",
    "aws_ecs_service",
    "aws_eks_cluster",
    "aws_eks_node_group",
    "aws_codebuild_project",
    "aws_glue_job",
    "aws_sagemaker_notebook_instance",
    "aws_batch_job_definition",
    "aws_sfn_state_machine",
}

# Cross-service trigger resources (for lateral movement detection)
SUPPORTED_CROSS_SERVICE_RESOURCES = {
    # ════════════════════════════════════════════════════════════════════
    # EVENT TRIGGERS (Lateral Movement)
    # ════════════════════════════════════════════════════════════════════
    "aws_s3_bucket_notification",          # S3 → Lambda/SQS/SNS
    "aws_lambda_event_source_mapping",     # SQS/DynamoDB/Kinesis → Lambda
    "aws_lambda_permission",               # External invoke permissions
    "aws_cloudwatch_event_rule",           # EventBridge rules
    "aws_cloudwatch_event_target",         # EventBridge targets
    "aws_sns_topic_subscription",          # SNS → Lambda/SQS/HTTP
    "aws_cloudwatch_log_subscription_filter",  # CloudWatch Logs → Lambda
    
    # ════════════════════════════════════════════════════════════════════
    # API GATEWAY (Public Entry Points)
    # ════════════════════════════════════════════════════════════════════
    "aws_api_gateway_rest_api",
    "aws_api_gateway_resource",
    "aws_api_gateway_method",
    "aws_api_gateway_integration",
    "aws_apigatewayv2_api",
    "aws_apigatewayv2_integration",
    "aws_apigatewayv2_route",
    
    # ════════════════════════════════════════════════════════════════════
    # RESOURCE POLICIES (Data Access)
    # ════════════════════════════════════════════════════════════════════
    "aws_s3_bucket_policy",
    "aws_s3_bucket_public_access_block",
    "aws_sqs_queue_policy", 
    "aws_sns_topic_policy",
    "aws_lambda_function_url",             # Public Lambda URL
    "aws_kms_key_policy",
    "aws_secretsmanager_secret_policy",
    
    # ════════════════════════════════════════════════════════════════════
    # CI/CD TRIGGERS (Supply Chain)
    # ════════════════════════════════════════════════════════════════════
    "aws_codecommit_trigger",
    "aws_codecommit_repository",
    "aws_codepipeline",
    "aws_codepipeline_webhook",
    "aws_codestarconnections_connection",
    
    # ════════════════════════════════════════════════════════════════════
    # CONTAINER REGISTRIES (Supply Chain)
    # ════════════════════════════════════════════════════════════════════
    "aws_ecr_repository",
    "aws_ecr_repository_policy",
    "aws_ecr_lifecycle_policy",
    
    # ════════════════════════════════════════════════════════════════════
    # IOT / COGNITO TRIGGERS
    # ════════════════════════════════════════════════════════════════════
    "aws_iot_topic_rule",                  # IoT → Lambda
    "aws_cognito_user_pool",               # Cognito triggers
    "aws_cognito_user_pool_client",
    
    # ════════════════════════════════════════════════════════════════════
    # SECRETS & CONFIG
    # ════════════════════════════════════════════════════════════════════
    "aws_secretsmanager_secret",
    "aws_secretsmanager_secret_rotation",  # Secrets rotation Lambda
    "aws_ssm_parameter",
}

# Dangerous permission patterns
ADMIN_PATTERNS = [
    r'"Action"\s*:\s*"\*"',
    r'"Action"\s*:\s*\[\s*"\*"\s*\]',
    r"AdministratorAccess",
    r"PowerUserAccess",
    r"IAMFullAccess",
]

DANGEROUS_ACTIONS = {
    # IAM escalation
    "iam:*", "iam:PassRole", "iam:CreatePolicy", "iam:CreatePolicyVersion",
    "iam:AttachRolePolicy", "iam:AttachUserPolicy", "iam:PutRolePolicy",
    "iam:PutUserPolicy", "iam:CreateAccessKey", "iam:UpdateAssumeRolePolicy",
    
    # STS
    "sts:*", "sts:AssumeRole",
    
    # Lambda
    "lambda:*", "lambda:CreateFunction", "lambda:UpdateFunctionCode",
    "lambda:InvokeFunction",
    
    # EC2
    "ec2:*", "ec2:RunInstances",
    
    # Secrets/Parameters
    "secretsmanager:*", "secretsmanager:GetSecretValue",
    "ssm:*", "ssm:GetParameter", "ssm:SendCommand",
}


class TerraformPlanParser:
    """
    Parses Terraform plan JSON and extracts security-relevant changes.
    
    Terraform plan JSON structure:
    {
        "format_version": "1.2",
        "terraform_version": "1.5.0",
        "planned_values": { ... },
        "resource_changes": [
            {
                "address": "aws_iam_role.example",
                "type": "aws_iam_role",
                "name": "example",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {
                    "actions": ["create"],
                    "before": null,
                    "after": { ... },
                    "after_unknown": { ... }
                }
            }
        ],
        "configuration": { ... }
    }
    """
    
    def __init__(self):
        self.supported_resources = (
            SUPPORTED_IAM_RESOURCES | 
            SUPPORTED_COMPUTE_RESOURCES | 
            SUPPORTED_CROSS_SERVICE_RESOURCES
        )
        self._warnings: List[str] = []
    
    def parse_file(self, plan_path: str) -> List[ResourceChange]:
        """
        Parse a Terraform plan JSON file.
        
        Args:
            plan_path: Path to the terraform plan JSON file
                       (created with: terraform plan -out=plan && terraform show -json plan)
        
        Returns:
            List of ResourceChange objects with IAM implications
        """
        path = Path(plan_path)
        if not path.exists():
            raise FileNotFoundError(f"Terraform plan not found: {plan_path}")
        
        with open(path, 'r') as f:
            plan_data = json.load(f)
        
        return self.parse(plan_data)
    
    def parse(self, plan_data: Dict[str, Any]) -> List[ResourceChange]:
        """
        Parse Terraform plan data (already loaded JSON).
        
        Args:
            plan_data: Terraform plan as dictionary
        
        Returns:
            List of ResourceChange objects with IAM implications
        """
        self._warnings = []
        changes: List[ResourceChange] = []
        
        # Get resource changes
        resource_changes = plan_data.get("resource_changes", [])
        
        if not resource_changes:
            logger.warning("No resource changes found in Terraform plan")
            return changes
        
        # Get configuration for source file info
        config = plan_data.get("configuration", {})
        
        for rc in resource_changes:
            resource_type = rc.get("type", "")
            
            # Skip unsupported resources
            if resource_type not in self.supported_resources:
                continue
            
            # Parse the change
            change = self._parse_resource_change(rc, config)
            if change:
                # Extract IAM implications
                change.iam_implications = self._extract_implications(change)
                changes.append(change)
        
        logger.info(f"Parsed {len(changes)} security-relevant resource changes")
        return changes
    
    def parse_prior_state(self, plan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse prior_state from Terraform plan to get existing resources.
        
        This is used to calculate "before" attack paths for destroy scenarios.
        
        Returns:
            List of resource dictionaries from prior state
        """
        prior_resources = []
        
        prior_state = plan_data.get("prior_state", {})
        if not prior_state:
            return prior_resources
        
        values = prior_state.get("values", {})
        root_module = values.get("root_module", {})
        resources = root_module.get("resources", [])
        
        for res in resources:
            res_type = res.get("type", "")
            if res_type in self.supported_resources:
                prior_resources.append({
                    "type": res_type,
                    "name": res.get("name", ""),
                    "values": res.get("values", {}),
                    "address": f"{res_type}.{res.get('name', '')}",
                })
        
        logger.info(f"Parsed {len(prior_resources)} resources from prior state")
        return prior_resources
    
    def _parse_resource_change(
        self, 
        rc: Dict[str, Any], 
        config: Dict[str, Any]
    ) -> Optional[ResourceChange]:
        """Parse a single resource change."""
        try:
            address = rc.get("address", "")
            resource_type = rc.get("type", "")
            name = rc.get("name", "")
            
            # Parse change actions
            change_data = rc.get("change", {})
            actions = change_data.get("actions", [])
            action = self._parse_actions(actions)
            
            if action == ChangeAction.NO_OP:
                return None
            
            # Get before/after state
            before = change_data.get("before")
            after = change_data.get("after") or {}
            
            # Handle after_unknown (values computed after apply)
            after_unknown = change_data.get("after_unknown", {})
            if after and after_unknown:
                after = self._merge_unknown(after, after_unknown)
            
            # If after is empty/incomplete, enrich from configuration
            after = self._enrich_from_config(address, after, config)
            
            # Get module address if applicable
            module_address = rc.get("module_address", "")
            
            # Get provider
            provider = rc.get("provider_name", "aws")
            if "hashicorp/aws" in provider:
                provider = "aws"
            
            return ResourceChange(
                address=address,
                resource_type=resource_type,
                resource_name=name,
                action=action,
                before_state=before,
                after_state=after,
                module_address=module_address,
                provider=provider,
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse resource change: {e}")
            return None
    
    def _parse_actions(self, actions: List[str]) -> ChangeAction:
        """Convert Terraform actions to ChangeAction enum."""
        if not actions:
            return ChangeAction.NO_OP
        
        # Terraform uses lists like ["create"], ["update"], ["delete", "create"]
        action_set = set(actions)
        
        if action_set == {"no-op"} or action_set == {"read"}:
            return ChangeAction.NO_OP
        if action_set == {"create"}:
            return ChangeAction.CREATE
        if action_set == {"update"}:
            return ChangeAction.UPDATE
        if action_set == {"delete"}:
            return ChangeAction.DELETE
        if "delete" in action_set and "create" in action_set:
            return ChangeAction.REPLACE
        
        return ChangeAction.UPDATE  # Default to update for unknown combinations
    
    def _merge_unknown(
        self, 
        after: Dict[str, Any], 
        after_unknown: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Merge after_unknown flags into after state."""
        result = after.copy()
        for key, is_unknown in after_unknown.items():
            if is_unknown is True and key not in result:
                result[key] = "<computed>"
        return result
    
    def _enrich_from_config(
        self, 
        address: str, 
        after: Dict[str, Any], 
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrich after state with values from configuration section.
        
        When Terraform plan has computed values, we can try to resolve
        references from the configuration.
        """
        result = after.copy() if after else {}
        
        # Find this resource in configuration
        root_module = config.get("root_module", {})
        resources = root_module.get("resources", [])
        
        for res in resources:
            if res.get("address") == address:
                expressions = res.get("expressions", {})
                
                for key, expr in expressions.items():
                    # Skip if we already have a value
                    if key in result and result[key] and result[key] != "<computed>":
                        continue
                    
                    # Get constant value
                    if "constant_value" in expr:
                        result[key] = expr["constant_value"]
                    
                    # Handle references - try to resolve
                    elif "references" in expr:
                        refs = expr["references"]
                        # Store the reference for later resolution
                        result[f"_ref_{key}"] = refs
                        
                        # Try to extract resource name from reference
                        for ref in refs:
                            if ".name" in ref or ".id" in ref:
                                # Extract resource name: aws_iam_role.foo.name -> foo
                                parts = ref.split(".")
                                if len(parts) >= 2:
                                    result[key] = parts[1]
                                    break
                            elif ref.endswith(".arn"):
                                # Handle ARN references
                                parts = ref.split(".")
                                if len(parts) >= 2:
                                    # Create placeholder ARN
                                    result[key] = f"arn:aws:iam::ACCOUNT:role/{parts[1]}"
                                    break
                
                break
        
        return result
    
    def _extract_implications(self, change: ResourceChange) -> List[IAMImplication]:
        """
        Extract IAM security implications from a resource change.
        
        This is the core logic that determines what security impact
        a Terraform change will have.
        """
        implications: List[IAMImplication] = []
        
        resource_type = change.resource_type
        after = change.after_state or {}
        before = change.before_state or {}
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # IAM ROLE
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if resource_type == "aws_iam_role":
            implications.extend(self._analyze_iam_role(change, after, before))
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # IAM POLICY
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        elif resource_type == "aws_iam_policy":
            implications.extend(self._analyze_iam_policy(change, after, before))
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # IAM ROLE POLICY (Inline)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        elif resource_type == "aws_iam_role_policy":
            implications.extend(self._analyze_inline_policy(change, after, before, "role"))
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # IAM POLICY ATTACHMENT
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        elif resource_type == "aws_iam_role_policy_attachment":
            implications.extend(self._analyze_policy_attachment(change, after, before, "role"))
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # LAMBDA FUNCTION
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        elif resource_type == "aws_lambda_function":
            implications.extend(self._analyze_lambda_function(change, after, before))
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # EC2 INSTANCE
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        elif resource_type == "aws_instance":
            implications.extend(self._analyze_ec2_instance(change, after, before))
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # ECS TASK DEFINITION
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        elif resource_type == "aws_ecs_task_definition":
            implications.extend(self._analyze_ecs_task(change, after, before))
        
        # Set terraform source on all implications
        for imp in implications:
            imp.terraform_resource = change.address
        
        return implications
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #                      RESOURCE-SPECIFIC ANALYZERS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    def _analyze_iam_role(
        self, 
        change: ResourceChange, 
        after: Dict, 
        before: Dict
    ) -> List[IAMImplication]:
        """Analyze IAM role creation/modification."""
        implications = []
        
        role_name = after.get("name", change.resource_name)
        role_arn = after.get("arn", f"arn:aws:iam::*:role/{role_name}")
        
        # Analyze trust policy (assume_role_policy)
        trust_policy = after.get("assume_role_policy", "")
        if trust_policy:
            if isinstance(trust_policy, str):
                try:
                    trust_policy = json.loads(trust_policy)
                except json.JSONDecodeError:
                    pass
            
            if isinstance(trust_policy, dict):
                # Check who can assume this role
                for statement in trust_policy.get("Statement", []):
                    if statement.get("Effect") == "Allow":
                        principal = statement.get("Principal", {})
                        
                        # Service principals (Lambda, EC2, etc.)
                        if isinstance(principal, dict):
                            services = principal.get("Service", [])
                            if isinstance(services, str):
                                services = [services]
                            
                            for service in services:
                                implications.append(IAMImplication(
                                    implication_type=ImplicationType.CAN_BE_ASSUMED,
                                    source_principal=service,
                                    target=role_arn,
                                    severity=self._get_trust_severity(service),
                                    description=f"Service {service} can assume role {role_name}",
                                ))
                        
                        # AWS account principals
                        if isinstance(principal, dict):
                            aws_principals = principal.get("AWS", [])
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            
                            for aws_principal in aws_principals:
                                if "*" in aws_principal:
                                    implications.append(IAMImplication(
                                        implication_type=ImplicationType.CAN_BE_ASSUMED,
                                        source_principal=aws_principal,
                                        target=role_arn,
                                        severity="CRITICAL",
                                        description=f"WARNING: Wildcard principal can assume role {role_name}",
                                    ))
        
        # Check if this is a new principal
        if change.action == ChangeAction.CREATE:
            implications.append(IAMImplication(
                implication_type=ImplicationType.CREATES_PRINCIPAL,
                source_principal="terraform",
                target=role_arn,
                severity="MEDIUM",
                description=f"New IAM role created: {role_name}",
            ))
        
        return implications
    
    def _analyze_iam_policy(
        self, 
        change: ResourceChange, 
        after: Dict, 
        before: Dict
    ) -> List[IAMImplication]:
        """Analyze IAM policy creation/modification."""
        implications = []
        
        policy_name = after.get("name", change.resource_name)
        policy_arn = after.get("arn", f"arn:aws:iam::*:policy/{policy_name}")
        policy_doc = after.get("policy", "")
        
        # Parse and analyze the policy document
        dangerous_actions = self._analyze_policy_document(policy_doc)
        
        if dangerous_actions:
            severity = "CRITICAL" if "*" in str(dangerous_actions) else "HIGH"
            implications.append(IAMImplication(
                implication_type=ImplicationType.GAINS_PERMISSION,
                source_principal=policy_arn,
                target="*",
                permissions=dangerous_actions,
                severity=severity,
                description=f"Policy {policy_name} grants dangerous permissions: {', '.join(dangerous_actions[:5])}",
            ))
        
        return implications
    
    def _analyze_inline_policy(
        self, 
        change: ResourceChange, 
        after: Dict, 
        before: Dict,
        principal_type: str
    ) -> List[IAMImplication]:
        """Analyze inline policy attachment."""
        implications = []
        
        role_name = after.get("role", after.get("name", ""))
        policy_doc = after.get("policy", "")
        
        dangerous_actions = self._analyze_policy_document(policy_doc)
        
        if dangerous_actions:
            severity = "CRITICAL" if "*" in str(dangerous_actions) else "HIGH"
            implications.append(IAMImplication(
                implication_type=ImplicationType.GAINS_PERMISSION,
                source_principal=f"arn:aws:iam::*:role/{role_name}",
                target="*",
                permissions=dangerous_actions,
                severity=severity,
                description=f"Inline policy on {role_name} grants: {', '.join(dangerous_actions[:5])}",
            ))
        
        return implications
    
    def _analyze_policy_attachment(
        self, 
        change: ResourceChange, 
        after: Dict, 
        before: Dict,
        principal_type: str
    ) -> List[IAMImplication]:
        """Analyze managed policy attachment."""
        implications = []
        
        role_name = after.get("role", "")
        policy_arn = after.get("policy_arn", "")
        
        # Check for known dangerous policies
        dangerous_policies = [
            "AdministratorAccess",
            "PowerUserAccess", 
            "IAMFullAccess",
        ]
        
        is_dangerous = any(dp in policy_arn for dp in dangerous_policies)
        
        if is_dangerous or "*" in policy_arn:
            implications.append(IAMImplication(
                implication_type=ImplicationType.ATTACHES_POLICY,
                source_principal=f"arn:aws:iam::*:role/{role_name}",
                target=policy_arn,
                severity="CRITICAL",
                description=f"Attaching admin policy {policy_arn} to {role_name}",
            ))
        else:
            implications.append(IAMImplication(
                implication_type=ImplicationType.ATTACHES_POLICY,
                source_principal=f"arn:aws:iam::*:role/{role_name}",
                target=policy_arn,
                severity="MEDIUM",
                description=f"Attaching policy to {role_name}",
            ))
        
        return implications
    
    def _analyze_lambda_function(
        self, 
        change: ResourceChange, 
        after: Dict, 
        before: Dict
    ) -> List[IAMImplication]:
        """Analyze Lambda function with IAM role."""
        implications = []
        
        function_name = after.get("function_name", change.resource_name)
        role_arn = after.get("role", "")
        
        if role_arn:
            # Lambda can use this role via PassRole
            implications.append(IAMImplication(
                implication_type=ImplicationType.PASSROLE_TO,
                source_principal=f"lambda:function:{function_name}",
                target=role_arn,
                severity="HIGH",
                description=f"Lambda {function_name} can execute with role {role_arn}",
            ))
            
            # Lambda service can assume the role
            implications.append(IAMImplication(
                implication_type=ImplicationType.CAN_ASSUME,
                source_principal="lambda.amazonaws.com",
                target=role_arn,
                severity="MEDIUM",
                description=f"Lambda service assumes role for {function_name}",
            ))
        
        return implications
    
    def _analyze_ec2_instance(
        self, 
        change: ResourceChange, 
        after: Dict, 
        before: Dict
    ) -> List[IAMImplication]:
        """Analyze EC2 instance with instance profile."""
        implications = []
        
        instance_profile = after.get("iam_instance_profile", "")
        
        if instance_profile:
            implications.append(IAMImplication(
                implication_type=ImplicationType.PASSROLE_TO,
                source_principal=f"ec2:instance:{change.resource_name}",
                target=instance_profile,
                severity="HIGH",
                description=f"EC2 instance uses profile {instance_profile} (IMDS credential exposure)",
            ))
        
        return implications
    
    def _analyze_ecs_task(
        self, 
        change: ResourceChange, 
        after: Dict, 
        before: Dict
    ) -> List[IAMImplication]:
        """Analyze ECS task definition with IAM roles."""
        implications = []
        
        task_role = after.get("task_role_arn", "")
        execution_role = after.get("execution_role_arn", "")
        
        if task_role:
            implications.append(IAMImplication(
                implication_type=ImplicationType.PASSROLE_TO,
                source_principal=f"ecs:task:{change.resource_name}",
                target=task_role,
                severity="HIGH",
                description=f"ECS task can execute with role {task_role}",
            ))
        
        if execution_role:
            implications.append(IAMImplication(
                implication_type=ImplicationType.PASSROLE_TO,
                source_principal=f"ecs:task:{change.resource_name}",
                target=execution_role,
                severity="MEDIUM",
                description=f"ECS task execution uses role {execution_role}",
            ))
        
        return implications
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #                          HELPER METHODS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    def _analyze_policy_document(self, policy_doc: Any) -> List[str]:
        """Extract dangerous actions from a policy document."""
        dangerous_found: Set[str] = set()
        
        if isinstance(policy_doc, str):
            # Check for admin patterns in raw string
            for pattern in ADMIN_PATTERNS:
                if re.search(pattern, policy_doc):
                    dangerous_found.add("*")
            
            # Try to parse as JSON
            try:
                policy_doc = json.loads(policy_doc)
            except json.JSONDecodeError:
                return list(dangerous_found)
        
        if not isinstance(policy_doc, dict):
            return list(dangerous_found)
        
        # Parse statements
        for statement in policy_doc.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue
            
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            
            for action in actions:
                if action in DANGEROUS_ACTIONS or action == "*":
                    dangerous_found.add(action)
                # Check for wildcards
                elif "*" in action:
                    service = action.split(":")[0] if ":" in action else action
                    if service in ["iam", "sts", "lambda", "ec2", "secretsmanager", "ssm"]:
                        dangerous_found.add(action)
        
        return list(dangerous_found)
    
    def _get_trust_severity(self, service: str) -> str:
        """Get severity level for a service principal in trust policy."""
        high_risk_services = {
            "lambda.amazonaws.com",
            "ec2.amazonaws.com",
            "ecs-tasks.amazonaws.com",
            "codebuild.amazonaws.com",
            "glue.amazonaws.com",
            "sagemaker.amazonaws.com",
        }
        
        if service in high_risk_services:
            return "HIGH"
        return "MEDIUM"
    
    def get_warnings(self) -> List[str]:
        """Get any warnings from the last parse operation."""
        return self._warnings
