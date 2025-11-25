# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                           ᛞᚹᛖᚱᚷᚨᚱ • THE DVERGAR
#                    Master Craftsmen of the Realms
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "In Svartálfaheim, the dwarves forge wonders: Mjölnir the hammer,
#    Gungnir the spear, and Gleipnir the unbreakable chain."
#
#   Like the Dvergar at their forges, this builder crafts attack chains
#   from raw findings - each link precisely fitted to the next.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import logging
from collections import defaultdict
from typing import List, Dict, Any, Optional, Set, Tuple

from heimdall.attack_chain.schema import (
    AttackChain, AttackStep, BlastRadius, ServiceImpact,
    ChainCategory, Severity, MITRE_MAPPINGS,
)

logger = logging.getLogger(__name__)

# Comprehensive pattern to category mapping (70+ patterns)
PATTERN_CATEGORIES = {
    # === PassRole + Service Execution (20+ services) ===
    "passrole_lambda": ChainCategory.PASSROLE_EXECUTION,
    "passrole_ec2": ChainCategory.PASSROLE_EXECUTION,
    "passrole_ecs": ChainCategory.PASSROLE_EXECUTION,
    "passrole_glue": ChainCategory.PASSROLE_EXECUTION,
    "passrole_codebuild": ChainCategory.PASSROLE_EXECUTION,
    "passrole_sagemaker": ChainCategory.PASSROLE_EXECUTION,
    "passrole_sagemaker_notebook": ChainCategory.PASSROLE_EXECUTION,
    "passrole_sagemaker_training": ChainCategory.PASSROLE_EXECUTION,
    "passrole_cloudformation": ChainCategory.PASSROLE_EXECUTION,
    "passrole_batch": ChainCategory.PASSROLE_EXECUTION,
    "passrole_emr": ChainCategory.PASSROLE_EXECUTION,
    "passrole_stepfunctions": ChainCategory.PASSROLE_EXECUTION,
    "passrole_datapipeline": ChainCategory.PASSROLE_EXECUTION,
    "passrole_iot": ChainCategory.PASSROLE_EXECUTION,
    "passrole_apprunner": ChainCategory.PASSROLE_EXECUTION,
    "passrole_mediaconvert": ChainCategory.PASSROLE_EXECUTION,
    "eks_passrole": ChainCategory.PASSROLE_EXECUTION,
    "eks_passrole_nodegroup": ChainCategory.PASSROLE_EXECUTION,
    "eks_passrole_fargate": ChainCategory.PASSROLE_EXECUTION,
    "eks_irsa_pod_exec": ChainCategory.PASSROLE_EXECUTION,
    "eks_node_role_abuse": ChainCategory.PASSROLE_EXECUTION,
    
    # === Policy Manipulation (10+ patterns) ===
    "create_policy_version": ChainCategory.POLICY_MANIPULATION,
    "set_default_policy_version": ChainCategory.POLICY_MANIPULATION,
    "put_user_policy": ChainCategory.POLICY_MANIPULATION,
    "put_role_policy": ChainCategory.POLICY_MANIPULATION,
    "put_group_policy": ChainCategory.POLICY_MANIPULATION,
    "attach_user_policy": ChainCategory.POLICY_MANIPULATION,
    "attach_role_policy": ChainCategory.POLICY_MANIPULATION,
    "attach_group_policy": ChainCategory.POLICY_MANIPULATION,
    "add_user_to_group": ChainCategory.POLICY_MANIPULATION,
    "create_policy_attach_combo": ChainCategory.POLICY_MANIPULATION,
    "permission_boundary_bypass": ChainCategory.POLICY_MANIPULATION,
    "delete_account_password_policy": ChainCategory.POLICY_MANIPULATION,
    "tag_based_access_bypass": ChainCategory.POLICY_MANIPULATION,
    
    # === Credential Exposure (15+ patterns) ===
    "create_access_key": ChainCategory.CREDENTIAL_EXPOSURE,
    "create_login_profile": ChainCategory.CREDENTIAL_EXPOSURE,
    "update_login_profile": ChainCategory.CREDENTIAL_EXPOSURE,
    "ssm_send_command": ChainCategory.CREDENTIAL_EXPOSURE,
    "ssm_start_session": ChainCategory.CREDENTIAL_EXPOSURE,
    "ssm_get_parameter": ChainCategory.CREDENTIAL_EXPOSURE,
    "ec2_instance_connect": ChainCategory.CREDENTIAL_EXPOSURE,
    "ec2_serial_console": ChainCategory.CREDENTIAL_EXPOSURE,
    "ec2_user_data": ChainCategory.CREDENTIAL_EXPOSURE,
    "codecommit_git_credentials": ChainCategory.CREDENTIAL_EXPOSURE,
    "secretsmanager_get_value": ChainCategory.CREDENTIAL_EXPOSURE,
    "sts_get_federation_token": ChainCategory.CREDENTIAL_EXPOSURE,
    "sts_get_session_token": ChainCategory.CREDENTIAL_EXPOSURE,
    "rds_iam_auth_token": ChainCategory.CREDENTIAL_EXPOSURE,
    "saml_oidc_provider_manipulation": ChainCategory.CREDENTIAL_EXPOSURE,
    
    # === Resource Hijack (10+ patterns) ===
    "update_function_code": ChainCategory.RESOURCE_HIJACK,
    "update_function_configuration": ChainCategory.RESOURCE_HIJACK,
    "lambda_layer": ChainCategory.RESOURCE_HIJACK,
    "modify_instance_attribute": ChainCategory.RESOURCE_HIJACK,
    "apigateway_integration_abuse": ChainCategory.RESOURCE_HIJACK,
    "cloudwatch_events_target": ChainCategory.RESOURCE_HIJACK,
    "eventbridge_lambda_trigger": ChainCategory.RESOURCE_HIJACK,
    "eks_update_cluster_config": ChainCategory.RESOURCE_HIJACK,
    "eks_wildcard_permissions": ChainCategory.RESOURCE_HIJACK,
    
    # === Data Exfiltration (10+ patterns) ===
    "s3_bucket_notification": ChainCategory.DATA_EXFILTRATION,
    "dynamodb_stream": ChainCategory.DATA_EXFILTRATION,
    "dynamodb_stream_lambda": ChainCategory.DATA_EXFILTRATION,
    "rds_snapshot": ChainCategory.DATA_EXFILTRATION,
    "rds_snapshot_export": ChainCategory.DATA_EXFILTRATION,
    "athena_query": ChainCategory.DATA_EXFILTRATION,
    "redshift_snapshot": ChainCategory.DATA_EXFILTRATION,
    "kinesis_stream": ChainCategory.DATA_EXFILTRATION,
    "firehose_delivery": ChainCategory.DATA_EXFILTRATION,
    "glue_catalog": ChainCategory.DATA_EXFILTRATION,
    
    # === Lateral Movement (10+ patterns) ===
    "update_assume_role_policy": ChainCategory.LATERAL_MOVEMENT,
    "sts_assume_role": ChainCategory.LATERAL_MOVEMENT,
    "sts_assume": ChainCategory.LATERAL_MOVEMENT,
    "cross_account_role": ChainCategory.LATERAL_MOVEMENT,
    "organization_account_access": ChainCategory.LATERAL_MOVEMENT,
    
    # === Persistence (5+ patterns) ===
    "backdoor_lambda": ChainCategory.PERSISTENCE,
    "backdoor_user": ChainCategory.PERSISTENCE,
    "backdoor_role": ChainCategory.PERSISTENCE,
    "eventbridge_scheduled": ChainCategory.PERSISTENCE,
    "cloudwatch_alarm_action": ChainCategory.PERSISTENCE,
}

# MITRE ATT&CK Technique Mapping (30+ techniques)
MITRE_TECHNIQUE_MAP = {
    # PassRole chains
    "passrole_lambda": ["T1078.004", "T1059.006"],       # Cloud Accounts, Python
    "passrole_ec2": ["T1078.004", "T1552.005"],          # Cloud Accounts, IMDS
    "passrole_ecs": ["T1078.004", "T1610"],              # Cloud Accounts, Container Deploy
    "passrole_glue": ["T1078.004", "T1059"],             # Cloud Accounts, Command Exec
    "passrole_codebuild": ["T1078.004", "T1072"],        # Cloud Accounts, Software Deploy
    "passrole_sagemaker": ["T1078.004", "T1059"],        # Cloud Accounts, Command Exec
    "passrole_stepfunctions": ["T1078.004", "T1059"],    # Cloud Accounts, Command Exec
    "passrole_batch": ["T1078.004", "T1059"],            # Cloud Accounts, Command Exec
    "passrole_emr": ["T1078.004", "T1059"],              # Cloud Accounts, Command Exec
    "eks_passrole": ["T1078.004", "T1610", "T1611"],     # Escape to Host
    "eks_irsa_pod_exec": ["T1078.004", "T1552.007"],     # Container API
    
    # Policy manipulation
    "create_policy_version": ["T1098.001"],              # Additional Cloud Credentials
    "set_default_policy_version": ["T1098.001"],
    "put_user_policy": ["T1098.001"],
    "put_role_policy": ["T1098.001"],
    "put_group_policy": ["T1098.001"],
    "attach_user_policy": ["T1098.001"],
    "attach_role_policy": ["T1098.001"],
    "attach_group_policy": ["T1098.001"],
    "add_user_to_group": ["T1098.001", "T1136.003"],     # Create Cloud Account
    "permission_boundary_bypass": ["T1098.001"],
    "delete_account_password_policy": ["T1098.001"],
    "tag_based_access_bypass": ["T1098.001"],
    "create_policy_attach_combo": ["T1098.001"],
    
    # Credential exposure
    "create_access_key": ["T1098.001", "T1136.003"],     # Create Cloud Account
    "create_login_profile": ["T1098.001", "T1136.003"],
    "update_login_profile": ["T1098.001"],
    "ssm_send_command": ["T1059", "T1021.007"],          # Remote Services: Cloud API
    "ssm_start_session": ["T1059", "T1021.007"],
    "ssm_get_parameter": ["T1552.001"],                  # Credentials In Files
    "secretsmanager_get_value": ["T1552.001"],
    "ec2_instance_connect": ["T1078.004", "T1021.004"],  # SSH
    "codecommit_git_credentials": ["T1552.001", "T1213"], # Data from Info Repos
    "sts_get_federation_token": ["T1550.001"],           # Alternate Auth
    "saml_oidc_provider_manipulation": ["T1550.001", "T1606.002"], # SAML Tokens
    
    # Resource hijack
    "update_function_code": ["T1059.006", "T1546"],      # Event Triggered Execution
    "update_function_configuration": ["T1059.006"],
    "lambda_layer": ["T1059.006", "T1195.002"],          # Supply Chain: Software
    "apigateway_integration_abuse": ["T1190"],           # Exploit Public App
    "eventbridge_lambda_trigger": ["T1546.015"],         # Event Triggered
    "cloudwatch_events_target": ["T1546.015"],
    
    # Data exfiltration
    "s3_bucket_notification": ["T1537", "T1567"],        # Exfil to Cloud
    "dynamodb_stream": ["T1537", "T1567"],
    "rds_snapshot": ["T1537", "T1530"],                  # Data from Cloud Storage
    "rds_snapshot_export": ["T1537", "T1530"],
    "athena_query": ["T1530"],
    "kinesis_stream": ["T1537"],
    
    # Lateral movement
    "update_assume_role_policy": ["T1550.001"],          # Use Alternate Auth
    "sts_assume_role": ["T1550.001", "T1078.004"],
    "cross_account_role": ["T1550.001", "T1078.004"],
    
    # Persistence
    "backdoor_lambda": ["T1546.015", "T1098"],           # Persistence
    "backdoor_user": ["T1098.001", "T1136.003"],
    "eventbridge_scheduled": ["T1053.007"],              # Scheduled Task/Job
}

# High-value target patterns for blast radius
HIGH_VALUE_TARGETS = {
    "admin", "administrator", "root", "superuser", "prod", "production",
    "master", "main", "deploy", "cicd", "pipeline", "secret", "key",
    "database", "rds", "dynamo", "billing", "security", "audit",
    "terraform", "cloudformation", "iac", "infra", "network", "vpc",
    "org", "organization", "management", "payer", "backup", "disaster"
}


class AttackChainBuilder:
    """Builds attack chains from IAM findings."""
    
    def __init__(self, graph_data: Optional[Dict] = None):
        self.graph_data = graph_data or {}
        self._chain_counter = 0
    
    def build_from_findings(self, findings: List[Dict], min_severity: str = "LOW") -> List[AttackChain]:
        """Build all attack chains from findings."""
        chains = []
        by_principal = self._group_by_principal(findings)
        
        for principal, pfindings in by_principal.items():
            chains.extend(self._build_for_principal(principal, pfindings))
        
        chains.sort(key=lambda c: c.risk_score, reverse=True)
        logger.info("Built %d chains from %d findings", len(chains), len(findings))
        return chains
    
    def build_for_principal(self, findings: List[Dict], principal: str) -> List[AttackChain]:
        """Build chains for specific principal."""
        pfindings = [f for f in findings if self._matches_principal(f, principal)]
        return self._build_for_principal(principal, pfindings) if pfindings else []
    
    def _build_for_principal(self, principal: str, findings: List[Dict]) -> List[AttackChain]:
        """Build chains for a single principal."""
        chains = []
        by_method = self._group_by_method(findings)
        
        for method, mfindings in by_method.items():
            chain = self._build_chain(principal, method, mfindings)
            if chain:
                chains.append(chain)
        
        # Add compound chains
        chains.extend(self._find_compound_chains(principal, findings))
        return chains
    
    def _build_chain(self, principal: str, method: str, findings: List[Dict]) -> Optional[AttackChain]:
        """Build single chain from findings."""
        if not findings:
            return None
        
        primary = findings[0]
        self._chain_counter += 1
        
        category = self._get_category(method)
        steps = self._build_steps(principal, method, primary)
        severity = self._get_severity(primary)
        
        chain = AttackChain(
            chain_id=f"chain_{self._chain_counter:04d}",
            category=category,
            title=self._get_title(method, primary),
            description=primary.get('description', 'Privilege escalation path'),
            source_principal=principal,
            target_objective=self._get_objective(category),
            steps=steps,
            severity=severity,
            privesc_methods=[f.get('privesc_method', '') for f in findings],
            mitre_techniques=self._get_mitre_techniques(method),
            remediation_steps=[primary.get('remediation', '')],
            quick_win=primary.get('remediation', 'Restrict permissions'),
        )
        
        chain.blast_radius = self._calc_blast_radius(principal, findings)
        return chain
    
    def _build_steps(self, principal: str, method: str, finding: Dict) -> List[AttackStep]:
        """Build attack steps based on method type - service-specific detailed chains."""
        method_lower = method.lower()
        target = finding.get('target_role_name', 'target-role')
        sev = self._get_severity(finding)
        
        # === PASSROLE CHAINS (Service-specific) ===
        if 'passrole' in method_lower and 'lambda' in method_lower:
            return [
                AttackStep(1, "iam:PassRole", "iam", f"Pass {target} to Lambda service", principal, target, Severity.HIGH),
                AttackStep(2, "lambda:CreateFunction", "lambda", "Create Lambda with malicious code", principal, severity=Severity.HIGH),
                AttackStep(3, "lambda:InvokeFunction", "lambda", "Trigger Lambda execution", principal, severity=Severity.HIGH),
                AttackStep(4, "Code executes as role", "lambda", f"Malicious code runs with {target} permissions", target, severity=Severity.CRITICAL, execution_type="service_execution", assumed_role=target),
                AttackStep(5, "Access AWS resources", "multiple", f"Read S3, Secrets, DynamoDB as {target}", target, severity=Severity.CRITICAL, execution_type="assumed_role"),
            ]
        
        if 'passrole' in method_lower and 'ec2' in method_lower:
            return [
                AttackStep(1, "iam:PassRole", "iam", f"Pass {target} to EC2 service", principal, target, Severity.HIGH),
                AttackStep(2, "ec2:RunInstances", "ec2", f"Launch EC2 with {target} instance profile", principal, severity=Severity.HIGH),
                AttackStep(3, "SSH/SSM connect", "ec2", "Connect to instance via SSH or SSM", "attacker", severity=Severity.HIGH),
                AttackStep(4, "curl IMDS", "ec2", "Query http://169.254.169.254/latest/meta-data/iam/", "attacker", severity=Severity.CRITICAL),
                AttackStep(5, "Steal credentials", "ec2", f"Retrieve {target} temporary credentials from IMDS", "attacker", severity=Severity.CRITICAL),
                AttackStep(6, "Use stolen creds", "aws", f"Authenticate as {target} from anywhere", target, severity=Severity.CRITICAL, execution_type="assumed_role"),
            ]
        
        if 'passrole' in method_lower and 'ecs' in method_lower:
            return [
                AttackStep(1, "iam:PassRole", "iam", f"Pass {target} as ECS task role", principal, target, Severity.HIGH),
                AttackStep(2, "ecs:RegisterTaskDefinition", "ecs", "Create malicious task definition", principal, severity=Severity.HIGH),
                AttackStep(3, "ecs:RunTask", "ecs", "Run task with privileged role", principal, severity=Severity.HIGH),
                AttackStep(4, "Container executes", "ecs", f"Container runs with {target} credentials", target, severity=Severity.CRITICAL, execution_type="service_execution", assumed_role=target),
                AttackStep(5, "Exfiltrate data", "multiple", "Access S3, RDS, Secrets from container", target, severity=Severity.CRITICAL),
            ]
        
        if 'passrole' in method_lower and 'glue' in method_lower:
            return [
                AttackStep(1, "iam:PassRole", "iam", f"Pass {target} to Glue service", principal, target, Severity.HIGH),
                AttackStep(2, "glue:CreateJob", "glue", "Create Glue ETL job with malicious script", principal, severity=Severity.HIGH),
                AttackStep(3, "glue:StartJobRun", "glue", "Execute Glue job", principal, severity=Severity.HIGH),
                AttackStep(4, "PySpark executes", "glue", f"Job runs with {target} - access data lakes", target, severity=Severity.CRITICAL, execution_type="service_execution", assumed_role=target),
            ]
        
        if 'passrole' in method_lower and 'codebuild' in method_lower:
            return [
                AttackStep(1, "iam:PassRole", "iam", f"Pass {target} to CodeBuild", principal, target, Severity.HIGH),
                AttackStep(2, "codebuild:CreateProject", "codebuild", "Create build project with role", principal, severity=Severity.HIGH),
                AttackStep(3, "codebuild:StartBuild", "codebuild", "Trigger build with malicious buildspec", principal, severity=Severity.HIGH),
                AttackStep(4, "Build container runs", "codebuild", f"Build commands execute as {target}", target, severity=Severity.CRITICAL, execution_type="service_execution", assumed_role=target),
                AttackStep(5, "Deploy backdoor", "codebuild", "Inject code into CI/CD artifacts", target, severity=Severity.CRITICAL),
            ]
        
        if 'passrole' in method_lower and 'sagemaker' in method_lower:
            return [
                AttackStep(1, "iam:PassRole", "iam", f"Pass {target} to SageMaker", principal, target, Severity.HIGH),
                AttackStep(2, "sagemaker:CreateNotebookInstance", "sagemaker", "Create notebook with role", principal, severity=Severity.HIGH),
                AttackStep(3, "Access notebook", "sagemaker", "Open Jupyter notebook interface", "attacker", severity=Severity.HIGH),
                AttackStep(4, "Execute code", "sagemaker", f"Run Python with {target} creds", target, severity=Severity.CRITICAL, execution_type="service_execution", assumed_role=target),
            ]
        
        if 'passrole' in method_lower and 'cloudformation' in method_lower:
            return [
                AttackStep(1, "iam:PassRole", "iam", f"Pass {target} to CloudFormation", principal, target, Severity.HIGH),
                AttackStep(2, "cloudformation:CreateStack", "cloudformation", "Create stack with admin role", principal, severity=Severity.HIGH),
                AttackStep(3, "Stack deploys resources", "cloudformation", f"Resources created with {target} permissions", target, severity=Severity.CRITICAL, execution_type="service_execution", assumed_role=target),
                AttackStep(4, "Backdoor deployed", "cloudformation", "Malicious Lambda/EC2 deployed via IaC", target, severity=Severity.CRITICAL),
            ]
        
        # Generic PassRole
        if 'passrole' in method_lower:
            service = self._extract_service(method_lower)
            return [
                AttackStep(1, "iam:PassRole", "iam", f"Pass {target} to {service}", principal, target, Severity.HIGH),
                AttackStep(2, f"{service}:Create*", service, f"Create {service} resource with role", principal, severity=Severity.HIGH),
                AttackStep(3, "Execute with role", service, f"Resource executes with {target} permissions", target, severity=Severity.CRITICAL, execution_type="service_execution", assumed_role=target),
                AttackStep(4, "Access resources", "multiple", f"Access S3, Secrets, RDS as {target}", target, severity=Severity.CRITICAL, execution_type="assumed_role"),
            ]
        
        # === POLICY MANIPULATION ===
        if 'attach' in method_lower and 'policy' in method_lower:
            target_type = "user" if "user" in method_lower else "role" if "role" in method_lower else "group"
            return [
                AttackStep(1, self._method_to_action(method), "iam", f"Attach AdministratorAccess to {target_type}", principal, severity=Severity.CRITICAL),
                AttackStep(2, "Wait for propagation", "iam", "Policy attachment propagates (~1s)", principal, severity=Severity.LOW),
                AttackStep(3, "*:*", "all", "Execute any AWS action with full permissions", principal, severity=Severity.CRITICAL),
            ]
        
        if 'put' in method_lower and 'policy' in method_lower:
            return [
                AttackStep(1, self._method_to_action(method), "iam", "Create inline policy with {Action: *, Resource: *}", principal, severity=Severity.CRITICAL),
                AttackStep(2, "*:*", "all", "Execute with admin permissions", principal, severity=Severity.CRITICAL),
            ]
        
        if 'create_policy_version' in method_lower:
            return [
                AttackStep(1, "iam:CreatePolicyVersion", "iam", "Create new policy version with admin perms", principal, severity=Severity.CRITICAL),
                AttackStep(2, "New version active", "iam", "Policy v2 becomes default (SetAsDefault=true)", principal, severity=Severity.HIGH),
                AttackStep(3, "*:*", "all", "All attached principals now have admin", principal, severity=Severity.CRITICAL),
            ]
        
        # === CREDENTIAL EXPOSURE ===
        if 'access_key' in method_lower:
            return [
                AttackStep(1, "iam:CreateAccessKey", "iam", "Generate new access key for target user", principal, severity=Severity.CRITICAL),
                AttackStep(2, "Retrieve key", "iam", "Capture AccessKeyId + SecretAccessKey", "attacker", severity=Severity.CRITICAL),
                AttackStep(3, "Configure CLI", "aws", "aws configure with stolen credentials", "attacker", severity=Severity.HIGH),
                AttackStep(4, "Persistent access", "aws", "Access AWS as target user indefinitely", "target-user", severity=Severity.CRITICAL, execution_type="credential_use"),
            ]
        
        if 'login_profile' in method_lower:
            action = "Create" if "create" in method_lower else "Update"
            return [
                AttackStep(1, f"iam:{action}LoginProfile", "iam", f"{action} console password for target user", principal, severity=Severity.CRITICAL),
                AttackStep(2, "Access console", "aws", "Login to AWS Console with new password", "attacker", severity=Severity.CRITICAL),
                AttackStep(3, "Full console access", "aws", "Browse resources, modify settings via GUI", "target-user", severity=Severity.CRITICAL),
            ]
        
        if 'ssm' in method_lower:
            return [
                AttackStep(1, "ssm:SendCommand", "ssm", "Send command to managed EC2 instances", principal, severity=Severity.HIGH),
                AttackStep(2, "Command executes", "ec2", "Shell command runs on target instance", "instance", severity=Severity.CRITICAL),
                AttackStep(3, "curl IMDS", "ec2", "Retrieve instance role credentials", "attacker", severity=Severity.CRITICAL),
                AttackStep(4, "Lateral movement", "aws", "Use stolen creds to access other resources", "instance-role", severity=Severity.CRITICAL),
            ]
        
        if 'ec2_user_data' in method_lower or 'user_data' in method_lower:
            return [
                AttackStep(1, "ec2:ModifyInstanceAttribute", "ec2", "Modify instance user data", principal, severity=Severity.HIGH),
                AttackStep(2, "Stop/Start instance", "ec2", "Reboot instance to execute new user data", principal, severity=Severity.HIGH),
                AttackStep(3, "Backdoor executes", "ec2", "Malicious script runs as root on boot", "root", severity=Severity.CRITICAL),
                AttackStep(4, "Steal credentials", "ec2", "Exfiltrate instance role credentials", "attacker", severity=Severity.CRITICAL),
            ]
        
        # === RESOURCE HIJACK ===
        if 'update_function_code' in method_lower:
            return [
                AttackStep(1, "lambda:UpdateFunctionCode", "lambda", "Replace Lambda code with backdoor", principal, severity=Severity.CRITICAL),
                AttackStep(2, "Wait for trigger", "lambda", "Function invoked by API/Event/Schedule", "trigger", severity=Severity.MEDIUM),
                AttackStep(3, "Backdoor executes", "lambda", "Malicious code runs with function's role", "lambda-role", severity=Severity.CRITICAL, execution_type="service_execution"),
                AttackStep(4, "Exfiltrate data", "lambda", "Send data to attacker endpoint", "attacker", severity=Severity.CRITICAL),
            ]
        
        if 'lambda_layer' in method_lower:
            return [
                AttackStep(1, "lambda:PublishLayerVersion", "lambda", "Publish malicious Lambda layer", principal, severity=Severity.HIGH),
                AttackStep(2, "lambda:UpdateFunctionConfiguration", "lambda", "Attach layer to target function", principal, severity=Severity.HIGH),
                AttackStep(3, "Function invoked", "lambda", "Layer code executes before handler", "lambda-role", severity=Severity.CRITICAL),
            ]
        
        # === RESOURCE HIJACK (continued) ===
        if 'apigateway' in method_lower:
            return [
                AttackStep(1, "apigateway:UpdateIntegration", "apigateway", "Modify API Gateway integration", principal, severity=Severity.HIGH),
                AttackStep(2, "Redirect traffic", "apigateway", "Route API calls to attacker endpoint", principal, severity=Severity.CRITICAL),
                AttackStep(3, "Intercept requests", "external", "Capture API keys, tokens, data", "attacker", severity=Severity.CRITICAL),
                AttackStep(4, "Credential harvesting", "external", "Collect user credentials from requests", "attacker", severity=Severity.CRITICAL),
            ]
        
        if 'eventbridge' in method_lower or 'cloudwatch_events' in method_lower:
            return [
                AttackStep(1, "events:PutTargets", "eventbridge", "Add malicious target to EventBridge rule", principal, severity=Severity.HIGH),
                AttackStep(2, "Event triggers", "eventbridge", "Scheduled/pattern event fires", "eventbridge", severity=Severity.LOW),
                AttackStep(3, "Attacker Lambda invoked", "lambda", "Malicious function receives event data", "attacker-lambda", severity=Severity.CRITICAL),
                AttackStep(4, "Data exfiltrated", "external", "Sensitive event data sent to attacker", "attacker", severity=Severity.CRITICAL),
            ]
        
        # === DATA EXFILTRATION ===
        if 's3_bucket_notification' in method_lower:
            return [
                AttackStep(1, "s3:PutBucketNotificationConfiguration", "s3", "Configure S3 event notification", principal, severity=Severity.HIGH),
                AttackStep(2, "Object uploaded", "s3", "New object triggers notification", "user", severity=Severity.LOW),
                AttackStep(3, "Lambda receives event", "lambda", "Attacker's Lambda gets object metadata", "attacker-lambda", severity=Severity.CRITICAL),
                AttackStep(4, "Data copied", "s3", "Object copied to attacker bucket", "attacker", severity=Severity.CRITICAL),
            ]
        
        if 'dynamodb_stream' in method_lower:
            return [
                AttackStep(1, "dynamodb:UpdateTable", "dynamodb", "Enable DynamoDB Streams", principal, severity=Severity.HIGH),
                AttackStep(2, "lambda:CreateEventSourceMapping", "lambda", "Connect stream to attacker Lambda", principal, severity=Severity.HIGH),
                AttackStep(3, "Data changes", "dynamodb", "New/modified items trigger stream", "application", severity=Severity.LOW),
                AttackStep(4, "Data exfiltrated", "lambda", "All changes sent to attacker", "attacker", severity=Severity.CRITICAL),
            ]
        
        if 'rds_snapshot' in method_lower:
            return [
                AttackStep(1, "rds:CreateDBSnapshot", "rds", "Create snapshot of production database", principal, severity=Severity.HIGH),
                AttackStep(2, "rds:ModifyDBSnapshotAttribute", "rds", "Share snapshot with attacker AWS account", principal, severity=Severity.CRITICAL),
                AttackStep(3, "rds:CopyDBSnapshot", "rds", "Copy snapshot to attacker account", "attacker-account", severity=Severity.CRITICAL),
                AttackStep(4, "rds:RestoreDBInstanceFromSnapshot", "rds", "Restore DB in attacker account", "attacker", severity=Severity.CRITICAL),
                AttackStep(5, "Data extraction", "rds", "Query and export all database data", "attacker", severity=Severity.CRITICAL),
            ]
        
        if 'secretsmanager' in method_lower or 'get_secret' in method_lower:
            return [
                AttackStep(1, "secretsmanager:ListSecrets", "secretsmanager", "Enumerate all secrets", principal, severity=Severity.MEDIUM),
                AttackStep(2, "secretsmanager:GetSecretValue", "secretsmanager", "Retrieve secret values (DB creds, API keys)", principal, severity=Severity.CRITICAL),
                AttackStep(3, "Exfiltrate secrets", "external", "Send secrets to attacker endpoint", "attacker", severity=Severity.CRITICAL),
                AttackStep(4, "Use credentials", "multiple", "Access databases, APIs with stolen creds", "attacker", severity=Severity.CRITICAL),
            ]
        
        if 'ssm_get_parameter' in method_lower or 'get_parameter' in method_lower:
            return [
                AttackStep(1, "ssm:GetParametersByPath", "ssm", "List all Parameter Store parameters", principal, severity=Severity.MEDIUM),
                AttackStep(2, "ssm:GetParameter", "ssm", "Retrieve parameter values (with decryption)", principal, severity=Severity.CRITICAL),
                AttackStep(3, "Exfiltrate parameters", "external", "Extract sensitive config and secrets", "attacker", severity=Severity.CRITICAL),
            ]
        
        if 'athena' in method_lower:
            return [
                AttackStep(1, "athena:StartQueryExecution", "athena", "Execute SQL query on data lake", principal, severity=Severity.HIGH),
                AttackStep(2, "athena:GetQueryResults", "athena", "Retrieve query results", principal, severity=Severity.CRITICAL),
                AttackStep(3, "s3:GetObject", "s3", "Download query results from S3", principal, severity=Severity.CRITICAL),
                AttackStep(4, "Data exfiltration", "external", "Export sensitive data from data lake", "attacker", severity=Severity.CRITICAL),
            ]
        
        if 'kinesis' in method_lower:
            return [
                AttackStep(1, "kinesis:DescribeStream", "kinesis", "Enumerate Kinesis streams", principal, severity=Severity.LOW),
                AttackStep(2, "kinesis:GetShardIterator", "kinesis", "Get stream shard iterator", principal, severity=Severity.MEDIUM),
                AttackStep(3, "kinesis:GetRecords", "kinesis", "Read real-time streaming data", principal, severity=Severity.CRITICAL),
                AttackStep(4, "Data exfiltration", "external", "Capture streaming data (logs, events, metrics)", "attacker", severity=Severity.CRITICAL),
            ]
        
        # === CREDENTIAL EXPOSURE (continued) ===
        if 'codecommit' in method_lower:
            return [
                AttackStep(1, "iam:CreateServiceSpecificCredential", "iam", "Create CodeCommit Git credentials", principal, severity=Severity.HIGH),
                AttackStep(2, "codecommit:ListRepositories", "codecommit", "Enumerate all Git repositories", principal, severity=Severity.MEDIUM),
                AttackStep(3, "git clone", "codecommit", "Clone repositories with credentials", "attacker", severity=Severity.CRITICAL),
                AttackStep(4, "Search for secrets", "local", "grep for API keys, passwords in code", "attacker", severity=Severity.CRITICAL),
            ]
        
        if 'sts_get_federation' in method_lower or 'federation_token' in method_lower:
            return [
                AttackStep(1, "sts:GetFederationToken", "sts", "Generate federated temporary credentials", principal, severity=Severity.HIGH),
                AttackStep(2, "Credentials valid 12h", "sts", "Federated creds with custom policy", principal, severity=Severity.HIGH),
                AttackStep(3, "Access AWS Console", "aws", "Use federation URL for console access", "attacker", severity=Severity.CRITICAL),
                AttackStep(4, "Evade detection", "aws", "Actions logged under federated session", "attacker", severity=Severity.HIGH),
            ]
        
        if 'saml' in method_lower or 'oidc' in method_lower:
            return [
                AttackStep(1, "iam:CreateSAMLProvider/CreateOpenIDConnectProvider", "iam", "Create malicious identity provider", principal, severity=Severity.CRITICAL),
                AttackStep(2, "iam:UpdateAssumeRolePolicy", "iam", "Allow IdP to assume roles", principal, severity=Severity.CRITICAL),
                AttackStep(3, "sts:AssumeRoleWithSAML/OIDC", "sts", "Assume role via malicious IdP", "attacker-idp", severity=Severity.CRITICAL),
                AttackStep(4, "Persistent access", "aws", "Maintain access via external identity", "attacker", severity=Severity.CRITICAL),
            ]
        
        # === LATERAL MOVEMENT ===
        if 'update_assume_role_policy' in method_lower:
            return [
                AttackStep(1, "iam:UpdateAssumeRolePolicy", "iam", "Modify role trust policy", principal, severity=Severity.CRITICAL),
                AttackStep(2, "Add self to trust", "iam", "Allow attacker principal to assume role", principal, severity=Severity.CRITICAL),
                AttackStep(3, "sts:AssumeRole", "sts", "Assume the modified role", principal, severity=Severity.HIGH),
                AttackStep(4, "Elevated access", "aws", "Operate with role's permissions", "target-role", severity=Severity.CRITICAL, execution_type="assumed_role"),
            ]
        
        # === GENERIC FALLBACK ===
        return [
            AttackStep(1, self._method_to_action(method), "iam", finding.get('description', 'Privilege escalation'), principal, severity=sev),
            AttackStep(2, "Elevated access", "aws", "Attacker gains privileges", principal, severity=Severity.CRITICAL),
        ]
    
    def _find_compound_chains(self, principal: str, findings: List[Dict]) -> List[AttackChain]:
        """Find multi-technique compound chains - complex attack scenarios."""
        chains = []
        methods = {f.get('privesc_method', '').lower() for f in findings}
        
        # === COMPOUND CHAIN 1: PassRole + Lambda → Secrets Exfiltration ===
        if any('passrole' in m and 'lambda' in m for m in methods):
            self._chain_counter += 1
            chain = AttackChain(
                chain_id=f"chain_{self._chain_counter:04d}",
                category=ChainCategory.DATA_EXFILTRATION,
                title="🔓 Secrets Exfiltration via Lambda",
                description="Chain PassRole to Lambda to access Secrets Manager, Parameter Store, or environment variables",
                source_principal=principal,
                target_objective="secrets exfiltration",
                steps=[
                    AttackStep(1, "iam:PassRole", "iam", "Pass role with secrets access to Lambda", principal, severity=Severity.HIGH),
                    AttackStep(2, "lambda:CreateFunction", "lambda", "Create Lambda with exfil code", principal, severity=Severity.HIGH),
                    AttackStep(3, "lambda:InvokeFunction", "lambda", "Trigger the Lambda function", principal, severity=Severity.HIGH),
                    AttackStep(4, "secretsmanager:GetSecretValue", "secretsmanager", "Retrieve database credentials", "lambda-role", severity=Severity.CRITICAL, execution_type="service_execution"),
                    AttackStep(5, "ssm:GetParameter", "ssm", "Read Parameter Store secrets", "lambda-role", severity=Severity.CRITICAL),
                    AttackStep(6, "Exfiltrate", "external", "Send secrets to attacker endpoint", "attacker", severity=Severity.CRITICAL),
                ],
                severity=Severity.CRITICAL,
                mitre_techniques=["T1078.004", "T1552.005", "T1041"],
                quick_win="Add resource constraints to iam:PassRole and use Secrets Manager resource policies",
            )
            chain.blast_radius = self._calc_blast_radius(principal, findings)
            chains.append(chain)
        
        # === COMPOUND CHAIN 2: Policy Manipulation → Full Admin ===
        if any('policy' in m for m in methods):
            self._chain_counter += 1
            chain = AttackChain(
                chain_id=f"chain_{self._chain_counter:04d}",
                category=ChainCategory.POLICY_MANIPULATION,
                title="⚠️ IAM Policy → Administrator Access",
                description="Modify IAM policies to grant full administrator access to AWS account",
                source_principal=principal,
                target_objective="full administrator access",
                steps=[
                    AttackStep(1, "iam:*Policy*", "iam", "Create/attach/modify IAM policy", principal, severity=Severity.CRITICAL),
                    AttackStep(2, "Policy grants *:*", "iam", "New policy allows all actions on all resources", principal, severity=Severity.CRITICAL),
                    AttackStep(3, "iam:*", "iam", "Create backdoor users, roles, keys", principal, severity=Severity.CRITICAL),
                    AttackStep(4, "s3:*", "s3", "Access all S3 buckets", principal, severity=Severity.CRITICAL),
                    AttackStep(5, "rds:*", "rds", "Access all databases", principal, severity=Severity.CRITICAL),
                ],
                severity=Severity.CRITICAL,
                mitre_techniques=["T1098.001", "T1078.004"],
                quick_win="Remove iam:*Policy* permissions; use SCPs to deny policy modifications",
            )
            chain.blast_radius = self._calc_blast_radius(principal, findings)
            chains.append(chain)
        
        # === COMPOUND CHAIN 3: Credential Chain → Lateral Movement ===
        if any('access_key' in m or 'login_profile' in m for m in methods):
            self._chain_counter += 1
            chain = AttackChain(
                chain_id=f"chain_{self._chain_counter:04d}",
                category=ChainCategory.CREDENTIAL_EXPOSURE,
                title="🔑 Credential Chain → Account Takeover",
                description="Create credentials for privileged users to gain persistent access",
                source_principal=principal,
                target_objective="persistent account access",
                steps=[
                    AttackStep(1, "iam:ListUsers", "iam", "Enumerate all IAM users", principal, severity=Severity.LOW),
                    AttackStep(2, "iam:ListAttachedUserPolicies", "iam", "Find users with admin policies", principal, severity=Severity.MEDIUM),
                    AttackStep(3, "iam:CreateAccessKey", "iam", "Create access key for admin user", principal, severity=Severity.CRITICAL),
                    AttackStep(4, "Use admin creds", "aws", "Authenticate as admin user", "admin-user", severity=Severity.CRITICAL, execution_type="credential_use"),
                    AttackStep(5, "Create backdoor", "iam", "Create new admin user for persistence", "admin-user", severity=Severity.CRITICAL),
                ],
                severity=Severity.CRITICAL,
                mitre_techniques=["T1098.001", "T1136.003", "T1078"],
                quick_win="Restrict iam:CreateAccessKey to self only: Resource: arn:aws:iam::*:user/${aws:username}",
            )
            chain.blast_radius = self._calc_blast_radius(principal, findings)
            chains.append(chain)
        
        # === COMPOUND CHAIN 4: EC2 → IMDS → Cross-Service ===
        if any('passrole' in m and 'ec2' in m for m in methods):
            self._chain_counter += 1
            chain = AttackChain(
                chain_id=f"chain_{self._chain_counter:04d}",
                category=ChainCategory.PASSROLE_EXECUTION,
                title="💻 EC2 IMDS → Cross-Service Pivot",
                description="Launch EC2, steal credentials via IMDS, pivot to other services",
                source_principal=principal,
                target_objective="cross-service access",
                steps=[
                    AttackStep(1, "iam:PassRole + ec2:RunInstances", "ec2", "Launch EC2 with admin role", principal, severity=Severity.HIGH),
                    AttackStep(2, "SSH to instance", "ec2", "Connect to running instance", "attacker", severity=Severity.HIGH),
                    AttackStep(3, "curl IMDS v1", "ec2", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "attacker", severity=Severity.CRITICAL),
                    AttackStep(4, "Export credentials", "ec2", "AWS_ACCESS_KEY_ID, SECRET, TOKEN", "attacker", severity=Severity.CRITICAL),
                    AttackStep(5, "s3:ListBuckets", "s3", "Enumerate S3 from stolen creds", "instance-role", severity=Severity.HIGH),
                    AttackStep(6, "secretsmanager:ListSecrets", "secretsmanager", "Find secrets to exfiltrate", "instance-role", severity=Severity.CRITICAL),
                ],
                severity=Severity.CRITICAL,
                mitre_techniques=["T1078.004", "T1552.005", "T1021.007"],
                quick_win="Require IMDSv2 (HttpTokens=required); restrict PassRole to specific roles",
            )
            chain.blast_radius = self._calc_blast_radius(principal, findings)
            chains.append(chain)
        
        # === COMPOUND CHAIN 5: SSM → Instance → Lateral ===
        if any('ssm' in m for m in methods):
            self._chain_counter += 1
            chain = AttackChain(
                chain_id=f"chain_{self._chain_counter:04d}",
                category=ChainCategory.CREDENTIAL_EXPOSURE,
                title="🖥️ SSM → Instance Compromise → Lateral Movement",
                description="Use SSM to execute commands on EC2, steal role credentials, pivot",
                source_principal=principal,
                target_objective="lateral movement via EC2",
                steps=[
                    AttackStep(1, "ssm:DescribeInstanceInformation", "ssm", "Find SSM-managed instances", principal, severity=Severity.LOW),
                    AttackStep(2, "ssm:SendCommand", "ssm", "Send reverse shell command", principal, severity=Severity.HIGH),
                    AttackStep(3, "Shell on instance", "ec2", "Attacker has shell access", "attacker", severity=Severity.CRITICAL),
                    AttackStep(4, "Steal instance role", "ec2", "Retrieve credentials from IMDS", "attacker", severity=Severity.CRITICAL),
                    AttackStep(5, "Access other services", "aws", "Use instance role for S3, DynamoDB, etc.", "instance-role", severity=Severity.CRITICAL),
                ],
                severity=Severity.CRITICAL,
                mitre_techniques=["T1059", "T1021.007", "T1552.005"],
                quick_win="Restrict ssm:SendCommand to specific instances; monitor SSM sessions",
            )
            chain.blast_radius = self._calc_blast_radius(principal, findings)
            chains.append(chain)
        
        # === COMPOUND CHAIN 6: CloudFormation → Infrastructure Backdoor ===
        if any('cloudformation' in m for m in methods):
            self._chain_counter += 1
            chain = AttackChain(
                chain_id=f"chain_{self._chain_counter:04d}",
                category=ChainCategory.PERSISTENCE,
                title="📦 CloudFormation → Infrastructure Backdoor",
                description="Use CloudFormation to deploy persistent backdoor infrastructure",
                source_principal=principal,
                target_objective="persistent infrastructure access",
                steps=[
                    AttackStep(1, "iam:PassRole", "iam", "Pass admin role to CloudFormation", principal, severity=Severity.HIGH),
                    AttackStep(2, "cloudformation:CreateStack", "cloudformation", "Deploy malicious template", principal, severity=Severity.HIGH),
                    AttackStep(3, "Lambda deployed", "lambda", "Backdoor Lambda created by stack", "cfn-role", severity=Severity.CRITICAL),
                    AttackStep(4, "EC2 deployed", "ec2", "Attacker-controlled EC2 in VPC", "cfn-role", severity=Severity.CRITICAL),
                    AttackStep(5, "IAM role created", "iam", "Persistent admin role for attacker", "cfn-role", severity=Severity.CRITICAL),
                ],
                severity=Severity.CRITICAL,
                mitre_techniques=["T1078.004", "T1098", "T1136"],
                quick_win="Restrict cloudformation:CreateStack; require template review",
            )
            chain.blast_radius = self._calc_blast_radius(principal, findings)
            chains.append(chain)
        
        return chains
    
    def _calc_blast_radius(self, principal: str, findings: List[Dict]) -> BlastRadius:
        """Calculate comprehensive blast radius - impact assessment."""
        services = set()
        data_stores = []
        secrets = []
        principals_reachable = []
        
        # Method-specific base scores for variety (78 patterns)
        method_base_scores = {
            # PassRole chains (high impact)
            'passrole_lambda': 45,
            'passrole_ec2': 55,
            'passrole_ecs': 50,
            'passrole_glue': 40,
            'passrole_codebuild': 48,
            'passrole_sagemaker': 52,
            'passrole_sagemaker_notebook': 52,
            'passrole_sagemaker_training': 50,
            'passrole_cloudformation': 60,
            'passrole_batch': 42,
            'passrole_emr': 55,
            'passrole_stepfunctions': 48,
            'passrole_datapipeline': 45,
            'passrole_iot': 43,
            'passrole_apprunner': 47,
            'passrole_mediaconvert': 40,
            'eks_passrole': 58,
            'eks_passrole_nodegroup': 56,
            'eks_passrole_fargate': 54,
            'eks_irsa_pod_exec': 60,
            'eks_node_role_abuse': 62,
            
            # Policy manipulation (very high impact)
            'create_policy_version': 65,
            'set_default_policy_version': 64,
            'put_user_policy': 60,
            'put_role_policy': 62,
            'put_group_policy': 58,
            'attach_user_policy': 58,
            'attach_role_policy': 60,
            'attach_group_policy': 55,
            'add_user_to_group': 57,
            'create_policy_attach_combo': 66,
            'permission_boundary_bypass': 68,
            'delete_account_password_policy': 50,
            'tag_based_access_bypass': 54,
            
            # Credential exposure (critical)
            'create_access_key': 70,
            'create_login_profile': 65,
            'update_login_profile': 62,
            'ssm_send_command': 68,
            'ssm_start_session': 65,
            'ssm_get_parameter': 55,
            'ec2_instance_connect': 58,
            'ec2_serial_console': 62,
            'ec2_user_data': 56,
            'codecommit_git_credentials': 52,
            'secretsmanager_get_value': 60,
            'sts_get_federation_token': 58,
            'sts_get_session_token': 54,
            'rds_iam_auth_token': 56,
            'saml_oidc_provider_manipulation': 66,
            
            # Resource hijacking
            'update_function_code': 55,
            'update_function_configuration': 53,
            'lambda_layer': 48,
            'modify_instance_attribute': 54,
            'apigateway_integration_abuse': 50,
            'cloudwatch_events_target': 48,
            'eventbridge_lambda_trigger': 50,
            'eks_update_cluster_config': 58,
            'eks_wildcard_permissions': 62,
            
            # Data exfiltration
            's3_bucket_notification': 42,
            'dynamodb_stream': 45,
            'dynamodb_stream_lambda': 47,
            'rds_snapshot': 58,
            'rds_snapshot_export': 60,
            'athena_query': 52,
            'redshift_snapshot': 58,
            'kinesis_stream': 48,
            'firehose_delivery': 46,
            'glue_catalog': 44,
            
            # Lateral movement (very high impact)
            'update_assume_role_policy': 72,
            'sts_assume': 50,
            'cross_account_role': 64,
            'organization_account_access': 68,
            
            # Persistence
            'backdoor_lambda': 58,
            'backdoor_user': 65,
            'backdoor_role': 63,
            'eventbridge_scheduled': 52,
            'cloudwatch_alarm_action': 48,
        }
        
        # Analyze findings for blast radius
        primary_method = ''
        for f in findings:
            method = f.get('privesc_method', '').lower()
            if not primary_method:
                primary_method = method
            service = self._extract_service(method)
            services.add(service)
            
            # Track target roles (principals reachable)
            target_role = f.get('target_role_name', '')
            if target_role and target_role not in principals_reachable:
                principals_reachable.append(target_role)
            
            # Identify data stores based on method
            if any(ds in method for ds in ['s3', 'rds', 'dynamo', 'redshift', 'athena']):
                data_stores.append(service)
            
            # Identify secrets access
            if any(sec in method for sec in ['secret', 'ssm', 'parameter', 'key']):
                secrets.append(service)
        
        # Calculate score with method-specific base
        base_score = 30  # Default base
        for key, score in method_base_scores.items():
            if key in primary_method:
                base_score = score
                break
        
        # Factor 1: Number of reachable principals (2 pts each, max 10)
        base_score += min(len(principals_reachable) * 2, 10)
        
        # Factor 2: Services affected (3 pts each, max 15)
        base_score += min(len(services) * 3, 15)
        
        # Factor 3: Admin path exists (15 pts)
        admin_path = any(
            'admin' in str(f).lower() or 
            'policy' in f.get('privesc_method', '').lower() or
            any(hv in f.get('target_role_name', '').lower() for hv in HIGH_VALUE_TARGETS)
            for f in findings
        )
        if admin_path:
            base_score += 15
        
        # Factor 4: Cross-account access (8 pts)
        cross_account = any('cross' in str(f).lower() or 'external' in str(f).lower() for f in findings)
        if cross_account:
            base_score += 8
        
        # Factor 5: Production impact (10 pts)
        production_impact = any(
            any(prod in str(f).lower() for prod in ['prod', 'production', 'live', 'main'])
            for f in findings
        )
        if production_impact:
            base_score += 10
        
        # Factor 6: Data stores exposed (bonus 5 pts)
        if data_stores:
            base_score += 5
        
        # Factor 7: Secrets accessible (bonus 5 pts)
        if secrets:
            base_score += 5
        
        # Build service impacts with detailed info
        service_impacts = []
        for svc in services:
            impact = ServiceImpact(
                service=svc,
                actions=self._get_service_actions(svc),
                resources=[f"arn:aws:{svc}:*:*:*"],
                data_access=svc in ['s3', 'rds', 'dynamodb', 'redshift', 'athena', 'glue'],
                write_access=True,
                delete_access=svc in ['s3', 'ec2', 'lambda', 'dynamodb'],
            )
            service_impacts.append(impact)
        
        return BlastRadius(
            principal_arn=principal,
            total_score=min(base_score, 100),
            services_affected=service_impacts,
            principals_reachable=principals_reachable,
            data_stores_exposed=data_stores,
            secrets_accessible=secrets,
            cross_account_access=cross_account,
            admin_path_exists=admin_path,
            production_impact=production_impact,
        )
    
    def _get_service_actions(self, service: str) -> List[str]:
        """Get typical dangerous actions for a service."""
        service_actions = {
            'iam': ['CreateUser', 'CreateRole', 'AttachPolicy', 'CreateAccessKey'],
            'lambda': ['CreateFunction', 'UpdateFunctionCode', 'InvokeFunction'],
            'ec2': ['RunInstances', 'ModifyInstanceAttribute', 'CreateKeyPair'],
            'ecs': ['RunTask', 'RegisterTaskDefinition', 'UpdateService'],
            's3': ['GetObject', 'PutObject', 'DeleteObject', 'ListBuckets'],
            'rds': ['CreateDBSnapshot', 'RestoreDBInstanceFromSnapshot'],
            'secretsmanager': ['GetSecretValue', 'CreateSecret'],
            'ssm': ['SendCommand', 'GetParameter'],
            'cloudformation': ['CreateStack', 'UpdateStack'],
            'glue': ['CreateJob', 'StartJobRun'],
            'sagemaker': ['CreateNotebookInstance'],
            'codebuild': ['CreateProject', 'StartBuild'],
        }
        return service_actions.get(service, ['*'])
    
    # Helper methods
    def _group_by_principal(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        grouped = defaultdict(list)
        for f in findings:
            grouped[f.get('principal_name', 'unknown')].append(f)
        return grouped
    
    def _group_by_method(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        grouped = defaultdict(list)
        for f in findings:
            grouped[f.get('privesc_method', 'unknown')].append(f)
        return grouped
    
    def _matches_principal(self, finding: Dict, name: str) -> bool:
        return name.lower() in finding.get('principal_name', '').lower() or \
               name.lower() in finding.get('principal_arn', '').lower()
    
    def _get_category(self, method: str) -> ChainCategory:
        for key, cat in PATTERN_CATEGORIES.items():
            if key in method.lower():
                return cat
        return ChainCategory.LATERAL_MOVEMENT
    
    def _get_severity(self, finding: Dict) -> Severity:
        sev = finding.get('severity', 'HIGH').upper()
        return Severity[sev] if sev in Severity.__members__ else Severity.HIGH
    
    def _get_title(self, method: str, finding: Dict) -> str:
        """Get human-readable title for attack chain."""
        titles = {
            # PassRole chains (20+)
            'passrole_lambda': '🚀 Lambda Execution via PassRole',
            'passrole_ec2': '💻 EC2 Instance Profile Abuse',
            'passrole_ecs': '🐳 ECS Task Role Hijack',
            'passrole_glue': '🔧 Glue ETL Job Execution',
            'passrole_codebuild': '🔨 CodeBuild CI/CD Abuse',
            'passrole_sagemaker': '🤖 SageMaker Notebook Execution',
            'passrole_sagemaker_notebook': '🤖 SageMaker Notebook Abuse',
            'passrole_sagemaker_training': '🤖 SageMaker Training Job Abuse',
            'passrole_cloudformation': '📦 CloudFormation Stack Deployment',
            'passrole_batch': '📊 AWS Batch Job Execution',
            'passrole_emr': '🔥 EMR Cluster Execution',
            'passrole_stepfunctions': '🔄 Step Functions Execution',
            'passrole_datapipeline': '🚰 Data Pipeline Execution',
            'passrole_iot': '📡 IoT Rule Action Abuse',
            'passrole_apprunner': '🏃 App Runner Service Abuse',
            'eks_passrole': '☸️ EKS Pod Execution',
            'eks_passrole_nodegroup': '☸️ EKS Node Group Abuse',
            'eks_passrole_fargate': '☸️ EKS Fargate Profile Abuse',
            'eks_irsa_pod_exec': '☸️ EKS IRSA Pod Execution',
            'eks_node_role_abuse': '☸️ EKS Node Role Abuse',
            
            # Policy manipulation (15+)
            'create_policy_version': '📝 Policy Version Escalation',
            'set_default_policy_version': '📝 Default Policy Version Switch',
            'put_user_policy': '📝 Inline User Policy Injection',
            'put_role_policy': '📝 Inline Role Policy Injection',
            'put_group_policy': '📝 Inline Group Policy Injection',
            'attach_user_policy': '⚡ Attach User Policy',
            'attach_role_policy': '⚡ Attach Role Policy',
            'attach_group_policy': '⚡ Attach Group Policy',
            'add_user_to_group': '👥 Add User to Admin Group',
            'create_policy_attach_combo': '📝 Create & Attach Admin Policy',
            'permission_boundary_bypass': '🚧 Permission Boundary Bypass',
            'delete_account_password_policy': '🔓 Delete Password Policy',
            'tag_based_access_bypass': '🏷️ Tag-Based Access Bypass',
            
            # Credential exposure (15+)
            'create_access_key': '🔑 Access Key Persistence',
            'create_login_profile': '🔑 Console Access Creation',
            'update_login_profile': '🔑 Password Reset Attack',
            'ssm_send_command': '🖥️ SSM Remote Execution',
            'ssm_start_session': '🖥️ SSM Session Hijack',
            'ssm_get_parameter': '🔐 Parameter Store Secrets',
            'ec2_instance_connect': '🔌 EC2 Instance Connect',
            'ec2_serial_console': '🖥️ EC2 Serial Console Access',
            'ec2_user_data': '📜 EC2 User Data Backdoor',
            'codecommit_git_credentials': '📂 CodeCommit Git Credentials',
            'secretsmanager_get_value': '🔐 Secrets Manager Access',
            'sts_get_federation_token': '🎫 STS Federation Token',
            'sts_get_session_token': '🎫 STS Session Token',
            'rds_iam_auth_token': '🔑 RDS IAM Auth Token',
            'saml_oidc_provider_manipulation': '🔐 SAML/OIDC Provider Abuse',
            
            # Resource hijack (10+)
            'update_function_code': '💉 Lambda Code Injection',
            'update_function_configuration': '⚙️ Lambda Config Modification',
            'lambda_layer': '📚 Lambda Layer Injection',
            'modify_instance_attribute': '🔧 EC2 Instance Modification',
            'apigateway_integration_abuse': '🌐 API Gateway Hijack',
            'cloudwatch_events_target': '⏰ CloudWatch Events Hijack',
            'eventbridge_lambda_trigger': '⚡ EventBridge Lambda Trigger',
            'eks_update_cluster_config': '☸️ EKS Cluster Config Modification',
            'eks_wildcard_permissions': '☸️ EKS Wildcard Permissions',
            
            # Data exfiltration (10+)
            's3_bucket_notification': '📤 S3 Event Hijacking',
            'dynamodb_stream': '📤 DynamoDB Stream Exfil',
            'dynamodb_stream_lambda': '📤 DynamoDB Stream to Lambda',
            'rds_snapshot': '💾 RDS Snapshot Theft',
            'rds_snapshot_export': '💾 RDS Snapshot Export',
            'athena_query': '🔍 Athena Data Lake Query',
            'redshift_snapshot': '💾 Redshift Snapshot Theft',
            'kinesis_stream': '📡 Kinesis Stream Intercept',
            'firehose_delivery': '🔥 Firehose Delivery Redirect',
            'glue_catalog': '📊 Glue Catalog Access',
            
            # Lateral movement (10+)
            'update_assume_role_policy': '🔄 Trust Policy Modification',
            'sts_assume_role': '🔄 Cross-Role Assumption',
            'sts_assume': '🔄 Role Assumption',
            'cross_account_role': '🌐 Cross-Account Role Assumption',
            'organization_account_access': '🏢 Organization Account Access',
            
            # Persistence (5+)
            'backdoor_lambda': '🚪 Lambda Backdoor',
            'backdoor_user': '🚪 IAM User Backdoor',
            'backdoor_role': '🚪 IAM Role Backdoor',
            'eventbridge_scheduled': '⏰ Scheduled EventBridge Persistence',
            'cloudwatch_alarm_action': '🔔 CloudWatch Alarm Persistence',
        }
        for key, title in titles.items():
            if key in method.lower():
                return title
        return f"⚡ {method.replace('_', ' ').title()}"
    
    def _get_objective(self, category: ChainCategory) -> str:
        """Get target objective based on attack category."""
        objectives = {
            ChainCategory.PASSROLE_EXECUTION: "code execution with elevated role",
            ChainCategory.POLICY_MANIPULATION: "administrator access",
            ChainCategory.CREDENTIAL_EXPOSURE: "persistent credentials",
            ChainCategory.RESOURCE_HIJACK: "resource takeover",
            ChainCategory.DATA_EXFILTRATION: "data exfiltration",
            ChainCategory.LATERAL_MOVEMENT: "lateral movement",
            ChainCategory.PERSISTENCE: "persistent access",
        }
        return objectives.get(category, "privilege escalation")
    
    def _extract_service(self, method: str) -> str:
        """Extract AWS service from method name."""
        method_lower = method.lower()
        
        # IAM-specific patterns first
        iam_patterns = ['put_user', 'put_role', 'put_group', 'attach_', 'create_access_key',
                        'create_login', 'update_login', 'add_user_to', 'create_policy', 
                        'set_default_policy', 'permission_boundary', 'delete_account_password',
                        'tag_based_access', 'update_assume_role']
        for pattern in iam_patterns:
            if pattern in method_lower:
                return 'iam'
        
        # Other AWS services
        services = [
            'lambda', 'ec2', 'ecs', 'eks', 'glue', 'codebuild', 'sagemaker',
            's3', 'ssm', 'rds', 'dynamodb', 'secretsmanager', 'cloudformation',
            'batch', 'emr', 'stepfunctions', 'datapipeline', 'athena', 'redshift',
            'sts', 'codecommit', 'kinesis', 'firehose', 'eventbridge', 'apigateway'
        ]
        for svc in services:
            if svc in method_lower:
                return svc
        
        # STS patterns
        if 'sts_' in method_lower or 'assume' in method_lower:
            return 'sts'
        
        return "iam"  # Default to IAM for policy-related operations
    
    def _method_to_action(self, method: str) -> str:
        """Convert method name to IAM action format with proper PascalCase."""
        if not method:
            return "iam:Unknown"
        
        # Common IAM action mappings
        action_map = {
            'put_user_policy': 'iam:PutUserPolicy',
            'put_role_policy': 'iam:PutRolePolicy', 
            'put_group_policy': 'iam:PutGroupPolicy',
            'attach_user_policy': 'iam:AttachUserPolicy',
            'attach_role_policy': 'iam:AttachRolePolicy',
            'attach_group_policy': 'iam:AttachGroupPolicy',
            'create_access_key': 'iam:CreateAccessKey',
            'create_login_profile': 'iam:CreateLoginProfile',
            'update_login_profile': 'iam:UpdateLoginProfile',
            'add_user_to_group': 'iam:AddUserToGroup',
            'create_policy_version': 'iam:CreatePolicyVersion',
            'set_default_policy_version': 'iam:SetDefaultPolicyVersion',
            'update_assume_role_policy': 'iam:UpdateAssumeRolePolicy',
            'passrole': 'iam:PassRole',
        }
        
        method_lower = method.lower()
        for key, action in action_map.items():
            if key in method_lower:
                return action
        
        # Fallback: convert snake_case to PascalCase
        parts = method.split('_')
        pascal = ''.join(word.capitalize() for word in parts)
        return f"iam:{pascal}"
    
    def _get_mitre_techniques(self, method: str) -> List[str]:
        """Get MITRE ATT&CK techniques for a method.
        
        Tries full method name first, then falls back to prefix matching.
        """
        method_lower = method.lower()
        
        # Try exact match first
        if method_lower in MITRE_TECHNIQUE_MAP:
            return MITRE_TECHNIQUE_MAP[method_lower]
        
        # Try prefix matching (e.g., "passrole_lambda" matches "passrole_lambda")
        for key, techniques in MITRE_TECHNIQUE_MAP.items():
            if key in method_lower or method_lower.startswith(key):
                return techniques
        
        # Fallback to old MITRE_MAPPINGS for backward compatibility
        for key, techniques in MITRE_MAPPINGS.items():
            if key in method_lower:
                return techniques
        
        return []
