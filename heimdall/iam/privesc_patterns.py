"""
IAM Privilege Escalation Pattern Library

Based on:
- Rhino Security Labs research: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- Bishop Fox IAM Vulnerable test cases
- Real-world pentesting experience
"""

from dataclasses import dataclass
from typing import List, Optional, Set
from enum import Enum


class PrivescMethod(Enum):
    """Privilege escalation method categories"""
    POLICY_MANIPULATION = "policy_manipulation"
    ROLE_MANIPULATION = "role_manipulation"
    PASSROLE_ABUSE = "passrole_abuse"
    CREDENTIAL_ACCESS = "credential_access"
    LAMBDA_ABUSE = "lambda_abuse"
    REMOTE_EXECUTION = "remote_execution"  # v0.9.0
    SECRET_EXFILTRATION = "secret_exfiltration"  # v0.9.0
    DIRECT_ROLE_ASSUMPTION = "direct_role_assumption"  # v0.9.0
    COMPUTE_MANIPULATION = "compute_manipulation"  # v0.9.0
    EKS_ABUSE = "eks_abuse"  # v1.1.0


@dataclass
class PrivescPattern:
    """Single privilege escalation pattern"""
    id: str
    name: str
    description: str
    required_actions: List[str]
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    method: PrivescMethod
    service: Optional[str] = None
    requires_target_role: bool = False
    explanation: Optional[str] = None
    remediation: Optional[str] = None
    conditional_requirements: Optional[List[str]] = None  # Non-IAM prerequisites (e.g., "kubectl access", "console access")


# Phase 2A-1: First 5 Critical Patterns
PRIVESC_PATTERNS = {
    
    # Pattern 1: PassRole + Lambda
    'passrole_lambda': PrivescPattern(
        id='passrole_lambda',
        name='iam:PassRole + lambda:CreateFunction',
        description='Create Lambda function with privileged role, execute code with elevated permissions',
        required_actions=['iam:PassRole', 'lambda:CreateFunction'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='lambda',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and lambda:CreateFunction can create a new Lambda function "
            "and attach a privileged role to it. When the Lambda executes, it runs with the permissions "
            "of the attached role. If that role has admin access, the attacker can execute arbitrary "
            "code with admin privileges."
        ),
        remediation=(
            "1. Remove lambda:CreateFunction permission\n"
            "2. Restrict iam:PassRole to specific roles:\n"
            "   Resource: arn:aws:iam::*:role/SafeRoleName\n"
            "3. Add MFA condition to sensitive permissions\n"
            "4. Use Lambda execution roles with minimal required permissions"
        )
    ),
    
    # Pattern 2: PassRole + EC2
    'passrole_ec2': PrivescPattern(
        id='passrole_ec2',
        name='iam:PassRole + ec2:RunInstances',
        description='Launch EC2 instance with privileged role, SSH and execute commands with elevated permissions',
        required_actions=['iam:PassRole', 'ec2:RunInstances'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='ec2',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and ec2:RunInstances can launch an EC2 instance "
            "with a privileged IAM role attached. Once the instance is running, they can SSH "
            "into it and use the instance metadata service (IMDS) to retrieve temporary credentials "
            "for the attached role. If that role has admin access, the attacker gains full AWS access."
        ),
        remediation=(
            "1. Remove ec2:RunInstances permission if not needed\n"
            "2. Restrict iam:PassRole to specific roles:\n"
            "   Resource: arn:aws:iam::*:role/SafeEC2Role\n"
            "3. Add condition to iam:PassRole:\n"
            "   Condition: StringEquals: iam:PassedToService: ec2.amazonaws.com\n"
            "4. Use VPC endpoints and disable IMDS v1\n"
            "5. Monitor EC2 instance launches with high-privilege roles"
        )
    ),
    
    # Pattern 3: AttachUserPolicy
    'attach_user_policy': PrivescPattern(
        id='attach_user_policy',
        name='iam:AttachUserPolicy',
        description='Attach AdministratorAccess policy to self or other user',
        required_actions=['iam:AttachUserPolicy'],
        severity='CRITICAL',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "With iam:AttachUserPolicy, an attacker can attach any managed policy (including "
            "AdministratorAccess) to themselves or another user they control. This immediately "
            "grants full AWS account access."
        ),
        remediation=(
            "1. Remove iam:AttachUserPolicy permission\n"
            "2. Use iam:AttachUserPolicy with resource constraints:\n"
            "   Resource: arn:aws:iam::*:user/SpecificUser\n"
            "3. Add condition to prevent attaching admin policies:\n"
            "   Condition: StringNotEquals: iam:PolicyARN: arn:aws:iam::aws:policy/AdministratorAccess"
        )
    ),
    
    # Pattern 3: PutUserPolicy
    'put_user_policy': PrivescPattern(
        id='put_user_policy',
        name='iam:PutUserPolicy',
        description='Create/update inline policy with admin permissions on self or other user',
        required_actions=['iam:PutUserPolicy'],
        severity='CRITICAL',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "iam:PutUserPolicy allows creating or updating inline policies. An attacker can create "
            "a new inline policy granting themselves full permissions (Effect: Allow, Action: *, Resource: *)."
        ),
        remediation=(
            "1. Remove iam:PutUserPolicy permission\n"
            "2. Use resource constraints to limit which users can be modified\n"
            "3. Monitor CloudTrail for PutUserPolicy API calls\n"
            "4. Prefer managed policies over inline policies for better auditability"
        )
    ),
    
    # Pattern 4: CreatePolicyVersion
    'create_policy_version': PrivescPattern(
        id='create_policy_version',
        name='iam:CreatePolicyVersion',
        description='Modify existing policy to grant admin access',
        required_actions=['iam:CreatePolicyVersion'],
        severity='HIGH',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "If a principal has iam:CreatePolicyVersion on a policy that is attached to them "
            "(or a role they can assume), they can create a new version of that policy with "
            "admin permissions. The new version becomes active immediately."
        ),
        remediation=(
            "1. Remove iam:CreatePolicyVersion permission\n"
            "2. Use resource constraints to limit which policies can be modified\n"
            "3. Set up alerts for policy version changes\n"
            "4. Use policy versioning limits (max 5 versions) as a partial mitigation"
        )
    ),
    
    # Pattern 5: UpdateAssumeRolePolicy
    'update_assume_role_policy': PrivescPattern(
        id='update_assume_role_policy',
        name='iam:UpdateAssumeRolePolicy',
        description='Modify role trust policy to assume privileged role',
        required_actions=['iam:UpdateAssumeRolePolicy'],
        severity='HIGH',
        method=PrivescMethod.ROLE_MANIPULATION,
        requires_target_role=True,
        explanation=(
            "With iam:UpdateAssumeRolePolicy, an attacker can modify the trust policy of a role "
            "to allow themselves (or a principal they control) to assume it. If the role has "
            "elevated permissions, this grants privilege escalation."
        ),
        remediation=(
            "1. Remove iam:UpdateAssumeRolePolicy permission\n"
            "2. Use resource constraints to protect critical roles\n"
            "3. Add MFA requirement in trust policies for sensitive roles\n"
            "4. Monitor AssumeRole API calls with CloudTrail"
        )
    ),
    
    # Pattern 6: PassRole + CloudFormation
    'passrole_cloudformation': PrivescPattern(
        id='passrole_cloudformation',
        name='iam:PassRole + cloudformation:CreateStack',
        description='Launch CloudFormation stack with privileged role, execute resources with elevated permissions',
        required_actions=['iam:PassRole', 'cloudformation:CreateStack'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='cloudformation',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and cloudformation:CreateStack can create a CloudFormation "
            "stack with a privileged IAM role. The stack's resources (Lambda functions, EC2 instances, "
            "etc.) execute with the passed role's permissions. If that role has admin access, the attacker "
            "can deploy malicious resources with full AWS privileges."
        ),
        remediation=(
            "1. Remove cloudformation:CreateStack permission if not needed\n"
            "2. Restrict iam:PassRole to specific roles:\n"
            "   Resource: arn:aws:iam::*:role/SafeCloudFormationRole\n"
            "3. Add condition to iam:PassRole:\n"
            "   Condition: StringEquals: iam:PassedToService: cloudformation.amazonaws.com\n"
            "4. Use CloudFormation StackSets with service-managed permissions\n"
            "5. Monitor CloudFormation stack creation with CloudTrail"
        )
    ),
    
    # Pattern 7: CreateAccessKey
    'create_access_key': PrivescPattern(
        id='create_access_key',
        name='iam:CreateAccessKey',
        description='Create programmatic access keys for other users, steal credentials',
        required_actions=['iam:CreateAccessKey'],
        severity='CRITICAL',
        method=PrivescMethod.CREDENTIAL_ACCESS,
        explanation=(
            "With iam:CreateAccessKey, an attacker can generate new programmatic access keys "
            "(AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY) for other IAM users. If the target user "
            "has elevated permissions, the attacker can use these keys to authenticate as that user "
            "and inherit their privileges. This is especially dangerous if the permission applies to "
            "admin users or is not resource-constrained."
        ),
        remediation=(
            "1. Remove iam:CreateAccessKey permission if not needed\n"
            "2. Use resource constraints to limit key creation:\n"
            "   Resource: arn:aws:iam::*:user/${aws:username}\n"
            "   (Only allow users to create keys for themselves)\n"
            "3. Monitor CreateAccessKey API calls with CloudTrail\n"
            "4. Implement key rotation policies\n"
            "5. Use AWS IAM Access Analyzer to detect unused keys\n"
            "6. Require MFA for sensitive API operations"
        )
    ),
    
    # Pattern 8: UpdateLoginProfile
    'update_login_profile': PrivescPattern(
        id='update_login_profile',
        name='iam:UpdateLoginProfile',
        description='Reset console password for other users, gain console access',
        required_actions=['iam:UpdateLoginProfile'],
        severity='HIGH',
        method=PrivescMethod.CREDENTIAL_ACCESS,
        explanation=(
            "iam:UpdateLoginProfile allows resetting the console password for IAM users. An attacker "
            "with this permission can change the password of another user (including admin users) and "
            "log into the AWS Console as that user. Unlike CreateAccessKey, this provides console access "
            "which may bypass some programmatic security controls."
        ),
        remediation=(
            "1. Remove iam:UpdateLoginProfile permission if not needed\n"
            "2. Use resource constraints:\n"
            "   Resource: arn:aws:iam::*:user/${aws:username}\n"
            "   (Only allow password changes for self)\n"
            "3. Enable MFA requirement for console access\n"
            "4. Monitor UpdateLoginProfile API calls with CloudTrail\n"
            "5. Use AWS SSO instead of IAM users for console access\n"
            "6. Implement password policies with complexity requirements"
        )
    ),
    
    # Pattern 11: CreateLoginProfile
    'create_login_profile': PrivescPattern(
        id='create_login_profile',
        name='iam:CreateLoginProfile',
        description='Create console password for users without one, gain console access',
        required_actions=['iam:CreateLoginProfile'],
        severity='CRITICAL',
        method=PrivescMethod.CREDENTIAL_ACCESS,
        explanation=(
            "iam:CreateLoginProfile allows creating a console password for IAM users who don't have one. "
            "Many IAM users in AWS accounts are created for programmatic access only (no console password). "
            "An attacker with this permission can enable console access for these users, set a password they "
            "control, and log into the AWS Console as that user. This is especially dangerous for users with "
            "elevated permissions who were intentionally restricted to programmatic-only access."
        ),
        remediation=(
            "1. Remove iam:CreateLoginProfile permission if not needed\n"
            "2. Use resource constraints:\n"
            "   Resource: arn:aws:iam::*:user/${aws:username}\n"
            "   (Only allow users to create console access for themselves)\n"
            "3. Monitor CreateLoginProfile API calls with CloudTrail\n"
            "4. Require MFA for console access\n"
            "5. Use AWS SSO instead of IAM users for console access\n"
            "6. Regularly audit users with console access\n"
            "7. Add Condition to require password reset on first login"
        )
    ),
    
    # Pattern 9: PassRole + ECS
    'passrole_ecs': PrivescPattern(
        id='passrole_ecs',
        name='iam:PassRole + ecs:RunTask',
        description='Run ECS task with privileged role, execute containerized code with elevated permissions',
        required_actions=['iam:PassRole', 'ecs:RunTask', 'ecs:RegisterTaskDefinition'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='ecs',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and ecs:RunTask + ecs:RegisterTaskDefinition can create a "
            "malicious ECS task definition and run it with a privileged role. The containerized workload "
            "executes with the permissions of the attached task role. This is similar to Lambda/EC2 "
            "PassRole attacks but leverages ECS container infrastructure."
        ),
        remediation=(
            "1. Remove ecs:RunTask and ecs:RegisterTaskDefinition permissions\n"
            "2. Restrict iam:PassRole to specific roles:\n"
            "   Condition: StringEquals: iam:PassedToService: ecs-tasks.amazonaws.com\n"
            "3. Use ECS task role trust policies with specific task definition ARNs\n"
            "4. Monitor ecs:RunTask and ecs:RegisterTaskDefinition API calls\n"
            "5. Implement ECS task execution logging with CloudWatch\n"
            "6. Use AWS IAM Access Analyzer to detect risky PassRole permissions"
        )
    ),
    
    # Pattern 10: AttachGroupPolicy
    'attach_group_policy': PrivescPattern(
        id='attach_group_policy',
        name='iam:AttachGroupPolicy',
        description='Attach admin policy to a group the user belongs to',
        required_actions=['iam:AttachGroupPolicy'],
        severity='CRITICAL',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "iam:AttachGroupPolicy allows attaching managed policies to IAM groups. If the attacker is a "
            "member of any group, they can attach AdministratorAccess or another privileged policy to that "
            "group, instantly gaining admin privileges. This is often overlooked compared to AttachUserPolicy "
            "because group membership is indirect."
        ),
        remediation=(
            "1. Remove iam:AttachGroupPolicy permission if not needed\n"
            "2. Use resource constraints to limit affected groups:\n"
            "   Resource: arn:aws:iam::*:group/DevTeam\n"
            "3. Use Condition to restrict attachable policies:\n"
            "   Condition: ArnNotEquals: iam:PolicyArn: arn:aws:iam::aws:policy/AdministratorAccess\n"
            "4. Monitor AttachGroupPolicy API calls with CloudTrail\n"
            "5. Implement SCPs to deny attachment of privileged policies\n"
            "6. Regularly audit group memberships and attached policies"
        )
    ),
    
    # Pattern 12: AttachRolePolicy
    'attach_role_policy': PrivescPattern(
        id='attach_role_policy',
        name='iam:AttachRolePolicy',
        description='Attach admin policy to assumable role, escalate via AssumeRole',
        required_actions=['iam:AttachRolePolicy'],
        severity='CRITICAL',
        method=PrivescMethod.POLICY_MANIPULATION,
        requires_target_role=True,
        explanation=(
            "iam:AttachRolePolicy allows attaching managed policies to IAM roles. An attacker can attach "
            "AdministratorAccess or another privileged policy to a role they can assume (or modify the trust "
            "policy of), then assume that role to gain elevated privileges. This is powerful because roles "
            "are commonly used for cross-account access and service permissions."
        ),
        remediation=(
            "1. Remove iam:AttachRolePolicy permission if not needed\n"
            "2. Use resource constraints to protect critical roles:\n"
            "   Resource: arn:aws:iam::*:role/SafeRole\n"
            "3. Add Condition to restrict attachable policies:\n"
            "   Condition: ArnNotEquals: iam:PolicyArn: arn:aws:iam::aws:policy/AdministratorAccess\n"
            "4. Monitor AttachRolePolicy API calls with CloudTrail\n"
            "5. Use SCPs to deny attachment of admin policies\n"
            "6. Require MFA for role assumption"
        )
    ),
    
    # Pattern 13: PutRolePolicy
    'put_role_policy': PrivescPattern(
        id='put_role_policy',
        name='iam:PutRolePolicy',
        description='Create/update inline policy on assumable role with admin permissions',
        required_actions=['iam:PutRolePolicy'],
        severity='CRITICAL',
        method=PrivescMethod.POLICY_MANIPULATION,
        requires_target_role=True,
        explanation=(
            "iam:PutRolePolicy allows creating or updating inline policies on IAM roles. An attacker can add "
            "a new inline policy granting full permissions (Effect: Allow, Action: *, Resource: *) to a role "
            "they can assume. This is similar to AttachRolePolicy but uses inline policies instead of managed "
            "policies, which can be harder to detect and audit."
        ),
        remediation=(
            "1. Remove iam:PutRolePolicy permission if not needed\n"
            "2. Use resource constraints to protect critical roles\n"
            "3. Monitor PutRolePolicy API calls with CloudTrail\n"
            "4. Prefer managed policies over inline policies for better visibility\n"
            "5. Use IAM Access Analyzer to detect overly permissive policies\n"
            "6. Implement SCPs to prevent inline policy creation on sensitive roles"
        )
    ),
    
    # Pattern 14: PutGroupPolicy
    'put_group_policy': PrivescPattern(
        id='put_group_policy',
        name='iam:PutGroupPolicy',
        description='Create/update inline policy on own group with admin permissions',
        required_actions=['iam:PutGroupPolicy'],
        severity='CRITICAL',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "iam:PutGroupPolicy allows creating or updating inline policies on IAM groups. If the attacker "
            "is a member of any group (even a low-privilege one), they can add an inline policy to that group "
            "granting full permissions. This immediately escalates their own privileges. Like AttachGroupPolicy, "
            "this is often overlooked because the privilege escalation happens through group membership."
        ),
        remediation=(
            "1. Remove iam:PutGroupPolicy permission if not needed\n"
            "2. Use resource constraints to limit affected groups:\n"
            "   Resource: arn:aws:iam::*:group/SpecificGroup\n"
            "3. Monitor PutGroupPolicy API calls with CloudTrail\n"
            "4. Prefer managed policies over inline policies\n"
            "5. Regularly audit group memberships and inline policies\n"
            "6. Use SCPs to prevent inline policy creation on sensitive groups"
        )
    ),
    
    # Pattern 15: PassRole + CodeBuild
    'passrole_codebuild': PrivescPattern(
        id='passrole_codebuild',
        name='iam:PassRole + codebuild:CreateProject',
        description='Create CodeBuild project with privileged role, execute arbitrary build commands',
        required_actions=['iam:PassRole', 'codebuild:CreateProject', 'codebuild:StartBuild'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='codebuild',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and codebuild:CreateProject + codebuild:StartBuild can create a "
            "malicious CodeBuild project that uses a privileged IAM role. The buildspec.yml can contain arbitrary "
            "commands that execute with the passed role's permissions. This is particularly dangerous because "
            "CodeBuild runs in an isolated environment with full shell access, making it easy to exfiltrate "
            "credentials or perform AWS API calls."
        ),
        remediation=(
            "1. Remove codebuild:CreateProject and codebuild:StartBuild permissions\n"
            "2. Restrict iam:PassRole to specific roles:\n"
            "   Condition: StringEquals: iam:PassedToService: codebuild.amazonaws.com\n"
            "3. Use VPC endpoints for CodeBuild to restrict network access\n"
            "4. Monitor CodeBuild project creation and build starts with CloudTrail\n"
            "5. Implement approval workflows for CodeBuild projects\n"
            "6. Use SCPs to deny PassRole to overly privileged roles"
        )
    ),
    
    # Pattern 16: PassRole + Glue
    'passrole_glue': PrivescPattern(
        id='passrole_glue',
        name='iam:PassRole + glue:CreateJob',
        description='Create Glue ETL job with privileged role, execute arbitrary Python/Scala code',
        required_actions=['iam:PassRole', 'glue:CreateJob', 'glue:StartJobRun'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='glue',
        requires_target_role=True,
        explanation=(
            "AWS Glue jobs execute custom Python or Scala code for ETL (Extract, Transform, Load) operations. "
            "An attacker with iam:PassRole and glue:CreateJob can create a Glue job that uses a privileged role, "
            "then inject malicious code into the job script. When the job runs (via glue:StartJobRun), the code "
            "executes with the passed role's permissions. This can be used to access databases, S3 buckets, or "
            "make AWS API calls."
        ),
        remediation=(
            "1. Remove glue:CreateJob and glue:StartJobRun permissions\n"
            "2. Restrict iam:PassRole to specific Glue service roles:\n"
            "   Condition: StringEquals: iam:PassedToService: glue.amazonaws.com\n"
            "3. Monitor Glue job creation and execution with CloudTrail\n"
            "4. Use Glue job bookmarks to track legitimate jobs\n"
            "5. Implement approval workflows for new Glue jobs\n"
            "6. Review Glue job scripts for suspicious code"
        )
    ),
    
    # Pattern 17: PassRole + DataPipeline
    'passrole_datapipeline': PrivescPattern(
        id='passrole_datapipeline',
        name='iam:PassRole + datapipeline:CreatePipeline',
        description='Create DataPipeline with privileged role, execute shell commands via pipeline activities',
        required_actions=['iam:PassRole', 'datapipeline:CreatePipeline', 'datapipeline:PutPipelineDefinition'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='datapipeline',
        requires_target_role=True,
        explanation=(
            "AWS Data Pipeline allows defining workflows that can include ShellCommandActivity, which executes "
            "arbitrary shell commands on EC2 instances or EMR clusters. An attacker with iam:PassRole and "
            "datapipeline:CreatePipeline + datapipeline:PutPipelineDefinition can create a pipeline that uses "
            "a privileged role and includes malicious shell commands. When the pipeline activates, these commands "
            "run with the passed role's permissions."
        ),
        remediation=(
            "1. Remove datapipeline:CreatePipeline and datapipeline:PutPipelineDefinition permissions\n"
            "2. Restrict iam:PassRole to specific Data Pipeline service roles:\n"
            "   Condition: StringEquals: iam:PassedToService: datapipeline.amazonaws.com\n"
            "3. Monitor Data Pipeline creation with CloudTrail\n"
            "4. Review pipeline definitions for ShellCommandActivity\n"
            "5. Use AWS Organizations SCPs to restrict Data Pipeline usage\n"
            "6. Consider migrating to AWS Step Functions for better security controls"
        )
    ),
    
    # Pattern 18: UpdateFunctionCode
    'update_function_code': PrivescPattern(
        id='update_function_code',
        name='lambda:UpdateFunctionCode',
        description='Inject malicious code into existing Lambda functions, execute with their privileges',
        required_actions=['lambda:UpdateFunctionCode'],
        severity='HIGH',
        method=PrivescMethod.LAMBDA_ABUSE,
        service='lambda',
        explanation=(
            "lambda:UpdateFunctionCode allows replacing the code of existing Lambda functions. An attacker can "
            "inject malicious code into functions that have privileged execution roles. While the attacker doesn't "
            "choose the role (unlike PassRole attacks), they can abuse whatever permissions the existing functions "
            "already have. This is particularly dangerous for Lambda functions with admin roles or access to "
            "sensitive resources. The malicious code executes when the function is next invoked."
        ),
        remediation=(
            "1. Remove lambda:UpdateFunctionCode permission if not needed\n"
            "2. Use resource constraints to limit which functions can be modified:\n"
            "   Resource: arn:aws:lambda:*:*:function/safe-function-*\n"
            "3. Monitor UpdateFunctionCode API calls with CloudTrail\n"
            "4. Implement code signing for Lambda functions\n"
            "5. Use Lambda function versions and aliases for immutable deployments\n"
            "6. Require approval workflows for function code updates\n"
            "7. Enable Lambda function monitoring with CloudWatch Logs"
        )
    ),
    
    # Pattern 19: UpdateFunctionConfiguration + PassRole
    'update_function_configuration': PrivescPattern(
        id='update_function_configuration',
        name='lambda:UpdateFunctionConfiguration + iam:PassRole',
        description='Modify Lambda function to use a privileged execution role',
        required_actions=['lambda:UpdateFunctionConfiguration', 'iam:PassRole'],
        severity='CRITICAL',
        method=PrivescMethod.LAMBDA_ABUSE,
        service='lambda',
        requires_target_role=True,
        explanation=(
            "lambda:UpdateFunctionConfiguration allows modifying Lambda function settings, including the execution "
            "role. Combined with iam:PassRole, an attacker can change an existing Lambda function to use a privileged "
            "role, then invoke it (or wait for it to be triggered) to execute code with elevated permissions. This "
            "is similar to creating a new Lambda with PassRole, but targets existing functions that may already be "
            "integrated into applications and regularly invoked."
        ),
        remediation=(
            "1. Remove lambda:UpdateFunctionConfiguration permission if not needed\n"
            "2. Restrict iam:PassRole to specific Lambda execution roles:\n"
            "   Condition: StringEquals: iam:PassedToService: lambda.amazonaws.com\n"
            "3. Use resource constraints on UpdateFunctionConfiguration\n"
            "4. Monitor function configuration changes with CloudTrail\n"
            "5. Use Lambda function locking/immutability features\n"
            "6. Implement approval workflows for configuration changes\n"
            "7. Regularly audit Lambda function execution roles"
        )
    ),
    
    # Batch 5 (v0.9.0): SSM and Advanced Patterns
    
    # Pattern 21: SSM SendCommand
    'ssm_send_command': PrivescPattern(
        id='ssm_send_command',
        name='ssm:SendCommand',
        description='Execute arbitrary commands on EC2 instances via Systems Manager',
        required_actions=['ssm:SendCommand'],
        severity='HIGH',
        method=PrivescMethod.REMOTE_EXECUTION,
        service='ssm',
        requires_target_role=False,
        explanation=(
            "An attacker with ssm:SendCommand can remotely execute arbitrary commands on any EC2 instance "
            "that has the SSM agent installed and is associated with an IAM role. The commands execute with "
            "the permissions of the instance's IAM role. If the instance role has admin access or can access "
            "sensitive resources, the attacker gains those privileges. Common targets include production "
            "instances with database access, API credentials, or privileged roles."
        ),
        remediation=(
            "1. Remove ssm:SendCommand permission\n"
            "2. Restrict SendCommand to specific instances:\n"
            "   Resource: arn:aws:ec2:*:*:instance/i-specific123\n"
            "3. Use SSM Session Manager with restricted commands\n"
            "4. Implement least-privilege IAM roles on EC2 instances\n"
            "5. Enable CloudTrail logging for SSM commands\n"
            "6. Require MFA for SendCommand operations"
        )
    ),
    
    # Pattern 22: SSM StartSession
    'ssm_start_session': PrivescPattern(
        id='ssm_start_session',
        name='ssm:StartSession',
        description='Start interactive shell session on EC2 instances via Session Manager',
        required_actions=['ssm:StartSession'],
        severity='HIGH',
        method=PrivescMethod.REMOTE_EXECUTION,
        service='ssm',
        requires_target_role=False,
        explanation=(
            "An attacker with ssm:StartSession can start an interactive shell session on EC2 instances "
            "through AWS Systems Manager Session Manager. This provides full shell access to the instance "
            "with the permissions of the instance's IAM role. Unlike SSH, Session Manager doesn't require "
            "public IPs, security group rules, or SSH keys, making it stealthier. The attacker can access "
            "environment variables, credentials, application code, and any resources accessible to the instance role."
        ),
        remediation=(
            "1. Remove ssm:StartSession permission\n"
            "2. Restrict to specific instances:\n"
            "   Resource: arn:aws:ec2:*:*:instance/i-specific123\n"
            "3. Use Session Manager document restrictions\n"
            "4. Enable session logging to S3 or CloudWatch\n"
            "5. Implement least-privilege instance roles\n"
            "6. Require MFA for session starts"
        )
    ),
    
    # Pattern 23: Secrets Manager GetSecretValue
    'secretsmanager_get_value': PrivescPattern(
        id='secretsmanager_get_value',
        name='secretsmanager:GetSecretValue',
        description='Access sensitive secrets including database passwords, API keys, and tokens',
        required_actions=['secretsmanager:GetSecretValue'],
        severity='MEDIUM',
        method=PrivescMethod.SECRET_EXFILTRATION,
        service='secretsmanager',
        requires_target_role=False,
        explanation=(
            "An attacker with secretsmanager:GetSecretValue can retrieve plaintext values of secrets stored "
            "in AWS Secrets Manager. These often include database credentials, API keys, OAuth tokens, and "
            "other highly sensitive credentials. With these credentials, an attacker can access databases, "
            "third-party services, or pivot to other AWS resources. Common targets include production database "
            "passwords, payment gateway API keys, and service account tokens."
        ),
        remediation=(
            "1. Restrict GetSecretValue to specific secrets:\n"
            "   Resource: arn:aws:secretsmanager:*:*:secret:app-specific-*\n"
            "2. Use resource tags for fine-grained access control\n"
            "3. Enable CloudTrail logging for secret access\n"
            "4. Implement secret rotation policies\n"
            "5. Use VPC endpoints to restrict network access\n"
            "6. Require MFA for production secret access"
        )
    ),
    
    # Pattern 24: SSM GetParameter
    'ssm_get_parameter': PrivescPattern(
        id='ssm_get_parameter',
        name='ssm:GetParameter',
        description='Access SecureString parameters containing sensitive configuration and credentials',
        required_actions=['ssm:GetParameter'],
        severity='MEDIUM',
        method=PrivescMethod.SECRET_EXFILTRATION,
        service='ssm',
        requires_target_role=False,
        explanation=(
            "An attacker with ssm:GetParameter can retrieve SSM Parameter Store values, including SecureString "
            "parameters that contain encrypted credentials. Common sensitive parameters include database passwords, "
            "API keys, license keys, and application secrets. While SecureStrings are encrypted at rest, the "
            "GetParameter API returns decrypted values to authorized principals. Attackers can exfiltrate these "
            "credentials and use them to access databases, APIs, or escalate privileges."
        ),
        remediation=(
            "1. Restrict GetParameter to specific parameter paths:\n"
            "   Resource: arn:aws:ssm:*:*:parameter/app/dev/*\n"
            "2. Separate parameters by environment (dev/staging/prod)\n"
            "3. Use IAM condition keys for parameter access\n"
            "4. Enable CloudTrail logging for parameter access\n"
            "5. Implement parameter versioning and rotation\n"
            "6. Require MFA for production parameters"
        )
    ),
    
    # Pattern 25: STS AssumeRole
    'sts_assume_role': PrivescPattern(
        id='sts_assume_role',
        name='sts:AssumeRole',
        description='Directly assume high-privilege roles without PassRole restrictions',
        required_actions=['sts:AssumeRole'],
        severity='CRITICAL',
        method=PrivescMethod.DIRECT_ROLE_ASSUMPTION,
        service='sts',
        requires_target_role=True,
        explanation=(
            "An attacker with unrestricted sts:AssumeRole permission can directly assume any IAM role that "
            "trusts their principal, bypassing PassRole restrictions. This is more direct than PassRole-based "
            "privesc because it doesn't require creating resources. If the trust policy allows the attacker's "
            "principal and they have AssumeRole permission, they immediately gain the role's permissions. Common "
            "targets include admin roles, cross-account roles, and service roles with elevated privileges."
        ),
        remediation=(
            "1. Restrict AssumeRole to specific roles:\n"
            "   Resource: arn:aws:iam::*:role/AllowedRoleName\n"
            "2. Implement strict role trust policies\n"
            "3. Use ExternalId for cross-account access\n"
            "4. Require MFA for sensitive role assumption\n"
            "5. Add session tag conditions\n"
            "6. Enable CloudTrail for AssumeRole operations"
        )
    ),
    
    # Pattern 26: EC2 ModifyInstanceAttribute (User Data)
    'ec2_user_data': PrivescPattern(
        id='ec2_user_data',
        name='ec2:ModifyInstanceAttribute',
        description='Inject malicious code via EC2 instance user data modification',
        required_actions=['ec2:ModifyInstanceAttribute', 'ec2:StopInstances', 'ec2:StartInstances'],
        severity='HIGH',
        method=PrivescMethod.COMPUTE_MANIPULATION,
        service='ec2',
        requires_target_role=False,
        explanation=(
            "An attacker with ec2:ModifyInstanceAttribute can modify an EC2 instance's user data script. "
            "User data executes automatically when an instance starts, running with root privileges. By stopping "
            "an instance, modifying its user data to include malicious code, and restarting it, an attacker can "
            "execute arbitrary commands with root access. The code runs in the context of the instance's IAM role, "
            "allowing privilege escalation if the role has elevated permissions."
        ),
        remediation=(
            "1. Remove ec2:ModifyInstanceAttribute permission\n"
            "2. Restrict modification to specific instances\n"
            "3. Use immutable infrastructure (terminate and rebuild)\n"
            "4. Implement EC2 instance metadata protection (IMDSv2)\n"
            "5. Enable CloudTrail for instance modifications\n"
            "6. Use Systems Manager for configuration management"
        )
    ),
    
    # Batch 6 (v1.1.0): PassRole Service Variants
    
    # Pattern 27: PassRole + AWS Batch
    'passrole_batch': PrivescPattern(
        id='passrole_batch',
        name='iam:PassRole + batch:SubmitJob',
        description='Submit AWS Batch job with privileged role, execute containerized code with elevated permissions',
        required_actions=['iam:PassRole', 'batch:SubmitJob', 'batch:RegisterJobDefinition'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='batch',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and batch:SubmitJob + batch:RegisterJobDefinition can create a "
            "malicious Batch job definition and submit jobs with a privileged IAM role. AWS Batch executes "
            "containerized workloads, and the attacker can inject arbitrary code into the container that runs "
            "with the permissions of the passed role. This is similar to ECS but specifically targets batch "
            "processing workloads which may have access to sensitive data pipelines or compute resources."
        ),
        remediation=(
            "1. Remove batch:SubmitJob and batch:RegisterJobDefinition permissions\n"
            "2. Restrict iam:PassRole to specific Batch service roles:\n"
            "   Condition: StringEquals: iam:PassedToService: batch.amazonaws.com\n"
            "3. Use Batch job definition version control\n"
            "4. Monitor batch:SubmitJob and batch:RegisterJobDefinition API calls\n"
            "5. Implement approval workflows for new job definitions\n"
            "6. Use VPC endpoints for Batch to restrict network access"
        )
    ),
    
    # Pattern 28: PassRole + EMR
    'passrole_emr': PrivescPattern(
        id='passrole_emr',
        name='iam:PassRole + emr:RunJobFlow',
        description='Create EMR cluster with privileged role, execute Spark/Hadoop jobs with elevated permissions',
        required_actions=['iam:PassRole', 'emr:RunJobFlow'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='emr',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and emr:RunJobFlow can create an Amazon EMR cluster with a privileged "
            "IAM role attached. EMR clusters run Spark, Hadoop, and other big data frameworks, and the attacker can "
            "submit custom jobs that execute with the cluster's role permissions. This is particularly dangerous "
            "because EMR clusters often have access to large datasets in S3, databases, and data lakes. The attacker "
            "can use Spark or Hadoop jobs to exfiltrate data, access secrets, or make AWS API calls."
        ),
        remediation=(
            "1. Remove emr:RunJobFlow permission if not needed\n"
            "2. Restrict iam:PassRole to specific EMR service roles:\n"
            "   Condition: StringEquals: iam:PassedToService: elasticmapreduce.amazonaws.com\n"
            "3. Use EMR security configurations with encryption\n"
            "4. Monitor EMR cluster creation with CloudTrail\n"
            "5. Implement approval workflows for cluster launches\n"
            "6. Use AWS Lake Formation for fine-grained data access control"
        )
    ),
    
    # Pattern 29: PassRole + SageMaker Notebook
    'passrole_sagemaker_notebook': PrivescPattern(
        id='passrole_sagemaker_notebook',
        name='iam:PassRole + sagemaker:CreateNotebookInstance',
        description='Create SageMaker notebook with privileged role, execute Python code with elevated permissions',
        required_actions=['iam:PassRole', 'sagemaker:CreateNotebookInstance'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='sagemaker',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and sagemaker:CreateNotebookInstance can create a SageMaker notebook "
            "instance with a privileged execution role. SageMaker notebooks provide interactive Jupyter environments "
            "where the attacker can execute arbitrary Python code with the permissions of the attached role. This is "
            "particularly dangerous in ML/data science environments where notebooks often have access to production "
            "data, model artifacts, and S3 buckets containing sensitive information."
        ),
        remediation=(
            "1. Remove sagemaker:CreateNotebookInstance permission\n"
            "2. Restrict iam:PassRole to specific SageMaker roles:\n"
            "   Condition: StringEquals: iam:PassedToService: sagemaker.amazonaws.com\n"
            "3. Use SageMaker notebook instance lifecycle configs\n"
            "4. Enable notebook instance encryption\n"
            "5. Monitor notebook creation with CloudTrail\n"
            "6. Use VPC-only SageMaker configurations"
        )
    ),
    
    # Pattern 30: PassRole + SageMaker Training
    'passrole_sagemaker_training': PrivescPattern(
        id='passrole_sagemaker_training',
        name='iam:PassRole + sagemaker:CreateTrainingJob',
        description='Create SageMaker training job with privileged role, execute ML training code with elevated permissions',
        required_actions=['iam:PassRole', 'sagemaker:CreateTrainingJob'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='sagemaker',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and sagemaker:CreateTrainingJob can create a SageMaker training job "
            "with a privileged role. Training jobs execute custom Python training scripts in containers, and the "
            "attacker can inject malicious code that runs with the job's role permissions. This is stealthier than "
            "notebook instances because training jobs run in the background and may not be as closely monitored. "
            "The attacker can access S3 data, model artifacts, and make AWS API calls during training."
        ),
        remediation=(
            "1. Remove sagemaker:CreateTrainingJob permission\n"
            "2. Restrict iam:PassRole to approved SageMaker training roles:\n"
            "   Condition: StringEquals: iam:PassedToService: sagemaker.amazonaws.com\n"
            "3. Use container image signing for training jobs\n"
            "4. Monitor training job creation with CloudTrail\n"
            "5. Implement approval workflows for training jobs\n"
            "6. Use SageMaker VPC configurations"
        )
    ),
    
    # Pattern 31: PassRole + Step Functions
    'passrole_stepfunctions': PrivescPattern(
        id='passrole_stepfunctions',
        name='iam:PassRole + states:CreateStateMachine',
        description='Create Step Functions state machine with privileged role, orchestrate privesc via workflow',
        required_actions=['iam:PassRole', 'states:CreateStateMachine', 'states:StartExecution'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='stepfunctions',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and states:CreateStateMachine + states:StartExecution can create a "
            "Step Functions state machine with a privileged role. State machines can orchestrate multiple AWS "
            "services (Lambda, ECS, Batch, SageMaker, etc.) and the attacker can design a workflow that abuses "
            "the role's permissions across multiple steps. This is particularly powerful because Step Functions "
            "can invoke other services, pass data between steps, and create complex attack chains. The attacker "
            "can also use state machines to obfuscate their activities across multiple service invocations."
        ),
        remediation=(
            "1. Remove states:CreateStateMachine and states:StartExecution permissions\n"
            "2. Restrict iam:PassRole to specific Step Functions roles:\n"
            "   Condition: StringEquals: iam:PassedToService: states.amazonaws.com\n"
            "3. Use Step Functions service integration patterns\n"
            "4. Monitor state machine creation and execution with CloudTrail\n"
            "5. Implement approval workflows for new state machines\n"
            "6. Use X-Ray for Step Functions to track execution flows"
        )
    ),
    
    # Pattern 32: PassRole + IoT
    'passrole_iot': PrivescPattern(
        id='passrole_iot',
        name='iam:PassRole + iot:CreateJob',
        description='Create IoT job with privileged role, execute code on fleet of IoT devices',
        required_actions=['iam:PassRole', 'iot:CreateJob'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='iot',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and iot:CreateJob can create an AWS IoT job that executes on IoT devices "
            "with a privileged role. While IoT jobs primarily target edge devices, they can be combined with AWS IoT "
            "Greengrass to execute Lambda functions or containers on edge locations with the passed role's permissions. "
            "This can be used to access device data, local credentials, or pivot to cloud resources accessible to the "
            "IoT role. This is particularly dangerous in industrial IoT or smart city deployments."
        ),
        remediation=(
            "1. Remove iot:CreateJob permission if not needed\n"
            "2. Restrict iam:PassRole to specific IoT service roles:\n"
            "   Condition: StringEquals: iam:PassedToService: iot.amazonaws.com\n"
            "3. Use IoT device defender for fleet monitoring\n"
            "4. Monitor iot:CreateJob API calls with CloudTrail\n"
            "5. Implement approval workflows for IoT job creation\n"
            "6. Use AWS IoT Core security best practices"
        )
    ),
    
    # Batch 7 (v1.1.0): IAM-Only Privilege Escalation
    
    # Pattern 33: SetDefaultPolicyVersion
    'set_default_policy_version': PrivescPattern(
        id='set_default_policy_version',
        name='iam:SetDefaultPolicyVersion',
        description='Activate previous permissive policy version to regain elevated permissions',
        required_actions=['iam:SetDefaultPolicyVersion'],
        severity='HIGH',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "An attacker with iam:SetDefaultPolicyVersion can change which version of a managed policy is active. "
            "If a policy previously had more permissive permissions (e.g., full admin in v1, restricted in v2), "
            "the attacker can set v1 as the default to regain those elevated permissions. This is particularly "
            "dangerous because policy version history is often overlooked in security audits. AWS allows up to 5 "
            "policy versions, and security teams may create restrictive new versions without deleting old ones."
        ),
        remediation=(
            "1. Remove iam:SetDefaultPolicyVersion permission\n"
            "2. Use resource constraints to protect critical policies:\n"
            "   Resource: arn:aws:iam::*:policy/SpecificPolicy\n"
            "3. Monitor SetDefaultPolicyVersion API calls with CloudTrail\n"
            "4. Regularly audit and delete old policy versions\n"
            "5. Use SCPs to prevent policy version manipulation\n"
            "6. Implement policy version change approval workflows"
        )
    ),
    
    # Pattern 34: AddUserToGroup
    'add_user_to_group': PrivescPattern(
        id='add_user_to_group',
        name='iam:AddUserToGroup',
        description='Add self to admin or privileged group to inherit elevated permissions',
        required_actions=['iam:AddUserToGroup'],
        severity='CRITICAL',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "An attacker with iam:AddUserToGroup can add themselves to any IAM group, including admin groups. "
            "Groups inherit all attached policies, so adding yourself to a group with AdministratorAccess or other "
            "privileged policies grants immediate admin access. This is often overlooked because the permission seems "
            "administrative rather than security-critical. Unlike AttachUserPolicy, this doesn't create audit logs "
            "for policy attachment, only group membership changes."
        ),
        remediation=(
            "1. Remove iam:AddUserToGroup permission if not needed\n"
            "2. Use resource constraints to limit affected groups:\n"
            "   Resource: arn:aws:iam::*:group/AllowedGroup\n"
            "3. Add Condition to prevent adding to admin groups:\n"
            "   Condition: StringNotEquals: iam:ResourceTag/Privileged: true\n"
            "4. Monitor AddUserToGroup API calls with CloudTrail\n"
            "5. Implement approval workflows for group membership changes\n"
            "6. Use SCPs to deny group membership for sensitive groups"
        )
    ),
    
    # Pattern 35: Permission Boundary Bypass
    'permission_boundary_bypass': PrivescPattern(
        id='permission_boundary_bypass',
        name='iam:DeleteUserPermissionsBoundary',
        description='Remove permission boundary to bypass imposed security restrictions',
        required_actions=['iam:DeleteUserPermissionsBoundary'],
        severity='HIGH',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "Permission boundaries are IAM policies that set the maximum permissions a principal can have. They're "
            "commonly used to delegate permission management while maintaining guardrails. An attacker with "
            "iam:DeleteUserPermissionsBoundary (or DeleteRolePermissionsBoundary) can remove these restrictions. "
            "If the principal has broad policy attachments but was limited by a boundary, removing the boundary "
            "grants unrestricted access. This is particularly dangerous in delegated admin scenarios where users "
            "can attach policies to themselves but boundaries prevent abuse."
        ),
        remediation=(
            "1. Remove DeleteUserPermissionsBoundary permission\n"
            "2. Use resource constraints to protect specific users/roles:\n"
            "   Resource: arn:aws:iam::*:user/${aws:username}\n"
            "3. Add Condition to require MFA for boundary deletion\n"
            "4. Monitor permission boundary deletion with CloudTrail\n"
            "5. Use SCPs to enforce permission boundaries at org level\n"
            "6. Implement alerting for boundary removal events"
        )
    ),
    
    # Pattern 36: Tag-Based Access Control (ABAC) Bypass
    'tag_based_access_bypass': PrivescPattern(
        id='tag_based_access_bypass',
        name='iam:TagUser / iam:TagRole',
        description='Modify IAM tags to bypass attribute-based access control (ABAC) restrictions',
        required_actions=['iam:TagUser'],  # Also detects TagRole via alternative check
        severity='MEDIUM',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "Attribute-based access control (ABAC) uses IAM tags to enforce fine-grained permissions. For example, "
            "a policy might allow access only if aws:PrincipalTag/Department equals 'Engineering'. An attacker with "
            "iam:TagUser or iam:TagRole can add/modify tags on themselves or other principals to bypass these "
            "restrictions. By setting Department=Engineering, they can gain access to resources protected by ABAC "
            "policies. This also works with resource tags: iam:TagRole can modify role tags to assume restricted roles."
        ),
        remediation=(
            "1. Restrict TagUser/TagRole to specific principals:\n"
            "   Resource: arn:aws:iam::*:user/${aws:username}\n"
            "2. Add Condition to prevent modifying security-critical tags:\n"
            "   Condition: ForAllValues:StringNotEquals: aws:TagKeys: ['Department', 'Environment']\n"
            "3. Use separate tag namespaces for ABAC vs operational tags\n"
            "4. Monitor tag modification with CloudTrail\n"
            "5. Use SCPs to enforce tag immutability\n"
            "6. Implement tag change approval workflows"
        )
    ),
    
    # Batch 8 (v1.1.0): Service-Based Execution + Data Exfiltration
    
    # Pattern 37: EventBridge Lambda Trigger
    'eventbridge_lambda_trigger': PrivescPattern(
        id='eventbridge_lambda_trigger',
        name='events:PutRule + events:PutTargets',
        description='Create EventBridge rule to trigger existing Lambda functions with their execution roles',
        required_actions=['events:PutRule', 'events:PutTargets'],
        severity='HIGH',
        method=PrivescMethod.REMOTE_EXECUTION,
        service='eventbridge',
        explanation=(
            "An attacker with events:PutRule and events:PutTargets can create EventBridge (CloudWatch Events) rules "
            "that trigger existing Lambda functions. While the attacker cannot create new functions, they can invoke "
            "existing ones with privileged execution roles by setting up event patterns that match frequently (e.g., "
            "every minute, or on any S3 event). The Lambda executes with its own role permissions, not the attacker's. "
            "This is particularly dangerous if Lambda functions have admin roles, database access, or can be manipulated "
            "via environment variables or configuration."
        ),
        remediation=(
            "1. Remove events:PutRule and events:PutTargets permissions\n"
            "2. Restrict to specific event buses:\n"
            "   Resource: arn:aws:events:*:*:rule/allowed-prefix-*\n"
            "3. Use resource-based policies on Lambda to restrict invocation\n"
            "4. Monitor EventBridge rule creation with CloudTrail\n"
            "5. Implement approval workflows for new event rules\n"
            "6. Use least-privilege Lambda execution roles"
        )
    ),
    
    # Pattern 38: CloudWatch Events Target Manipulation
    'cloudwatch_events_target': PrivescPattern(
        id='cloudwatch_events_target',
        name='events:PutTargets',
        description='Modify CloudWatch Events targets to invoke privileged Lambda, Step Functions, or ECS tasks',
        required_actions=['events:PutTargets'],
        severity='MEDIUM',
        method=PrivescMethod.REMOTE_EXECUTION,
        service='events',
        explanation=(
            "An attacker with events:PutTargets can modify existing EventBridge/CloudWatch Events rules to change "
            "their targets. They can redirect events to different Lambda functions, Step Functions state machines, "
            "ECS tasks, or other AWS services. This allows abusing existing event patterns (which may fire frequently) "
            "to trigger privileged resources. For example, changing a rule that fires on S3 uploads to invoke an admin "
            "Lambda function. This is stealthier than creating new rules because existing rules may not be closely monitored."
        ),
        remediation=(
            "1. Remove events:PutTargets permission if not needed\n"
            "2. Use resource constraints on specific rules:\n"
            "   Resource: arn:aws:events:*:*:rule/safe-rule-*\n"
            "3. Enable CloudTrail for PutTargets API calls\n"
            "4. Use Lambda resource-based policies to restrict invocation\n"
            "5. Monitor unexpected target changes\n"
            "6. Implement change approval for event rule targets"
        )
    ),
    
    # Pattern 39: API Gateway Integration Abuse
    'apigateway_integration_abuse': PrivescPattern(
        id='apigateway_integration_abuse',
        name='apigateway:PUT / apigateway:PATCH',
        description='Modify API Gateway integrations to access privileged backend resources or Lambda functions',
        required_actions=['apigateway:PUT', 'apigateway:PATCH'],
        severity='MEDIUM',
        method=PrivescMethod.REMOTE_EXECUTION,
        service='apigateway',
        explanation=(
            "An attacker with apigateway:PUT or apigateway:PATCH can modify API Gateway REST API configurations, "
            "including integration backends. They can change integrations to point to different Lambda functions, "
            "HTTP endpoints, or AWS services. This allows hijacking existing API endpoints to invoke privileged "
            "Lambda functions, access internal HTTP APIs, or abuse service integrations (e.g., changing a public "
            "API to write to sensitive DynamoDB tables). Public-facing APIs provide an easy way to trigger the "
            "modified integrations remotely."
        ),
        remediation=(
            "1. Remove apigateway:PUT and apigateway:PATCH permissions\n"
            "2. Use resource constraints on specific APIs:\n"
            "   Resource: arn:aws:apigateway:*::/restapis/allowed-api-id/*\n"
            "3. Use Lambda resource-based policies to restrict API Gateway invocation\n"
            "4. Monitor API Gateway configuration changes with CloudTrail\n"
            "5. Implement deployment approval workflows\n"
            "6. Use API Gateway access logging to detect unexpected traffic patterns"
        )
    ),
    
    # Pattern 40: RDS Snapshot Data Exfiltration
    'rds_snapshot_export': PrivescPattern(
        id='rds_snapshot_export',
        name='rds:ModifyDBSnapshotAttribute + rds:CopyDBSnapshot',
        description='Share or copy RDS snapshots to exfiltrate database data including credentials and PII',
        required_actions=['rds:ModifyDBSnapshotAttribute', 'rds:CopyDBSnapshot'],
        severity='HIGH',
        method=PrivescMethod.SECRET_EXFILTRATION,
        service='rds',
        explanation=(
            "An attacker with rds:ModifyDBSnapshotAttribute can modify snapshot permissions to share them with "
            "external AWS accounts (including attacker-controlled accounts). Combined with rds:CopyDBSnapshot, "
            "they can also copy snapshots to different regions. Once shared or copied, the attacker can restore "
            "the snapshot in their own environment to access all database contents, including application data, "
            "user credentials, API keys, PII, and other sensitive information. This is a common data exfiltration "
            "technique in cloud breaches."
        ),
        remediation=(
            "1. Remove rds:ModifyDBSnapshotAttribute permission\n"
            "2. Restrict to specific snapshots:\n"
            "   Resource: arn:aws:rds:*:*:snapshot:allowed-prefix-*\n"
            "3. Add Condition to prevent public sharing:\n"
            "   Condition: StringNotEquals: rds:AttributeName: restore\n"
            "4. Monitor snapshot sharing with CloudTrail\n"
            "5. Enable RDS snapshot encryption (prevents cross-account restore)\n"
            "6. Use AWS Backup with WORM (Write Once Read Many) policies"
        )
    ),
    
    # Batch 9 (v1.2.0): Credential Access Expansion
    
    # Pattern 41: STS GetSessionToken
    'sts_get_session_token': PrivescPattern(
        id='sts_get_session_token',
        name='sts:GetSessionToken',
        description='Generate temporary credentials to bypass MFA requirements on API calls',
        required_actions=['sts:GetSessionToken'],
        severity='MEDIUM',
        method=PrivescMethod.CREDENTIAL_ACCESS,
        service='sts',
        explanation=(
            "sts:GetSessionToken allows generating temporary AWS credentials (access key, secret key, session token) "
            "for the calling principal. While these credentials have the same permissions as the original principal, "
            "they can bypass MFA requirements on subsequent API calls. If a policy requires MFA for sensitive actions "
            "(Condition: aws:MultiFactorAuthPresent: true), an attacker can use GetSessionToken to obtain credentials "
            "that appear to have MFA enabled. This is particularly dangerous for accessing resources protected by MFA "
            "conditions, such as production S3 buckets, RDS databases, or IAM policy modifications."
        ),
        remediation=(
            "1. Remove sts:GetSessionToken permission if not needed\n"
            "2. Use resource constraints where possible\n"
            "3. Require MFA for GetSessionToken itself:\n"
            "   Condition: MultiFactorAuthPresent: true\n"
            "4. Monitor GetSessionToken API calls with CloudTrail\n"
            "5. Use session duration limits\n"
            "6. Prefer IAM roles with AssumeRole over long-term credentials"
        )
    ),
    
    # Pattern 42: STS GetFederationToken
    'sts_get_federation_token': PrivescPattern(
        id='sts_get_federation_token',
        name='sts:GetFederationToken',
        description='Create federated user sessions with custom inline policies up to principal permissions',
        required_actions=['sts:GetFederationToken'],
        severity='MEDIUM',
        method=PrivescMethod.CREDENTIAL_ACCESS,
        service='sts',
        explanation=(
            "sts:GetFederationToken creates temporary federated user credentials with custom inline policies. While "
            "the federated session cannot exceed the calling principal's permissions, an attacker can craft optimized "
            "permission sets for specific attack scenarios. For example, if the principal has broad permissions but "
            "is monitored, the attacker can create a federated session with just the permissions needed for data "
            "exfiltration (s3:GetObject) to reduce detection. Federated sessions also have different CloudTrail "
            "attribution (federatedUser instead of the original principal), potentially evading monitoring rules."
        ),
        remediation=(
            "1. Remove sts:GetFederationToken permission\n"
            "2. Use IAM roles with AssumeRole instead of federation\n"
            "3. Monitor GetFederationToken API calls with CloudTrail\n"
            "4. Set up alerts for federated user activity\n"
            "5. Limit session duration (default 12 hours, max 36 hours)\n"
            "6. Review CloudTrail logs for unusual federatedUser patterns"
        )
    ),
    
    # Pattern 43: EC2 Instance Metadata Credential Theft
    'ec2_imds_credential_theft': PrivescPattern(
        id='ec2_imds_credential_theft',
        name='ec2:DescribeInstances + SSRF/Network Access',
        description='Identify EC2 instances and steal IAM role credentials via Instance Metadata Service (IMDS)',
        required_actions=['ec2:DescribeInstances'],
        severity='LOW',
        method=PrivescMethod.CREDENTIAL_ACCESS,
        service='ec2',
        explanation=(
            "An attacker with ec2:DescribeInstances can enumerate EC2 instances and their attached IAM roles. While "
            "the permission itself doesn't grant credential access, it provides intelligence for IMDS attacks. If the "
            "attacker gains any access to an EC2 instance (SSRF vulnerability, SSH access, SSM access, compromised "
            "application), they can query the Instance Metadata Service at http://169.254.169.254/latest/meta-data/iam/ "
            "to retrieve temporary credentials for the instance's IAM role. This is a common privilege escalation path "
            "in cloud penetration testing, especially when combined with SSRF vulnerabilities in web applications."
        ),
        remediation=(
            "1. Implement IMDSv2 (session-oriented) to prevent SSRF attacks:\n"
            "   aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-tokens required\n"
            "2. Use VPC endpoints to restrict instance network access\n"
            "3. Minimize IAM role permissions on EC2 instances\n"
            "4. Monitor unusual IMDS access patterns\n"
            "5. Use instance metadata hop limit = 1\n"
            "6. Implement network segmentation and security groups"
        )
    ),
    
    # Pattern 44: CodeCommit Git Credentials
    'codecommit_git_credentials': PrivescPattern(
        id='codecommit_git_credentials',
        name='iam:CreateServiceSpecificCredential',
        description='Generate Git credentials for CodeCommit to access source code repositories',
        required_actions=['iam:CreateServiceSpecificCredential'],
        severity='MEDIUM',
        method=PrivescMethod.CREDENTIAL_ACCESS,
        service='codecommit',
        explanation=(
            "iam:CreateServiceSpecificCredential allows generating Git credentials for AWS CodeCommit. An attacker "
            "can create credentials for themselves or other IAM users to clone private repositories containing source "
            "code, configuration files, secrets, and infrastructure-as-code templates. This is particularly dangerous "
            "because CodeCommit repositories often contain hardcoded credentials, API keys, database connection strings, "
            "and architectural documentation. Unlike SSH keys, service-specific credentials are password-based and may "
            "not be monitored as closely. Once credentials are generated, the attacker can clone repositories outside "
            "of AWS without further API calls."
        ),
        remediation=(
            "1. Remove iam:CreateServiceSpecificCredential permission\n"
            "2. Use resource constraints to limit which users can have credentials:\n"
            "   Resource: arn:aws:iam::*:user/${aws:username}\n"
            "3. Monitor CreateServiceSpecificCredential API calls\n"
            "4. Implement credential rotation policies\n"
            "5. Use SSH keys instead of HTTPS credentials where possible\n"
            "6. Enable CodeCommit repository access logging\n"
            "7. Scan repositories for secrets using tools like git-secrets"
        )
    ),
    
    # Pattern 45: RDS IAM Database Authentication
    'rds_iam_auth_token': PrivescPattern(
        id='rds_iam_auth_token',
        name='rds-db:connect',
        description='Generate RDS database authentication tokens to access databases without passwords',
        required_actions=['rds-db:connect'],
        severity='MEDIUM',
        method=PrivescMethod.CREDENTIAL_ACCESS,
        service='rds',
        explanation=(
            "The rds-db:connect permission allows generating 15-minute authentication tokens for RDS databases that "
            "have IAM database authentication enabled. An attacker with this permission can connect to RDS MySQL or "
            "PostgreSQL databases without knowing database passwords. The token is generated via AWS STS and used as "
            "a temporary password. This bypasses traditional database credential management and can provide access to "
            "production databases, customer data, PII, and application secrets stored in database tables. It's "
            "particularly dangerous because database access may not be logged in CloudTrail (only the token generation is)."
        ),
        remediation=(
            "1. Restrict rds-db:connect to specific database resources:\n"
            "   Resource: arn:aws:rds-db:region:account:dbuser:db-instance-id/db-username\n"
            "2. Monitor rds-db:connect API calls with CloudTrail\n"
            "3. Enable database audit logging to track connections\n"
            "4. Use VPC security groups to restrict database network access\n"
            "5. Implement database-level access controls\n"
            "6. Consider using AWS Secrets Manager for database credentials\n"
            "7. Review which databases have IAM authentication enabled"
        )
    ),
    
    # Batch 10 (v1.2.0): IAM-Only + Service Execution - FINAL to 50 patterns
    
    # Pattern 46: CreatePolicy + AttachUserPolicy Combo
    'create_policy_attach_combo': PrivescPattern(
        id='create_policy_attach_combo',
        name='iam:CreatePolicy + iam:AttachUserPolicy',
        description='Create custom admin policy and attach to self for privilege escalation',
        required_actions=['iam:CreatePolicy', 'iam:AttachUserPolicy'],
        severity='CRITICAL',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "An attacker with both iam:CreatePolicy and iam:AttachUserPolicy can perform a two-step privilege "
            "escalation. First, they create a new managed policy with admin permissions (Effect: Allow, Action: *, "
            "Resource: *). Then, they attach this policy to themselves using AttachUserPolicy. This is more stealthy "
            "than directly having AttachUserPolicy with access to AWS managed policies like AdministratorAccess, "
            "because the custom policy may not be monitored as closely. The attacker can also create policies with "
            "specific permissions tailored to their attack objectives, potentially evading detection rules that look "
            "for attachment of known privileged policies."
        ),
        remediation=(
            "1. Remove iam:CreatePolicy and iam:AttachUserPolicy permissions\n"
            "2. Use resource constraints on AttachUserPolicy:\n"
            "   Resource: arn:aws:iam::*:user/${aws:username}\n"
            "3. Add Condition to restrict attachable policies:\n"
            "   Condition: ArnNotEquals: iam:PolicyArn: arn:aws:iam::*:policy/Custom*\n"
            "4. Monitor CreatePolicy and AttachUserPolicy API calls together\n"
            "5. Implement approval workflows for new policy creation\n"
            "6. Use SCPs to deny attachment of overly permissive policies"
        )
    ),
    
    # Pattern 47: Delete Account Password Policy
    'delete_account_password_policy': PrivescPattern(
        id='delete_account_password_policy',
        name='iam:DeleteAccountPasswordPolicy',
        description='Remove account password policy to enable weak passwords and facilitate account takeover',
        required_actions=['iam:DeleteAccountPasswordPolicy'],
        severity='MEDIUM',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "iam:DeleteAccountPasswordPolicy removes the account-wide password policy that enforces complexity "
            "requirements, minimum length, rotation, and password reuse restrictions. An attacker can delete this "
            "policy to weaken security controls, then use UpdateLoginProfile or CreateLoginProfile to set weak "
            "passwords on other user accounts. This facilitates brute-force attacks, credential stuffing, and "
            "social engineering. It's particularly dangerous when combined with CreateLoginProfile (for users without "
            "console access) or UpdateLoginProfile (to reset existing passwords). The deletion is a one-time API call "
            "that affects all IAM users in the account."
        ),
        remediation=(
            "1. Remove iam:DeleteAccountPasswordPolicy permission\n"
            "2. Enforce password policy via AWS Organizations SCP\n"
            "3. Monitor DeleteAccountPasswordPolicy API calls with CloudTrail\n"
            "4. Set up CloudWatch alarms for policy deletion\n"
            "5. Implement automated re-application of password policy\n"
            "6. Use AWS SSO instead of IAM users where possible"
        )
    ),
    
    # Pattern 48: SAML/OIDC Provider Manipulation
    'saml_oidc_provider_manipulation': PrivescPattern(
        id='saml_oidc_provider_manipulation',
        name='iam:UpdateSAMLProvider / iam:UpdateOpenIDConnectProviderThumbprint',
        description='Modify SAML or OIDC identity providers to enable unauthorized federated access',
        required_actions=['iam:UpdateSAMLProvider'],
        severity='HIGH',
        method=PrivescMethod.ROLE_MANIPULATION,
        explanation=(
            "SAML and OIDC providers enable federated authentication to AWS. An attacker with iam:UpdateSAMLProvider "
            "or iam:UpdateOpenIDConnectProviderThumbprint can modify the provider configuration to accept authentication "
            "from attacker-controlled identity providers. For SAML, they can upload a malicious SAML metadata document "
            "that their own IdP will sign. For OIDC (e.g., Google, GitHub), they can update the thumbprint to trust "
            "a different provider. Once the provider is compromised, the attacker can authenticate as any federated user "
            "and assume roles that trust the provider. This is particularly dangerous in organizations using SSO for AWS access."
        ),
        remediation=(
            "1. Remove UpdateSAMLProvider and UpdateOpenIDConnectProviderThumbprint permissions\n"
            "2. Monitor SAML/OIDC provider modifications with CloudTrail\n"
            "3. Use resource constraints to protect specific providers:\n"
            "   Resource: arn:aws:iam::*:saml-provider/Production*\n"
            "4. Implement approval workflows for federation changes\n"
            "5. Regularly audit federation configurations\n"
            "6. Use condition keys to restrict provider updates\n"
            "7. Enable MFA for users with federation permissions"
        )
    ),
    
    # Pattern 49: S3 Bucket Notification Configuration
    's3_bucket_notification': PrivescPattern(
        id='s3_bucket_notification',
        name='s3:PutBucketNotification',
        description='Configure S3 bucket events to trigger existing Lambda functions with their execution roles',
        required_actions=['s3:PutBucketNotification'],
        severity='MEDIUM',
        method=PrivescMethod.REMOTE_EXECUTION,
        service='s3',
        explanation=(
            "s3:PutBucketNotification allows configuring event notifications on S3 buckets to trigger Lambda functions, "
            "SNS topics, or SQS queues. An attacker can configure frequently-accessed buckets to invoke existing Lambda "
            "functions on events like s3:ObjectCreated, s3:ObjectRemoved, etc. The Lambda executes with its own role "
            "permissions, not the attacker's. By uploading objects to the bucket or leveraging normal application traffic, "
            "the attacker can repeatedly invoke privileged Lambda functions. This is particularly effective against "
            "high-traffic buckets (e.g., application uploads, logging) where functions will be triggered automatically "
            "without suspicious API calls."
        ),
        remediation=(
            "1. Restrict s3:PutBucketNotification to specific buckets:\n"
            "   Resource: arn:aws:s3:::allowed-bucket-*\n"
            "2. Use Lambda resource-based policies to restrict S3 invocation:\n"
            "   Condition: StringEquals: AWS:SourceArn: arn:aws:s3:::safe-bucket\n"
            "3. Monitor PutBucketNotification API calls with CloudTrail\n"
            "4. Implement S3 bucket policy to restrict notification configuration\n"
            "5. Use S3 event notification validation\n"
            "6. Review Lambda function permissions and minimize privileges"
        )
    ),
    
    # Pattern 50: DynamoDB Stream Lambda Trigger
    'dynamodb_stream_lambda': PrivescPattern(
        id='dynamodb_stream_lambda',
        name='lambda:CreateEventSourceMapping',
        description='Create event source mapping to trigger Lambda from DynamoDB streams or Kinesis',
        required_actions=['lambda:CreateEventSourceMapping'],
        severity='MEDIUM',
        method=PrivescMethod.REMOTE_EXECUTION,
        service='lambda',
        explanation=(
            "lambda:CreateEventSourceMapping allows connecting event sources (DynamoDB Streams, Kinesis, SQS, Kafka) "
            "to Lambda functions. An attacker can map existing Lambda functions with privileged roles to DynamoDB tables "
            "or Kinesis streams. When data is written to the stream (which may happen frequently in production applications), "
            "the Lambda function is automatically invoked with the stream records. The function executes with its execution "
            "role permissions, not the attacker's. This is stealthier than direct Lambda invocation because the trigger "
            "is legitimate application activity. High-volume streams (user activity, transaction logs) provide frequent "
            "execution opportunities."
        ),
        remediation=(
            "1. Restrict lambda:CreateEventSourceMapping to specific functions:\n"
            "   Resource: arn:aws:lambda:*:*:function:allowed-function-*\n"
            "2. Use Lambda resource-based policies to restrict event sources\n"
            "3. Monitor CreateEventSourceMapping API calls with CloudTrail\n"
            "4. Implement approval workflows for new event source mappings\n"
            "5. Review Lambda execution roles and minimize privileges\n"
            "6. Use DynamoDB stream encryption and access controls\n"
            "7. Set up alerts for unexpected event source mapping creation"
        )
    ),
    
    # ========== EKS PRIVILEGE ESCALATION PATTERNS (v1.1.0) ==========
    
    # Pattern 51: EKS IRSA Abuse via Pod Execution
    'eks_irsa_pod_exec': PrivescPattern(
        id='eks_irsa_pod_exec',
        name='EKS IRSA Abuse: Pod Execution with Privileged Service Account',
        description='Deploy pods to EKS cluster with IRSA service accounts to assume powerful IAM roles',
        required_actions=['eks:DescribeCluster'],
        severity='CRITICAL',
        method=PrivescMethod.EKS_ABUSE,
        service='eks',
        conditional_requirements=['kubectl access', 'K8s RBAC: pod creation rights'],
        explanation=(
            "IRSA (IAM Roles for Service Accounts) allows Kubernetes pods to assume IAM roles via OIDC federation. "
            "An attacker with kubectl access to an EKS cluster can deploy pods that use service accounts annotated "
            "with IAM role ARNs. If powerful IRSA roles exist (e.g., with admin access, S3 full access, or secrets "
            "read permissions), the attacker can deploy a pod with that service account and obtain temporary credentials "
            "via the AWS_WEB_IDENTITY_TOKEN_FILE. This bypasses traditional IAM credential controls and can escalate "
            "from limited K8s RBAC to full AWS account access. The attack requires: (1) kubectl/pod deployment access, "
            "(2) knowledge of IRSA-enabled service accounts, and (3) existing powerful IRSA roles in the cluster."
        ),
        remediation=(
            "1. Minimize IRSA role permissions using least privilege\n"
            "2. Use K8s RBAC to restrict pod creation to specific namespaces\n"
            "3. Implement PodSecurityPolicy or OPA Gatekeeper to block unauthorized service account usage\n"
            "4. Monitor eks:DescribeCluster and sts:AssumeRoleWithWebIdentity calls\n"
            "5. Add OIDC condition keys to IRSA trust policies:\n"
            "   Condition: StringEquals: oidc.eks.REGION.amazonaws.com/id/CLUSTER_ID:sub: system:serviceaccount:NAMESPACE:SA_NAME\n"
            "6. Use AWS IAM role session tagging to track pod-originated sessions\n"
            "7. Enable EKS control plane logging for audit trail\n"
            "8. Regularly audit IRSA roles and remove unused ones"
        )
    ),
    
    # Pattern 52: EKS Node Role Abuse via Instance Metadata
    'eks_node_role_abuse': PrivescPattern(
        id='eks_node_role_abuse',
        name='EKS Node Role Abuse: Pod Escape to Instance Metadata',
        description='Escape pod to access EKS node instance metadata and assume node IAM role',
        required_actions=['eks:DescribeCluster'],
        severity='HIGH',
        method=PrivescMethod.EKS_ABUSE,
        service='eks',
        conditional_requirements=['kubectl access', 'Pod without IMDSv2 enforcement'],
        explanation=(
            "EKS nodes run as EC2 instances with IAM instance profiles (node roles). By default, pods can access the "
            "EC2 instance metadata service (IMDS) at http://169.254.169.254 to retrieve temporary credentials for the "
            "node role. An attacker with pod execution access can: (1) deploy a pod without 'automountServiceAccountToken: false', "
            "(2) curl the metadata endpoint to retrieve node role credentials, and (3) use those credentials outside the pod. "
            "Node roles often have broad permissions (ec2:*, eks:*, ecr:*, CloudWatch, etc.) to manage cluster infrastructure. "
            "This attack is especially dangerous if IMDSv1 is enabled (no session token required) or if pod security policies "
            "don't block hostNetwork/hostPath access. It bypasses IRSA restrictions and K8s RBAC."
        ),
        remediation=(
            "1. Enforce IMDSv2 on EKS nodes (requires session token):\n"
            "   aws ec2 modify-instance-metadata-options --instance-id ID --http-tokens required\n"
            "2. Use iptables rules to block pod access to metadata (Amazon VPC CNI default in newer versions)\n"
            "3. Deploy pods with 'automountServiceAccountToken: false' by default\n"
            "4. Use PodSecurityPolicy to block hostNetwork and hostPath\n"
            "5. Minimize EKS node role permissions using least privilege\n"
            "6. Segregate workloads into different node groups with different IAM roles\n"
            "7. Use Fargate for sensitive workloads (pods run in isolated VMs)\n"
            "8. Monitor IMDSv1 usage with VPC Flow Logs\n"
            "9. Enable EKS Pod Security Standards (restricted profile)"
        )
    ),
    
    # Pattern 53: EKS Cluster Admin via UpdateClusterConfig
    'eks_update_cluster_config': PrivescPattern(
        id='eks_update_cluster_config',
        name='eks:UpdateClusterConfig',
        description='Modify EKS cluster configuration to add attacker IAM principal as cluster admin',
        required_actions=['eks:UpdateClusterConfig'],
        severity='CRITICAL',
        method=PrivescMethod.EKS_ABUSE,
        service='eks',
        conditional_requirements=['kubectl access after config update'],
        explanation=(
            "eks:UpdateClusterConfig allows modifying EKS cluster settings, including the 'accessConfig' which defines "
            "which IAM principals can authenticate to the cluster. An attacker with this permission can add their own "
            "IAM user/role to the cluster's aws-auth ConfigMap or use the new EKS access entries API to grant themselves "
            "system:masters (cluster-admin) access. Once added, they can use kubectl with full cluster permissions to: "
            "(1) deploy privileged pods, (2) access secrets, (3) modify deployments, (4) abuse IRSA roles, and (5) escape "
            "to node roles. This is a critical privilege escalation because it bridges IAM and Kubernetes RBAC. The attack "
            "requires only a single API call: eks:UpdateClusterConfig with the attacker's ARN in the admin section."
        ),
        remediation=(
            "1. Remove eks:UpdateClusterConfig from all non-admin principals\n"
            "2. Use resource constraints to protect specific clusters:\n"
            "   Resource: arn:aws:eks:*:*:cluster/production-*\n"
            "3. Enable EKS control plane logging and monitor UpdateClusterConfig calls\n"
            "4. Use AWS Organizations SCPs to block UpdateClusterConfig for certain roles\n"
            "5. Implement approval workflows for cluster configuration changes\n"
            "6. Use EKS access entries instead of aws-auth ConfigMap (easier to audit)\n"
            "7. Set up CloudWatch alarms for unexpected cluster config updates\n"
            "8. Regularly audit cluster access entries and aws-auth ConfigMap"
        )
    ),
    
    # Pattern 54: EKS + PassRole for Node Group Creation
    'eks_passrole_nodegroup': PrivescPattern(
        id='eks_passrole_nodegroup',
        name='iam:PassRole + eks:CreateNodegroup',
        description='Create EKS node group with privileged IAM role to gain access via instance metadata',
        required_actions=['iam:PassRole', 'eks:CreateNodegroup'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='eks',
        requires_target_role=True,
        conditional_requirements=['kubectl access', 'Pod scheduling to new node group'],
        explanation=(
            "Similar to PassRole + EC2, an attacker can create a new EKS node group and attach a privileged IAM role to it. "
            "The node group launches EC2 instances with that role as their instance profile. The attacker can then: "
            "(1) deploy a pod to the cluster that gets scheduled on the new node group, (2) access the instance metadata "
            "from inside the pod, and (3) retrieve credentials for the privileged role. This is stealthier than launching "
            "standalone EC2 instances because EKS nodes look like legitimate cluster infrastructure. The attack requires "
            "kubectl access to deploy pods (which may be available if the attacker is already a cluster user) and the "
            "ability to target specific node groups via nodeSelector or taints/tolerations."
        ),
        remediation=(
            "1. Remove eks:CreateNodegroup permission\n"
            "2. Restrict iam:PassRole to specific node roles:\n"
            "   Resource: arn:aws:iam::*:role/eks-node-role-*\n"
            "3. Use resource constraints on eks:CreateNodegroup:\n"
            "   Resource: arn:aws:eks:*:*:cluster/allowed-cluster\n"
            "4. Monitor CreateNodegroup API calls with CloudTrail\n"
            "5. Use EKS managed node groups with automated updates\n"
            "6. Implement node group naming conventions and validation\n"
            "7. Enforce IMDSv2 on all EKS nodes\n"
            "8. Use admission controllers to prevent pod scheduling on unauthorized node groups"
        )
    ),
    
    # Pattern 55: EKS Fargate Profile for Pod Execution Role
    'eks_passrole_fargate': PrivescPattern(
        id='eks_passrole_fargate',
        name='iam:PassRole + eks:CreateFargateProfile',
        description='Create Fargate profile with privileged pod execution role for serverless privilege escalation',
        required_actions=['iam:PassRole', 'eks:CreateFargateProfile'],
        severity='HIGH',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='eks',
        requires_target_role=True,
        conditional_requirements=['kubectl access', 'Pod deployment to Fargate namespace'],
        explanation=(
            "EKS Fargate profiles define which pods run on Fargate (serverless) instead of EC2 nodes. Each profile has a "
            "pod execution role that Fargate uses to pull container images and write logs. An attacker with iam:PassRole "
            "and eks:CreateFargateProfile can create a new Fargate profile with a privileged pod execution role and configure "
            "it to match pods in a specific namespace. When the attacker deploys a pod to that namespace, it runs on Fargate "
            "and inherits the pod execution role. Unlike node roles (which require metadata access), Fargate pod execution roles "
            "are directly accessible via environment variables in the pod. This provides a cleaner escalation path if the role "
            "has admin or high-privilege permissions. The attack requires kubectl access to deploy pods."
        ),
        remediation=(
            "1. Remove eks:CreateFargateProfile permission\n"
            "2. Restrict iam:PassRole to specific Fargate execution roles:\n"
            "   Resource: arn:aws:iam::*:role/eks-fargate-pod-execution-role-*\n"
            "3. Use resource constraints on eks:CreateFargateProfile:\n"
            "   Resource: arn:aws:eks:*:*:cluster/allowed-cluster\n"
            "4. Monitor CreateFargateProfile API calls with CloudTrail\n"
            "5. Minimize Fargate pod execution role permissions (only ECR pull and CloudWatch logs)\n"
            "6. Use K8s RBAC to restrict pod creation to specific namespaces\n"
            "7. Implement admission controllers to validate pod namespaces\n"
            "8. Regularly audit Fargate profiles and remove unused ones"
        )
    ),
    
    # Pattern 56: EKS Wildcard Permissions
    'eks_wildcard_permissions': PrivescPattern(
        id='eks_wildcard_permissions',
        name='eks:* Wildcard Permissions',
        description='Unrestricted EKS permissions allow full cluster control and IRSA abuse',
        required_actions=['eks:*'],
        severity='CRITICAL',
        method=PrivescMethod.EKS_ABUSE,
        service='eks',
        conditional_requirements=['kubectl access for full exploitation'],
        explanation=(
            "eks:* wildcard permission grants all EKS API actions, including critical operations like UpdateClusterConfig, "
            "CreateNodegroup, CreateFargateProfile, UpdateNodegroupConfig, and DescribeCluster. An attacker with this permission "
            "can: (1) add themselves as cluster admin, (2) create node groups with privileged roles, (3) modify cluster authentication, "
            "(4) access OIDC provider details for IRSA abuse, (5) delete clusters for denial of service, and (6) modify cluster "
            "logging/monitoring. This is equivalent to full EKS administrative access and should only be granted to cluster operators. "
            "It's particularly dangerous when combined with iam:PassRole, as it enables all PassRole-based EKS escalations."
        ),
        remediation=(
            "1. Replace eks:* with specific required actions (e.g., eks:DescribeCluster, eks:ListClusters)\n"
            "2. Use resource constraints to limit scope:\n"
            "   Resource: arn:aws:eks:*:*:cluster/dev-*\n"
            "3. Implement separate roles for read-only vs. write operations\n"
            "4. Monitor EKS API calls with CloudTrail\n"
            "5. Use AWS Organizations SCPs to block dangerous actions\n"
            "6. Enable EKS control plane logging\n"
            "7. Use condition keys to restrict actions to specific clusters"
        )
    ),
}


# Phase 2A-2: Additional patterns (to be added)
ADDITIONAL_PATTERNS = {
    'passrole_ec2': 'iam:PassRole + ec2:RunInstances',
    'passrole_ecs': 'iam:PassRole + ecs:RunTask',
    'attach_role_policy': 'iam:AttachRolePolicy',
    'put_role_policy': 'iam:PutRolePolicy',
    'create_access_key': 'iam:CreateAccessKey (for other users)',
    'create_login_profile': 'iam:CreateLoginProfile',
    'update_login_profile': 'iam:UpdateLoginProfile',
    'add_user_to_group': 'iam:AddUserToGroup (to admin group)',
    # ... ~20+ more patterns from Rhino Security research
}


class PrivescDetector:
    """Detect privilege escalation opportunities in effective permissions"""
    
    def __init__(self):
        self.patterns = PRIVESC_PATTERNS
    
    def detect_privesc_methods(
        self, 
        effective_permissions,
        high_value_roles: Optional[Set[str]] = None
    ) -> List[dict]:
        """
        Detect which privesc patterns this principal can execute.
        
        Args:
            effective_permissions: EffectivePermissions object
            high_value_roles: Set of role ARNs with admin/high privileges
            
        Returns:
            List of detected privesc opportunities
        """
        detections = []
        
        for pattern_id, pattern in self.patterns.items():
            # Special handling for tag_based_access_bypass - detect either TagUser or TagRole
            if pattern_id == 'tag_based_access_bypass':
                has_tag_user = effective_permissions.has_actions(['iam:TagUser'])
                has_tag_role = effective_permissions.has_actions(['iam:TagRole'])
                if not (has_tag_user or has_tag_role):
                    continue
            # Check if principal has ALL required actions
            elif not effective_permissions.has_actions(pattern.required_actions):
                continue
                
            # If pattern requires a target role, check if any high-value roles exist
            if pattern.requires_target_role and not high_value_roles:
                continue  # Skip if no target roles available
            
            detections.append({
                'pattern_id': pattern.id,
                'pattern_name': pattern.name,
                'severity': pattern.severity,
                'method': pattern.method.value,
                'description': pattern.description,
                'explanation': pattern.explanation,
                'remediation': pattern.remediation,
                'required_actions': pattern.required_actions,
                'service': pattern.service,
                'conditional_requirements': pattern.conditional_requirements
            })
        
        return detections
    
    def get_pattern_by_id(self, pattern_id: str) -> Optional[PrivescPattern]:
        """Get pattern details by ID"""
        return self.patterns.get(pattern_id)
