# Terraform Attack Path Engine

> Detect IAM privilege escalation in Terraform plans before deployment

## What It Does

Analyzes `terraform plan` output to find **security issues before `terraform apply`**.

```bash
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json
heimdall terraform scan plan.json
```

## What We Detect

### 🔴 Critical (Block Deployment)

| Category | Patterns |
|----------|----------|
| **IAM Privilege Escalation** | Admin policy attachment, policy version manipulation, trust policy hijack, credential creation |
| **Remote Code Execution** | SSM SendCommand, Lambda code injection, EC2 user data injection |
| **Audit Bypass** | CloudTrail tampering, GuardDuty/SecurityHub disabling |

### 🟠 High Risk

| Category | Patterns |
|----------|----------|
| **PassRole Chains** | PassRole → Lambda/EC2/ECS/Glue/SageMaker/etc → Admin |
| **AssumeRole Chains** | Role → AssumeRole → Admin Role |
| **Multi-Hop Chains** | 3+ hop privilege escalation paths |
| **Cross-Service** | S3→Lambda, SQS→Lambda, API Gateway→Lambda triggers |
| **Data Exfil** | Broad S3 access, secrets access, KMS abuse |

### 📊 45+ Attack Patterns and more is coming...

- 10 IAM privilege escalation patterns
- 12 PassRole/AssumeRole chain patterns  
- 11 cross-service attack patterns
- 8 EC2/EBS/S3 data patterns
- 4 network/security group patterns

## Key Features

| Feature | Description |
|---------|-------------|
| **Before/After Diff** | Shows security posture change |
| **Risk Delta** | Quantifies impact (+15 risk score) |
| **Multi-Hop Detection** | Finds complex 3+ hop chains |
| **Actionable Fixes** | Specific recommendations per issue |
| **CI/CD Ready** | Exit codes for automation |

## Example Output

```
📊 Security Posture Comparison
╔═══════════════════════════╤══════════════╤══════════════╤════════════════╗
║ Metric                    │    Before    │    After     │     Change     ║
╟───────────────────────────┼──────────────┼──────────────┼────────────────╢
║ ⚔️ Attack Paths            │      0       │      3       │       +3       ║
║ 🎯 Risk Score             │      0       │      25      │      +25       ║
╚═══════════════════════════╧══════════════╧══════════════╧════════════════╝

🔴 NEW CRITICAL (2)
   + Admin Policy Attachment → my-admin-role
   + Assume Role To Admin → dev-role → my-admin-role

❌ FAILED - This plan introduces 2 critical issues
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Terraform Security Scan
  run: |
    terraform plan -out=plan.tfplan
    terraform show -json plan.tfplan > plan.json
    heimdall terraform scan plan.json --fail-on critical
```

## Test Results

| Test | Scenario | Status |
|------|----------|--------|
| Real AWS | 7 deployment tests | ✅ PASS |
| False Positives | 0 detected | ✅ |
| False Negatives | 0 detected | ✅ |

## Limitations

- AWS only (Azure/GCP planned)
- Single account (cross-account planned)
- Requires `terraform plan` JSON output

---
