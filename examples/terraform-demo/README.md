# 🧪 Heimdall PR Simulator - Terraform Demo

This directory contains example Terraform configurations to test Heimdall PR Simulator.

## 📁 Files

- **`main.tf`** - Safe IAM configuration (read-only permissions)
- **`dangerous-change.tf.example`** - Example of dangerous changes that Heimdall will block

## 🚀 Quick Test

### 1. Test Locally

```bash
# From heimdall root directory
cd examples/terraform-demo

# Generate Terraform plan
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Run Heimdall simulation
cd ../..
python -m heimdall.cli pr-simulate \
  --current-state test-scan-v1.8.0.json \
  --terraform-plan examples/terraform-demo/tfplan.json \
  --format text
```

### 2. Test with GitHub Action

**Step 1: Create a branch with safe changes**

```bash
git checkout -b feature/safe-iam-change
git add examples/terraform-demo/main.tf
git commit -m "Add safe IAM configuration"
git push origin feature/safe-iam-change
```

**Result:** ✅ PR approved, no security issues

**Step 2: Create a branch with dangerous changes**

```bash
git checkout -b feature/dangerous-iam-change

# Replace main.tf with dangerous version
mv examples/terraform-demo/dangerous-change.tf.example examples/terraform-demo/main.tf

git add examples/terraform-demo/main.tf
git commit -m "Add Lambda permissions for developer"
git push origin feature/dangerous-iam-change
```

**Result:** ❌ PR blocked by Heimdall!

```markdown
## 🛡️ Heimdall PR Security Analysis

**Status:** ❌ MERGE BLOCKED

### 📊 Summary

| Metric | Current | Proposed | Delta |
|--------|---------|----------|-------|
| CRITICAL paths | 136 | 137 | +1 |

**Risk Delta:** +1 CRITICAL

### ⚠️ New Attack Paths (1)

[CRITICAL] alice-developer - passrole_lambda
```

## 🎬 Attack Scenario Explained

### The Vulnerable Configuration

```hcl
resource "aws_iam_user_policy" "dev_dangerous" {
  name = "developer-dangerous"
  user = aws_iam_user.developer.name

  policy = jsonencode({
    Statement = [{
      Action = [
        "iam:PassRole",           # 🚨 Step 1
        "lambda:CreateFunction",  # 🚨 Step 2
        "lambda:InvokeFunction"   # 🚨 Step 3
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "admin_role" {
  name = "AdminRole"
  # Admin access policy attached
}
```

### The Attack Path

```
alice-developer (low privilege user)
  ↓
  Uses: iam:PassRole + lambda:CreateFunction
  ↓
  Creates: Lambda function with AdminRole attached
  ↓
  Lambda executes with: FULL ADMIN ACCESS
  ↓
  alice-developer controls: THE ENTIRE AWS ACCOUNT!
```

### How Heimdall Detects It

1. **Scans current state** - No privilege escalation paths
2. **Parses Terraform plan** - Detects IAM changes
3. **Simulates proposed state** - Detects new privilege escalation
4. **Calculates risk delta** - +1 CRITICAL path
5. **Blocks PR** - Prevents deployment

### Remediation

Heimdall suggests:

```hcl
# Option 1: Restrict PassRole to specific roles
resource "aws_iam_user_policy" "dev_safe" {
  policy = jsonencode({
    Statement = [{
      Action = ["iam:PassRole"]
      Resource = "arn:aws:iam::*:role/SafeLambdaRole"  # ✅ Specific role
      Condition = {
        StringEquals = {
          "iam:PassedToService" = "lambda.amazonaws.com"
        }
      }
    }]
  })
}

# Option 2: Remove dangerous permissions
# Don't give developers iam:PassRole + lambda:CreateFunction together
```

## 📊 Expected Output

### Safe Configuration

```
✅ SAFE TO MERGE - No new attack paths

📊 Summary:
  Current:  136 CRITICAL, 67 HIGH
  Proposed: 136 CRITICAL, 67 HIGH
  Delta:    No change

🎯 Recommendation: APPROVED
```

### Dangerous Configuration

```
❌ MERGE BLOCKED - Critical privilege escalation detected

📊 Summary:
  Current:  136 CRITICAL, 67 HIGH
  Proposed: 137 CRITICAL, 67 HIGH
  Delta:    +1 CRITICAL

⚠️  NEW ATTACK PATHS (1):
[CRITICAL] alice-developer - passrole_lambda
  Impact: Full AWS account compromise via Lambda
  Fix: Restrict iam:PassRole to specific roles

🎯 Recommendation: BLOCK
```

## 🎓 Learning Resources

### Related Privilege Escalation Techniques

1. **passrole_lambda** - Create Lambda with privileged role
2. **passrole_ec2** - Launch EC2 with privileged role
3. **attach_user_policy** - Attach admin policy to self
4. **put_user_policy** - Create inline admin policy
5. **create_access_key** - Create keys for other users

### AWS IAM Security Best Practices

- ✅ Use principle of least privilege
- ✅ Enable MFA for sensitive operations
- ✅ Use permission boundaries
- ✅ Restrict iam:PassRole with conditions
- ✅ Monitor with CloudTrail
- ✅ **Use Heimdall PR Simulator!** 🛡️

## 🤝 Contributing

Found a new attack pattern? Submit a PR!

```bash
# Add new pattern to:
heimdall/iam/privesc_patterns.py

# Add test case:
tests/iam/test_new_pattern.py
```

## 📞 Questions?

- 📖 [Full Documentation](../../PR_SIMULATOR_DEMO.md)
- 🐛 [Report Issues](https://github.com/DenizParlak/heimdall/issues)
- 💬 [Discussions](https://github.com/DenizParlak/heimdall/discussions)

---

**⚡ Protect your AWS infrastructure today!**
