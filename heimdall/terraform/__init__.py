# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                           ᛗᛁᛗᛁᚱ • MÍMIR
#                    The Wise One Who Sees All
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "Mímir guards the well of wisdom beneath Yggdrasil's roots.
#    Even Odin sacrificed his eye to drink from its waters."
#
#   This module analyzes Terraform plans before they become reality,
#   seeing the attack paths that will emerge from infrastructure changes.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"""
Heimdall Terraform Module - IaC Attack Path Analysis

Analyzes Terraform plans to detect privilege escalation paths BEFORE deployment.

Unlike static linters (Checkov, tfsec), this module:
- Combines Terraform changes with current AWS state
- Detects multi-hop attack chains across resources
- Shows before/after attack path comparison
- Traces new risks back to specific Terraform resources

Usage:
    from heimdall.terraform import TerraformAnalyzer
    
    analyzer = TerraformAnalyzer(session)
    report = analyzer.analyze_plan("terraform.plan.json")
    
    print(f"New critical paths: {len(report.new_critical_paths)}")
"""

from heimdall.terraform.parser import TerraformPlanParser
from heimdall.terraform.analyzer import TerraformAnalyzer
from heimdall.terraform.models import (
    ResourceChange,
    IAMImplication,
    TerraformImpactReport,
    ChangeAction,
)

__all__ = [
    "TerraformPlanParser",
    "TerraformAnalyzer",
    "ResourceChange",
    "IAMImplication",
    "TerraformImpactReport",
    "ChangeAction",
]
