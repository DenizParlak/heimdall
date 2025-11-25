# ᛗᛁᛞᚷᚨᚱᛞ • Midgard - Cross-Service Analysis Command
"""CLI command for cross-service privilege escalation analysis."""

import click
import json
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@click.command('cross-service')
@click.option('--output', '-o', type=click.Path(), help='Output file for results (JSON)')
@click.option('--format', '-f', type=click.Choice(['table', 'json']), default='table', help='Output format')
@click.option('--severity', '-s', type=click.Choice(['critical', 'high', 'medium', 'low', 'all']), 
              default='all', help='Filter by severity')
@click.option('--limit', '-l', default=20, help='Max findings to display')
@click.option('--public-only', is_flag=True, help='Show only public resources')
@click.option('--profile', '-p', help='AWS profile to use')
@click.option('--services', '-S', default='all', help='Services: s3,lambda,kms,sts,secrets,ec2,sns,sqs,dynamodb,rds or "all"')
@click.option('--compact', '-c', is_flag=True, help='Compact output (summary only)')
@click.option('--principal', '-P', help='Filter by principal name or ARN (substring match)')
def cross_service(output, format, severity, limit, public_only, profile, services, compact, principal):
    """
    Analyze cross-service privilege escalation paths.
    
    \b
    Scans 10 AWS services for privilege escalation:
    • S3, Lambda, KMS, STS, Secrets Manager
    • EC2, SNS, SQS, DynamoDB, RDS
    
    \b
    Examples:
      heimdall iam cross-service
      heimdall iam cross-service --services s3,lambda,ec2
      heimdall iam cross-service --principal admin
      heimdall iam cross-service -o results.json
    """
    import boto3
    from heimdall.cross_service import CrossServiceScanner
    from heimdall.cross_service.scanner import ScanConfig
    from heimdall.cross_service.models import ServiceType
    from heimdall.cross_service.analyzers import S3Analyzer
    
    console.print()
    console.print(Panel.fit(
        "[bold cyan]Cross-Service Privilege Escalation Analysis[/bold cyan]\n"
        "Analyzing 10 AWS services for attack paths",
        border_style="cyan"
    ))
    console.print()
    
    # Setup session
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        
        console.print(f"[green]✓[/green] Account: [cyan]{account_id}[/cyan]")
        console.print(f"[green]✓[/green] Region: [cyan]{session.region_name}[/cyan]")
        if profile:
            console.print(f"[green]✓[/green] Profile: [cyan]{profile}[/cyan]")
        console.print()
    except Exception as e:
        console.print(f"[red]✗ AWS Error: {e}[/red]")
        raise click.Abort()
    
    # Create scanner
    console.print("[dim]Scanning IAM principals...[/dim]")
    scanner = CrossServiceScanner(
        session=session,
        account_id=account_id,
        region=session.region_name,
    )
    
    # Parse services option
    service_map = {
        's3': ServiceType.S3, 
        'lambda': ServiceType.LAMBDA, 
        'kms': ServiceType.KMS,
        'sts': ServiceType.STS,
        'secrets': ServiceType.SECRETS_MANAGER,
        'secretsmanager': ServiceType.SECRETS_MANAGER,
        'ec2': ServiceType.EC2,
        'sns': ServiceType.SNS,
        'sqs': ServiceType.SQS,
        'dynamodb': ServiceType.DYNAMODB,
        'rds': ServiceType.RDS,
    }
    
    all_services = [
        ServiceType.S3, ServiceType.LAMBDA, ServiceType.KMS, ServiceType.STS,
        ServiceType.SECRETS_MANAGER, ServiceType.EC2, ServiceType.SNS,
        ServiceType.SQS, ServiceType.DYNAMODB, ServiceType.RDS
    ]
    
    if services.lower() == 'all':
        scan_services = all_services
    else:
        scan_services = []
        for svc in services.lower().split(','):
            svc = svc.strip()
            if svc in service_map:
                scan_services.append(service_map[svc])
        if not scan_services:
            scan_services = all_services
    
    console.print(f"[green]✓[/green] Services: [cyan]{', '.join(s.value for s in scan_services)}[/cyan]")
    if principal:
        console.print(f"[green]✓[/green] Principal filter: [cyan]{principal}[/cyan]")
    console.print()
    
    # Configure scan
    config = ScanConfig(
        services=scan_services,
        include_public_resources=True,
        include_cross_account=True,
    )
    
    # Run scan
    import time
    start_time = time.time()
    
    try:
        with console.status("[bold cyan]Analyzing cross-service permissions..."):
            result = scanner.scan(config=config)
    except Exception as e:
        console.print(f"[red]✗ Scan failed: {e}[/red]")
        raise click.Abort()
    
    # Filter chains by principal if specified
    if principal:
        principal_lower = principal.lower()
        result.chains = [c for c in result.chains 
                        if principal_lower in c.initial_principal.lower()]
        # Update findings count
        result.findings = [f for f in result.findings 
                         if principal_lower in f.chain.initial_principal.lower()]
    
    scan_duration = time.time() - start_time
    
    # Get analyzers for detailed info
    s3_analyzer = scanner._analyzers.get(ServiceType.S3)
    lambda_analyzer = scanner._analyzers.get(ServiceType.LAMBDA)
    
    console.print()
    console.print("━" * 60)
    
    # Get all analyzers
    kms_analyzer = scanner._analyzers.get(ServiceType.KMS)
    sts_analyzer = scanner._analyzers.get(ServiceType.STS)
    secrets_analyzer = scanner._analyzers.get(ServiceType.SECRETS_MANAGER)
    ec2_analyzer = scanner._analyzers.get(ServiceType.EC2)
    sns_analyzer = scanner._analyzers.get(ServiceType.SNS)
    sqs_analyzer = scanner._analyzers.get(ServiceType.SQS)
    dynamodb_analyzer = scanner._analyzers.get(ServiceType.DYNAMODB)
    rds_analyzer = scanner._analyzers.get(ServiceType.RDS)
    
    # Summary
    console.print(f"[bold cyan]📊 Scan Summary[/bold cyan]")
    console.print(f"  Duration: [cyan]{scan_duration:.1f}s[/cyan]")
    console.print(f"  Principals: [cyan]{len(scanner._principal_permissions)}[/cyan]")
    resource_items = []
    for svc, label in [('s3', 'S3'), ('lambda', 'Lambda'), ('kms', 'KMS'), 
                       ('sts', 'STS'), ('secretsmanager', 'Secrets'), ('ec2', 'EC2'),
                       ('sns', 'SNS'), ('sqs', 'SQS'), ('dynamodb', 'DynamoDB'), ('rds', 'RDS')]:
        if svc in result.resources_scanned:
            resource_items.append(f"{label}: {result.resources_scanned.get(svc, 0)}")
    if resource_items:
        console.print(f"  Resources: [cyan]{', '.join(resource_items)}[/cyan]")
    console.print(f"  Policies: [cyan]{result.policies_analyzed}[/cyan] | Chains: [cyan]{len(result.chains)}[/cyan]")
    console.print()
    
    # Severity breakdown
    console.print("[bold cyan]🎯 Findings by Severity[/bold cyan]")
    severity_icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵', 'INFO': '⚪'}
    for sev, count in result.severity_summary.items():
        if count > 0:
            console.print(f"  {severity_icons.get(sev, '⚪')} {sev}: [bold]{count}[/bold]")
    console.print()
    
    # Show errors if any
    if result.errors:
        console.print("[bold red]⚠️ Scan Errors[/bold red]")
        for err in result.errors[:3]:
            console.print(f"  • {err['service']}: {err['error']}")
        console.print()
    
    # Skip detailed output in compact mode
    if compact:
        if output:
            output_data = result.to_dict()
            with open(output, 'w') as f:
                json.dump(output_data, f, indent=2, default=str)
            console.print(f"[green]✓[/green] Results saved to [cyan]{output}[/cyan]")
        return
    
    # S3 Analysis
    if s3_analyzer:
        console.print("━" * 60)
        console.print("[bold cyan]🪣 S3 Bucket Analysis[/bold cyan]")
        console.print()
        
        public_buckets = s3_analyzer.get_public_buckets()
        sensitive_buckets = s3_analyzer.get_sensitive_buckets()
        cross_account = s3_analyzer.get_cross_account_buckets()
        high_risk = s3_analyzer.get_high_risk_buckets(50)
        
        if public_buckets:
            console.print(f"[bold red]🔴 Public Buckets ({len(public_buckets)})[/bold red]")
            for b in public_buckets[:5]:
                console.print(f"  • {b.name}")
                console.print(f"    [dim]Type: {b.public_access_type} | Risk: {b.risk_score}[/dim]")
            if len(public_buckets) > 5:
                console.print(f"  [dim]... and {len(public_buckets) - 5} more[/dim]")
            console.print()
        
        if sensitive_buckets and not public_only:
            console.print(f"[bold yellow]🟡 Sensitive Buckets ({len(sensitive_buckets)})[/bold yellow]")
            for b in sensitive_buckets[:5]:
                console.print(f"  • {b.name}")
            if len(sensitive_buckets) > 5:
                console.print(f"  [dim]... and {len(sensitive_buckets) - 5} more[/dim]")
            console.print()
        
        if cross_account and not public_only:
            console.print(f"[bold blue]🔗 Cross-Account Access ({len(cross_account)})[/bold blue]")
            for b in cross_account[:5]:
                principals = b.cross_account_principals[:2]
                console.print(f"  • {b.name}")
                for p in principals:
                    # Shorten ARN for display
                    short = p.split('/')[-1] if '/' in p else p.split(':')[-1]
                    console.print(f"    [dim]→ {short}[/dim]")
            if len(cross_account) > 5:
                console.print(f"  [dim]... and {len(cross_account) - 5} more[/dim]")
            console.print()
        
        if high_risk and not public_only:
            console.print(f"[bold red]⚠️  High Risk Buckets ({len(high_risk)})[/bold red]")
            for b in high_risk[:5]:
                console.print(f"  • {b.name} [dim](score: {b.risk_score})[/dim]")
                for r in b.risk_factors[:2]:
                    console.print(f"    [dim]{r}[/dim]")
            console.print()
    
    # Lambda Analysis
    if lambda_analyzer:
        console.print("━" * 60)
        console.print("[bold cyan]⚡ Lambda Function Analysis[/bold cyan]")
        console.print()
        
        admin_functions = lambda_analyzer.get_admin_functions()
        public_functions = lambda_analyzer.get_public_functions()
        secret_functions = lambda_analyzer.get_functions_with_secrets()
        high_risk_funcs = lambda_analyzer.get_high_risk_functions(50)
        
        if admin_functions:
            console.print(f"[bold red]🔴 Admin Execution Roles ({len(admin_functions)})[/bold red]")
            for f in admin_functions[:5]:
                console.print(f"  • {f.name}")
                console.print(f"    [dim]Role: {f.role_arn.split('/')[-1]}[/dim]")
                for r in f.risk_factors[:2]:
                    console.print(f"    [dim]{r}[/dim]")
            if len(admin_functions) > 5:
                console.print(f"  [dim]... and {len(admin_functions) - 5} more[/dim]")
            console.print()
        
        if public_functions:
            console.print(f"[bold red]🔴 Publicly Invokable ({len(public_functions)})[/bold red]")
            for f in public_functions[:5]:
                console.print(f"  • {f.name}")
                console.print(f"    [dim]Runtime: {f.runtime}[/dim]")
            if len(public_functions) > 5:
                console.print(f"  [dim]... and {len(public_functions) - 5} more[/dim]")
            console.print()
        
        if secret_functions and not public_only:
            console.print(f"[bold yellow]🔑 Sensitive Env Vars ({len(secret_functions)})[/bold yellow]")
            for f in secret_functions[:5]:
                console.print(f"  • {f.name}")
                console.print(f"    [dim]Vars: {', '.join(f.sensitive_env_vars[:3])}[/dim]")
            if len(secret_functions) > 5:
                console.print(f"  [dim]... and {len(secret_functions) - 5} more[/dim]")
            console.print()
        
        if high_risk_funcs and not public_only:
            console.print(f"[bold red]⚠️  High Risk Functions ({len(high_risk_funcs)})[/bold red]")
            for f in high_risk_funcs[:5]:
                console.print(f"  • {f.name} [dim](score: {f.risk_score})[/dim]")
            console.print()
    
    # KMS Analysis
    if kms_analyzer:
        console.print("━" * 60)
        console.print("[bold cyan]🔐 KMS Key Analysis[/bold cyan]")
        console.print()
        
        customer_keys = kms_analyzer.get_customer_keys()
        cross_account_keys = kms_analyzer.get_cross_account_keys()
        keys_with_grants = kms_analyzer.get_keys_with_grants()
        high_risk_keys = kms_analyzer.get_high_risk_keys(30)
        
        console.print(f"  Customer managed keys: [cyan]{len(customer_keys)}[/cyan]")
        console.print()
        
        if cross_account_keys:
            console.print(f"[bold yellow]🔗 Cross-Account Access ({len(cross_account_keys)})[/bold yellow]")
            for k in cross_account_keys[:5]:
                alias = k.alias or k.key_id[:8]
                console.print(f"  • {alias}")
                for p in k.cross_account_principals[:2]:
                    short = p.split(':')[4] if ':' in p else p
                    console.print(f"    [dim]→ Account: {short}[/dim]")
            if len(cross_account_keys) > 5:
                console.print(f"  [dim]... and {len(cross_account_keys) - 5} more[/dim]")
            console.print()
        
        if keys_with_grants and not public_only:
            console.print(f"[bold blue]📋 Keys with Grants ({len(keys_with_grants)})[/bold blue]")
            for k in keys_with_grants[:5]:
                alias = k.alias or k.key_id[:8]
                console.print(f"  • {alias} [dim]({len(k.grants)} grants)[/dim]")
            if len(keys_with_grants) > 5:
                console.print(f"  [dim]... and {len(keys_with_grants) - 5} more[/dim]")
            console.print()
        
        if high_risk_keys and not public_only:
            console.print(f"[bold red]⚠️  High Risk Keys ({len(high_risk_keys)})[/bold red]")
            for k in high_risk_keys[:5]:
                alias = k.alias or k.key_id[:8]
                console.print(f"  • {alias} [dim](score: {k.risk_score})[/dim]")
                for r in k.risk_factors[:2]:
                    console.print(f"    [dim]{r}[/dim]")
            console.print()
    
    # STS Analysis
    if sts_analyzer:
        console.print("━" * 60)
        console.print("[bold cyan]🔀 STS Role Assumption Analysis[/bold cyan]")
        console.print()
        
        cross_account_roles = sts_analyzer.get_cross_account_roles()
        permissive_roles = sts_analyzer.get_overly_permissive_roles()
        no_external_id = sts_analyzer.get_roles_without_external_id()
        high_risk_roles = sts_analyzer.get_high_risk_roles(30)
        
        if cross_account_roles:
            console.print(f"[bold yellow]🔗 Cross-Account Roles ({len(cross_account_roles)})[/bold yellow]")
            for r in cross_account_roles[:5]:
                console.print(f"  • {r.role_name}")
                for acc in r.trusted_accounts[:2]:
                    console.print(f"    [dim]→ Account: {acc}[/dim]")
            if len(cross_account_roles) > 5:
                console.print(f"  [dim]... and {len(cross_account_roles) - 5} more[/dim]")
            console.print()
        
        if no_external_id and not public_only:
            console.print(f"[bold red]⚠️  No External ID ({len(no_external_id)})[/bold red]")
            for r in no_external_id[:5]:
                console.print(f"  • {r.role_name}")
            if len(no_external_id) > 5:
                console.print(f"  [dim]... and {len(no_external_id) - 5} more[/dim]")
            console.print()
        
        if permissive_roles:
            console.print(f"[bold red]🔴 Overly Permissive (Principal: *) ({len(permissive_roles)})[/bold red]")
            for r in permissive_roles[:3]:
                console.print(f"  • {r.role_name}")
            console.print()
    
    # Secrets Manager Analysis
    if secrets_analyzer:
        console.print("━" * 60)
        console.print("[bold cyan]🔑 Secrets Manager Analysis[/bold cyan]")
        console.print()
        
        sensitive_secrets = secrets_analyzer.get_sensitive_secrets()
        unrotated = secrets_analyzer.get_unrotated_secrets()
        cross_account_secrets = secrets_analyzer.get_cross_account_secrets()
        high_risk_secrets = secrets_analyzer.get_high_risk_secrets(30)
        
        console.print(f"  Total secrets: [cyan]{len(secrets_analyzer._secrets)}[/cyan]")
        console.print()
        
        if sensitive_secrets and not public_only:
            console.print(f"[bold yellow]🔒 Sensitive Secrets ({len(sensitive_secrets)})[/bold yellow]")
            for s in sensitive_secrets[:5]:
                indicators = ', '.join(s.sensitivity_indicators[:2])
                console.print(f"  • {s.name}")
                console.print(f"    [dim]{indicators}[/dim]")
            if len(sensitive_secrets) > 5:
                console.print(f"  [dim]... and {len(sensitive_secrets) - 5} more[/dim]")
            console.print()
        
        if unrotated and not public_only:
            console.print(f"[bold yellow]🔄 No Rotation ({len(unrotated)})[/bold yellow]")
            for s in unrotated[:5]:
                console.print(f"  • {s.name}")
            if len(unrotated) > 5:
                console.print(f"  [dim]... and {len(unrotated) - 5} more[/dim]")
            console.print()
        
        if high_risk_secrets and not public_only:
            console.print(f"[bold red]⚠️  High Risk Secrets ({len(high_risk_secrets)})[/bold red]")
            for s in high_risk_secrets[:5]:
                console.print(f"  • {s.name} [dim](score: {s.risk_score})[/dim]")
            console.print()
    
    # EC2 Analysis
    if ec2_analyzer:
        console.print("━" * 60)
        console.print("[bold cyan]🖥️  EC2 Instance Analysis[/bold cyan]")
        console.print()
        
        instances_with_profiles = ec2_analyzer.get_instances_with_profiles()
        admin_instances = ec2_analyzer.get_admin_instances()
        ssm_instances = ec2_analyzer.get_ssm_instances()
        imdsv1_instances = ec2_analyzer.get_imdsv1_instances()
        public_instances = ec2_analyzer.get_public_instances()
        high_risk_inst = ec2_analyzer.get_high_risk_instances(50)
        
        console.print(f"  Total instances: [cyan]{len(ec2_analyzer._instances)}[/cyan]")
        console.print(f"  With instance profiles: [cyan]{len(instances_with_profiles)}[/cyan]")
        console.print(f"  SSM managed: [cyan]{len(ssm_instances)}[/cyan]")
        console.print()
        
        if admin_instances:
            console.print(f"[bold red]🔴 Admin Instance Profiles ({len(admin_instances)})[/bold red]")
            for i in admin_instances[:5]:
                name = i.name or i.instance_id
                console.print(f"  • {name}")
                console.print(f"    [dim]Role: {i.role_name}[/dim]")
            if len(admin_instances) > 5:
                console.print(f"  [dim]... and {len(admin_instances) - 5} more[/dim]")
            console.print()
        
        if imdsv1_instances and not public_only:
            console.print(f"[bold yellow]⚠️  IMDSv1 Enabled ({len(imdsv1_instances)})[/bold yellow]")
            for i in imdsv1_instances[:5]:
                name = i.name or i.instance_id
                console.print(f"  • {name}")
            if len(imdsv1_instances) > 5:
                console.print(f"  [dim]... and {len(imdsv1_instances) - 5} more[/dim]")
            console.print()
        
        if public_instances and not public_only:
            console.print(f"[bold yellow]🌐 Public IP ({len(public_instances)})[/bold yellow]")
            for i in public_instances[:5]:
                name = i.name or i.instance_id
                console.print(f"  • {name} [dim]({i.public_ip})[/dim]")
            if len(public_instances) > 5:
                console.print(f"  [dim]... and {len(public_instances) - 5} more[/dim]")
            console.print()
    
    # SNS Analysis
    if sns_analyzer and sns_analyzer._topics:
        public_topics = sns_analyzer.get_public_topics()
        cross_acc_topics = sns_analyzer.get_cross_account_topics()
        if public_topics or cross_acc_topics:
            console.print("━" * 60)
            console.print(f"[bold cyan]📢 SNS ({len(sns_analyzer._topics)} topics)[/bold cyan]")
            if public_topics:
                console.print(f"  [red]Public: {len(public_topics)}[/red]")
            if cross_acc_topics:
                console.print(f"  [yellow]Cross-account: {len(cross_acc_topics)}[/yellow]")
            console.print()
    
    # SQS Analysis
    if sqs_analyzer and sqs_analyzer._queues:
        public_queues = sqs_analyzer.get_public_queues()
        cross_acc_queues = sqs_analyzer.get_cross_account_queues()
        if public_queues or cross_acc_queues:
            console.print("━" * 60)
            console.print(f"[bold cyan]📬 SQS ({len(sqs_analyzer._queues)} queues)[/bold cyan]")
            if public_queues:
                console.print(f"  [red]Public: {len(public_queues)}[/red]")
            if cross_acc_queues:
                console.print(f"  [yellow]Cross-account: {len(cross_acc_queues)}[/yellow]")
            console.print()
    
    # DynamoDB Analysis
    if dynamodb_analyzer and dynamodb_analyzer._tables:
        sensitive_tables = dynamodb_analyzer.get_sensitive_tables()
        unencrypted = dynamodb_analyzer.get_unencrypted_tables()
        if sensitive_tables or unencrypted:
            console.print("━" * 60)
            console.print(f"[bold cyan]🗄️  DynamoDB ({len(dynamodb_analyzer._tables)} tables)[/bold cyan]")
            if sensitive_tables:
                console.print(f"  [yellow]Sensitive: {len(sensitive_tables)}[/yellow]")
                for t in sensitive_tables[:3]:
                    console.print(f"    • {t.table_name}")
            if unencrypted:
                console.print(f"  [red]Unencrypted: {len(unencrypted)}[/red]")
            console.print()
    
    # RDS Analysis
    if rds_analyzer and (rds_analyzer._instances or rds_analyzer._snapshots):
        public_rds = rds_analyzer.get_public_instances()
        public_snaps = rds_analyzer.get_public_snapshots()
        shared_snaps = rds_analyzer.get_shared_snapshots()
        if public_rds or public_snaps or shared_snaps:
            console.print("━" * 60)
            console.print(f"[bold cyan]🛢️  RDS ({len(rds_analyzer._instances)} instances, {len(rds_analyzer._snapshots)} snapshots)[/bold cyan]")
            if public_rds:
                console.print(f"  [red]Public instances: {len(public_rds)}[/red]")
                for r in public_rds[:3]:
                    console.print(f"    • {r.db_instance_id} ({r.engine})")
            if public_snaps:
                console.print(f"  [red]Public snapshots: {len(public_snaps)}[/red]")
            if shared_snaps:
                console.print(f"  [yellow]Shared snapshots: {len(shared_snaps)}[/yellow]")
            console.print()
    
    # Multi-Hop Chains (special section)
    multi_hop_chains = [c for c in result.chains if c.chain_id.startswith('mhop_')]
    if multi_hop_chains and not public_only:
        console.print("━" * 60)
        console.print(f"[bold magenta]🔗 Multi-Hop Attack Chains ({len(multi_hop_chains)})[/bold magenta]")
        console.print()
        
        # Group by pattern
        by_pattern = {}
        for c in multi_hop_chains:
            pattern_name = c.title.replace('🔗 ', '')
            if pattern_name not in by_pattern:
                by_pattern[pattern_name] = []
            by_pattern[pattern_name].append(c)
        
        for pattern_name, chains_list in list(by_pattern.items())[:5]:
            console.print(f"  [bold]{pattern_name}[/bold]")
            console.print(f"    Principals: {len(chains_list)} | Steps: {len(chains_list[0].vectors) if chains_list else 0}")
            if chains_list and chains_list[0].vectors:
                for i, v in enumerate(chains_list[0].vectors[:3], 1):
                    console.print(f"    {i}. {v.description[:50]}...")
            console.print()
    
    # Attack Chains
    if result.chains and not public_only:
        console.print("━" * 60)
        console.print("[bold cyan]⛓️  Top Attack Chains[/bold cyan]")
        console.print()
        
        # Filter by severity if specified
        chains = result.chains
        if severity != 'all':
            chains = [c for c in chains if c.severity.value.lower() == severity]
        
        # Sort by risk score
        chains = sorted(chains, key=lambda c: c.total_risk_score, reverse=True)
        
        if format == 'table':
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("#", width=3)
            table.add_column("Severity", width=10)
            table.add_column("Title", width=30)
            table.add_column("Path", width=15)
            table.add_column("Risk", width=6)
            table.add_column("Principal", width=20)
            
            for i, chain in enumerate(chains[:limit], 1):
                sev_style = {
                    'CRITICAL': 'red',
                    'HIGH': 'orange1',
                    'MEDIUM': 'yellow',
                    'LOW': 'blue',
                }.get(chain.severity.value, 'white')
                
                principal = chain.initial_principal.split('/')[-1][:18]
                
                table.add_row(
                    str(i),
                    f"[{sev_style}]{chain.severity.value}[/{sev_style}]",
                    chain.title[:28] + '..' if len(chain.title) > 30 else chain.title,
                    chain.path_summary,
                    str(chain.total_risk_score),
                    principal,
                )
            
            console.print(table)
        else:
            for i, chain in enumerate(chains[:limit], 1):
                icon = severity_icons.get(chain.severity.value, '⚪')
                console.print(f"{i}. {icon} [{chain.severity.value}] {chain.title}")
                console.print(f"   Path: {chain.path_summary} | Risk: {chain.total_risk_score}")
                console.print(f"   Principal: {chain.initial_principal.split('/')[-1]}")
                console.print()
        
        if len(chains) > limit:
            console.print(f"[dim]Showing {limit} of {len(chains)} chains. Use --limit to see more.[/dim]")
    
    # Save output
    if output:
        output_data = result.to_dict()
        with open(output, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
        console.print()
        console.print(f"[green]✓[/green] Results saved to [cyan]{output}[/cyan]")
    
    console.print()
    
    # Final summary
    if result.severity_summary.get('CRITICAL', 0) > 0:
        console.print(Panel.fit(
            f"[bold red]⚠️  {result.severity_summary['CRITICAL']} CRITICAL findings require immediate attention![/bold red]",
            border_style="red"
        ))
    elif result.severity_summary.get('HIGH', 0) > 0:
        console.print(Panel.fit(
            f"[bold yellow]⚠️  {result.severity_summary['HIGH']} HIGH severity findings found[/bold yellow]",
            border_style="yellow"
        ))
    else:
        console.print(Panel.fit(
            "[bold green]✓ No critical cross-service issues found[/bold green]",
            border_style="green"
        ))
