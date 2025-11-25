"""
Heimdall Interactive Terminal UI (TUI)

Beautiful, interactive terminal interface for Heimdall IAM security analysis.
"""

import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Header,
    Footer,
    Static,
    Button,
    Label,
    Tree,
    DataTable,
    TabbedContent,
    TabPane,
    Input,
    ProgressBar,
)
from textual.binding import Binding
from textual.reactive import reactive
from textual import events
from rich.console import RenderableType
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree as RichTree
from rich.table import Table as RichTable


class StatsPanel(Static):
    """Display IAM statistics"""

    def __init__(self, stats: Optional[Dict[str, Any]] = None) -> None:
        super().__init__()
        self.stats = stats or {}

    def on_mount(self) -> None:
        """Called when widget is mounted"""
        self.update_stats(self.stats)

    def update_stats(self, stats: Dict[str, Any]) -> None:
        """Update statistics display"""
        self.stats = stats

        # Create stats table
        table = RichTable(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="bold white", justify="right")

        # Add stats
        table.add_row("👥 IAM Roles", str(stats.get("role_count", 0)))
        table.add_row("👤 IAM Users", str(stats.get("user_count", 0)))
        table.add_row("🔗 Relationships", str(stats.get("edge_count", 0)))
        table.add_row("⚙️  Service Principals", str(stats.get("service_count", 0)))
        table.add_row("🌐 Federated", str(stats.get("federated_count", 0)))

        # Privilege escalation stats
        if "privesc_summary" in stats:
            summary = stats["privesc_summary"]
            table.add_row("", "")
            table.add_row("🔴 CRITICAL", str(summary.get("critical_count", 0)))
            table.add_row("🟠 HIGH", str(summary.get("high_count", 0)))
            table.add_row("🟡 MEDIUM", str(summary.get("medium_count", 0)))
            table.add_row("🟢 LOW", str(summary.get("low_count", 0)))

        self.update(Panel(table, title="📊 Statistics", border_style="cyan"))


class FindingsDataTable(DataTable):
    """Interactive findings table with keyboard navigation"""
    
    def __init__(self) -> None:
        super().__init__(cursor_type="row")
        self.findings: List[Dict[str, Any]] = []
    
    def on_mount(self) -> None:
        """Setup table columns"""
        self.add_column("Sev", width=10)
        self.add_column("Principal", width=25)
        self.add_column("Method", width=22)
        self.add_column("Target", width=20)
    
    def update_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Update findings in the table"""
        self.findings = findings
        self.clear()
        
        for finding in findings:
            severity = finding.get("severity", "UNKNOWN")
            severity_icon = {
                "CRITICAL": "🔴",
                "HIGH": "🟠", 
                "MEDIUM": "🟡",
                "LOW": "🟢",
            }.get(severity, "⚪")
            
            principal_name = finding.get("principal_name", "Unknown")
            method = finding.get("privesc_method", "Unknown")
            # Get target or generate meaningful description based on method
            target = finding.get("target_role_name") or finding.get("target_resource") or finding.get("target")
            if not target or target == "*":
                target = self._get_target_description(method)
            
            self.add_row(
                f"{severity_icon} {severity}",
                principal_name[:23] + ".." if len(principal_name) > 25 else principal_name,
                method[:20] + ".." if len(method) > 22 else method,
                target[:18] + ".." if len(target) > 20 else target,
            )
    
    def _get_target_description(self, method: str) -> str:
        """Get meaningful target description based on privesc method"""
        method_lower = method.lower()
        
        # PassRole patterns - should have actual target, fallback
        if 'passrole' in method_lower:
            if 'lambda' in method_lower:
                return "→ Lambda Role"
            if 'ec2' in method_lower:
                return "→ EC2 Role"
            if 'ecs' in method_lower:
                return "→ ECS Role"
            if 'glue' in method_lower:
                return "→ Glue Role"
            if 'sagemaker' in method_lower:
                return "→ SageMaker Role"
            if 'codebuild' in method_lower:
                return "→ CodeBuild Role"
            if 'cloudformation' in method_lower:
                return "→ CFN Role"
            return "→ Service Role"
        
        # User/credential patterns
        if 'access_key' in method_lower:
            return "Any IAM User"
        if 'login_profile' in method_lower:
            return "Any IAM User"
        if 'add_user_to_group' in method_lower:
            return "Admin Group"
        
        # Policy patterns
        if 'attach' in method_lower and 'policy' in method_lower:
            return "Admin Policy"
        if 'put' in method_lower and 'policy' in method_lower:
            return "Inline Policy"
        if 'permission_boundary' in method_lower:
            return "Boundary"
        
        # Role patterns
        if 'assume_role' in method_lower or 'update_assume' in method_lower:
            return "Trust Policy"
        if 'sts' in method_lower:
            return "STS Token"
        
        # SSM/EC2 patterns
        if 'ssm' in method_lower:
            return "EC2 Instances"
        if 'ec2' in method_lower:
            return "EC2 Instance"
        
        # Data patterns
        if 'secrets' in method_lower:
            return "Secrets"
        if 's3' in method_lower:
            return "S3 Buckets"
        if 'dynamodb' in method_lower:
            return "DynamoDB"
        if 'rds' in method_lower:
            return "RDS"
        
        # Lambda patterns
        if 'lambda' in method_lower:
            return "Lambda Func"
        
        # Default
        return "All Resources"
    
    def get_selected_finding(self) -> Optional[Dict[str, Any]]:
        """Get currently selected finding"""
        if (self.cursor_row is not None 
            and self.cursor_row >= 0 
            and self.cursor_row < len(self.findings)):
            return self.findings[self.cursor_row]
        return None


class FindingDetailPanel(Static):
    """Shows detailed information about selected finding"""
    
    def __init__(self) -> None:
        super().__init__()
        self.current_finding: Optional[Dict[str, Any]] = None
    
    def on_mount(self) -> None:
        self.show_empty()
    
    def show_empty(self) -> None:
        """Show empty state"""
        self.update(Panel(
            Text("↑↓ Select a finding to see details", style="dim italic"),
            title="📋 Finding Details",
            border_style="yellow"
        ))
    
    def show_finding(self, finding: Dict[str, Any]) -> None:
        """Show finding details"""
        self.current_finding = finding
        
        severity = finding.get("severity", "UNKNOWN")
        severity_colors = {
            "CRITICAL": "red bold",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "LOW": "green",
        }
        
        content = Text()
        
        # Severity
        severity_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        content.append("Severity: ", style="bold")
        content.append(f"{severity_icons.get(severity, '⚪')} {severity}\n", style=severity_colors.get(severity, "white"))
        
        # Principal Type
        principal_type = finding.get('principal_type', finding.get('type', ''))
        if principal_type:
            type_icon = "👤" if principal_type == "user" else "🎭"
            content.append("Type: ", style="bold")
            content.append(f"{type_icon} {principal_type.upper()}\n", style="dim")
        
        # Principal Name & ARN
        principal_name = finding.get('principal_name', finding.get('name', 'N/A'))
        principal_arn = finding.get('principal_arn', finding.get('principal', finding.get('arn', '')))
        content.append("\nPrincipal: ", style="bold")
        content.append(f"{principal_name}\n", style="cyan bold")
        if principal_arn:
            content.append(f"  {principal_arn}\n", style="dim")
        
        # Method
        method = finding.get('privesc_method', finding.get('method', 'N/A'))
        content.append("\n⚔️  Attack Method: ", style="bold")
        content.append(f"{method}\n", style="yellow bold")
        
        # Target Resource
        target = finding.get('target_resource', finding.get('target_role_name', finding.get('target', '')))
        if target:
            content.append("\n🎯 Target: ", style="bold")
            content.append(f"{target}\n", style="magenta")
        
        # Required Permissions/Actions
        actions = finding.get('required_permissions', finding.get('required_actions', []))
        if actions:
            content.append("\n🔑 Required Permissions:\n", style="bold")
            for action in actions[:6]:
                content.append(f"  • {action}\n", style="green")
            if len(actions) > 6:
                content.append(f"  ... and {len(actions) - 6} more\n", style="dim")
        
        # Risk Description / Explanation
        description = finding.get('risk_description', finding.get('explanation', finding.get('description', '')))
        if description:
            content.append("\n📝 Risk Description:\n", style="bold")
            # Truncate long descriptions
            if len(description) > 250:
                description = description[:250] + "..."
            content.append(f"  {description}\n", style="italic")
        
        # Remediation hint
        remediation = finding.get('remediation', finding.get('quick_win', ''))
        if remediation:
            content.append("\n💡 Remediation:\n", style="bold green")
            lines = str(remediation).split('\n')[:3]
            for line in lines:
                content.append(f"  {line}\n", style="green dim")
        
        self.update(Panel(
            content,
            title=f"📋 {principal_name} - {method}",
            border_style="yellow"
        ))


class GraphView(Static):
    """Display IAM trust graph"""

    def __init__(self, graph: Optional[Dict[str, Any]] = None) -> None:
        super().__init__()
        self.graph = graph or {}

    def on_mount(self) -> None:
        """Called when widget is mounted"""
        self.update_graph(self.graph)

    def update_graph(self, graph: Dict[str, Any]) -> None:
        """Update graph display"""
        self.graph = graph

        # Create ASCII graph tree
        tree = RichTree("🛡️ IAM Trust Graph")

        nodes = graph.get("nodes", [])
        links = graph.get("links", [])

        # Group by type
        users = [n for n in nodes if n.get("type") == "user"]
        roles = [n for n in nodes if n.get("type") == "role"]
        services = [n for n in nodes if n.get("type") == "service"]

        # Add users
        if users:
            users_branch = tree.add("👥 Users")
            for user in users[:5]:  # Show first 5
                users_branch.add(f"👤 {user.get('name', 'Unknown')}")
            if len(users) > 5:
                users_branch.add(f"... and {len(users) - 5} more")

        # Add roles
        if roles:
            roles_branch = tree.add("🎭 Roles")
            for role in roles[:5]:  # Show first 5
                roles_branch.add(f"🎭 {role.get('name', 'Unknown')}")
            if len(roles) > 5:
                roles_branch.add(f"... and {len(roles) - 5} more")

        # Add services
        if services:
            services_branch = tree.add("⚙️  Service Principals")
            for service in services[:5]:  # Show first 5
                services_branch.add(f"⚙️  {service.get('name', 'Unknown')}")
            if len(services) > 5:
                services_branch.add(f"... and {len(services) - 5} more")

        # Add relationship summary
        if links:
            rels = tree.add(f"🔗 Relationships ({len(links)})")
            rel_types = {}
            for link in links:
                rel_type = link.get("type", "unknown")
                rel_types[rel_type] = rel_types.get(rel_type, 0) + 1

            for rel_type, count in list(rel_types.items())[:5]:
                rels.add(f"  {rel_type}: {count}")

        self.update(Panel(tree, title="📊 Graph Overview", border_style="blue"))


class HeimdallTUI(App):
    """Heimdall Interactive Terminal UI"""

    CSS = """
    Screen {
        layout: grid;
        grid-size: 3 2;
        grid-columns: 1fr 2fr 2fr;
        grid-rows: 2fr 1fr;
    }

    Header {
        column-span: 3;
    }

    Footer {
        column-span: 3;
    }

    #stats {
        border: solid green;
        padding: 1;
    }

    #findings-container {
        border: solid red;
        padding: 0;
    }

    #findings-table {
        height: 100%;
    }

    #detail {
        border: solid yellow;
        padding: 1;
        overflow-y: auto;
    }

    #log-panel {
        column-span: 3;
        border: solid cyan;
        padding: 0 1;
        height: 100%;
        overflow-y: auto;
    }

    #log-content {
        height: auto;
    }

    .log-entry {
        color: #888888;
    }

    .log-progress {
        color: cyan;
        text-style: bold;
    }

    DataTable {
        height: 100%;
    }

    DataTable > .datatable--cursor {
        background: $accent;
        color: $text;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("s", "scan", "Scan"),
        Binding("r", "refresh", "Refresh"),
        Binding("f", "filter", "Filter"),
        Binding("a", "filter_all", "All", show=False),
        Binding("1", "filter_critical", "Critical", show=False),
        Binding("2", "filter_high", "High", show=False),
        Binding("3", "filter_medium", "Medium", show=False),
        Binding("4", "filter_low", "Low", show=False),
        Binding("?", "help", "Help"),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
    ]

    TITLE = "Heimdall IAM Security Scanner"
    SUB_TITLE = "↑↓ Navigate | Enter Select | q Quit"

    graph_data: reactive[Optional[Dict[str, Any]]] = reactive(None)
    findings_data: reactive[Optional[List[Dict[str, Any]]]] = reactive(None)
    all_findings: List[Dict[str, Any]] = []  # Unfiltered findings
    current_filter: Optional[str] = None  # Current severity filter
    status_message: reactive[str] = reactive("Ready")

    def __init__(self, graph_file: Optional[str] = None):
        super().__init__()
        self.graph_file = graph_file
        self.stats_panel = StatsPanel()
        self.findings_table = FindingsDataTable()
        self.detail_panel = FindingDetailPanel()
        self.log_panel = Static("📋 Activity Log\n─────────────────────────────────────────────────────────────\n[s] Scan AWS  |  [f] Filter  |  [?] Help  |  [q] Quit", id="log-content")
        self.scan_logs: List[str] = []
        self.scan_progress = 0

    def compose(self) -> ComposeResult:
        """Create child widgets"""
        yield Header()

        # Top row: Stats, Findings, Details
        yield Container(self.stats_panel, id="stats")
        yield Container(self.findings_table, id="findings-container")
        yield Container(self.detail_panel, id="detail")
        
        # Bottom row: Activity Log (spans all columns)
        yield VerticalScroll(self.log_panel, id="log-panel")

        yield Footer()
    
    @property
    def status_bar(self):
        """Return log panel as status bar for compatibility"""
        return self.log_panel

    def on_mount(self) -> None:
        """Called when app is mounted"""
        if self.graph_file:
            self.load_graph_file(self.graph_file)
        else:
            self.status_message = "📋 No data loaded. Press [s] to scan AWS or use --graph file.json"

    def watch_status_message(self, new_value: str) -> None:
        """Update status bar when status_message changes"""
        # Update the log panel header with current status
        log_header = f"📋 Activity Log | Status: {new_value}\n"
        log_header += "─────────────────────────────────────────────────────────────\n"
        if self.scan_logs:
            log_header += "\n".join(self.scan_logs[-12:])
        else:
            log_header += "[s] Scan AWS  |  [f] Filter  |  [?] Help  |  [q] Quit"
        self.log_panel.update(log_header)

    def load_graph_file(self, filepath: str) -> None:
        """Load graph data from JSON file"""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            # Support both 'graph' and 'trust_graph' keys
            self.graph_data = data.get("trust_graph", data.get("graph", {}))
            self.all_findings = data.get("findings", [])
            self.findings_data = self.all_findings
            self.current_filter = None

            # Get stats from graph data
            stats = self.graph_data.get("stats", {})

            # Add privesc summary
            if self.all_findings:
                summary = {}
                for finding in self.all_findings:
                    severity = finding.get("severity", "UNKNOWN")
                    summary[f"{severity.lower()}_count"] = (
                        summary.get(f"{severity.lower()}_count", 0) + 1
                    )
                stats["privesc_summary"] = summary

            self.stats_panel.update_stats(stats)
            self.findings_table.update_findings(self.findings_data)
            
            # Select first finding if available
            if self.findings_data:
                self.detail_panel.show_finding(self.findings_data[0])

            self.status_message = f"✅ {len(self.all_findings)} findings | ↑↓ navigate | f filter"

        except FileNotFoundError:
            self.status_message = f"❌ File not found: {filepath}"
        except json.JSONDecodeError:
            self.status_message = f"❌ Invalid JSON in: {filepath}"
        except Exception as e:
            self.status_message = f"❌ Error: {str(e)}"

    def action_quit(self) -> None:
        """Quit the application"""
        self.exit()

    def action_refresh(self) -> None:
        """Refresh data"""
        if self.graph_file:
            self.load_graph_file(self.graph_file)
            self.status_message = "🔄 Refreshed data"
        else:
            self.status_message = "No file to refresh"

    def action_scan(self) -> None:
        """Trigger new AWS IAM scan"""
        self.status_message = "🔄 Starting AWS IAM scan... (this may take 30-60 seconds)"
        # Use thread=True for blocking boto3 calls
        self.run_worker(self._perform_scan_thread, thread=True, name="scan_worker", exclusive=True)
    
    def _perform_scan_thread(self) -> dict:
        """Perform AWS IAM scan in a thread (blocking IO safe)"""
        import tempfile
        import os
        
        result = {"success": False, "error": None, "output_file": None, "findings_count": 0}
        
        try:
            # Create temp file for scan output
            temp_dir = tempfile.gettempdir()
            scan_output = os.path.join(temp_dir, "heimdall-tui-scan.json")
            
            # Import scanner components
            from heimdall.iam.scanner import IAMScanner
            from heimdall.graph.builder import GraphBuilder
            from heimdall.graph.permission_analyzer import PermissionAnalyzer
            
            # Clear previous logs and start fresh
            self.call_from_thread(self._clear_logs)
            self.call_from_thread(self._add_log, "🚀 Starting AWS IAM scan...", 0)
            self.call_from_thread(self._update_status, "🔍 Connecting to AWS...")
            
            # Run scanner
            self.call_from_thread(self._add_log, "📡 Connecting to AWS IAM API...", 5)
            scanner = IAMScanner()
            self.call_from_thread(self._add_log, "✅ Connected to AWS", 10)
            
            self.call_from_thread(self._add_log, "🔍 Scanning IAM roles...", 15)
            self.call_from_thread(self._update_status, "🔍 Scanning IAM roles...")
            roles = scanner.scan_roles()
            self.call_from_thread(self._add_log, f"✅ Found {len(roles)} IAM roles", 35)
            
            self.call_from_thread(self._add_log, "🔍 Scanning IAM users...", 40)
            self.call_from_thread(self._update_status, f"🔍 Found {len(roles)} roles. Scanning users...")
            users = scanner.scan_users()
            self.call_from_thread(self._add_log, f"✅ Found {len(users)} IAM users", 55)
            
            self.call_from_thread(self._add_log, "📊 Building trust graph...", 60)
            self.call_from_thread(self._update_status, f"📊 {len(roles)} roles, {len(users)} users. Building graph...")
            
            # Build trust graph
            iam_data = {'roles': roles, 'users': users}
            builder = GraphBuilder()
            trust_graph = builder.build_from_principals(roles, users)
            edges = len(trust_graph.get('links', []))
            self.call_from_thread(self._add_log, f"✅ Graph built: {edges} trust relationships", 70)
            
            self.call_from_thread(self._add_log, "🔎 Analyzing for privilege escalation...", 75)
            self.call_from_thread(self._update_status, "🔎 Analyzing for privilege escalation...")
            
            # Analyze for privesc
            analyzer = PermissionAnalyzer(roles, users, iam_client=scanner.iam)
            findings = analyzer.detect_direct_privesc()
            self.call_from_thread(self._add_log, f"✅ Found {len(findings)} privilege escalation paths", 90)
            
            # Convert findings to serializable format (preserve all fields)
            findings_list = []
            for f in findings:
                findings_list.append({
                    'principal_arn': f.get('principal', f.get('principal_arn', '')),
                    'principal_name': f.get('principal_name', ''),
                    'principal_type': f.get('principal_type', ''),
                    'privesc_method': f.get('privesc_method', ''),
                    'severity': f.get('severity', 'MEDIUM'),
                    'required_actions': f.get('required_actions', []),
                    'target_role': f.get('target_role', ''),
                    'target_role_name': f.get('target_role_name', '*'),
                    'description': f.get('description', ''),
                    'explanation': f.get('explanation', ''),
                    'remediation': f.get('remediation', ''),
                })
            
            # Graph stats
            graph_stats = {
                'role_count': len(roles),
                'user_count': len(users),
                'edge_count': edges,
            }
            
            self.call_from_thread(self._add_log, "💾 Saving results...", 95)
            
            # Prepare output
            output_data = {
                "scan_info": {
                    "timestamp": datetime.now().isoformat(),
                    "source": "tui-scan",
                },
                "trust_graph": {
                    "nodes": trust_graph.get('nodes', []),
                    "links": trust_graph.get('links', []),
                    "stats": graph_stats,
                },
                "findings": findings_list,
            }
            
            # Save to temp file
            with open(scan_output, "w") as f:
                json.dump(output_data, f, indent=2, default=str)
            
            self.call_from_thread(self._add_log, f"✅ SCAN COMPLETE! Results: {scan_output}", 100)
            
            result["success"] = True
            result["output_file"] = scan_output
            result["findings_count"] = len(findings_list)
            
        except ImportError as e:
            self.call_from_thread(self._add_log, f"❌ ERROR: Missing module - {e}")
            result["error"] = f"Missing module: {e}"
        except Exception as e:
            self.call_from_thread(self._add_log, f"❌ ERROR: {str(e)[:60]}")
            result["error"] = f"Scan failed: {str(e)[:80]}"
        
        return result
    
    def _update_status(self, message: str) -> None:
        """Update status message (called from thread)"""
        self.status_message = message
    
    def _clear_logs(self) -> None:
        """Clear activity log"""
        self.scan_logs = []
        self.scan_progress = 0
        self.log_panel.update("📋 Activity Log\n─────────────────────────────────────────────────────────────\n")
    
    def _add_log(self, message: str, progress: int = None) -> None:
        """Add log entry to activity log (called from thread)"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if progress is not None:
            self.scan_progress = progress
            progress_bar = self._make_progress_bar(progress)
            log_entry = f"[{timestamp}] {progress_bar} {message}"
        else:
            log_entry = f"[{timestamp}] {message}"
        
        self.scan_logs.append(log_entry)
        
        # Update log panel
        log_text = "📋 Activity Log\n─────────────────────────────────────────────────────────────\n"
        log_text += "\n".join(self.scan_logs[-15:])  # Show last 15 entries
        self.log_panel.update(log_text)
    
    def _make_progress_bar(self, percent: int) -> str:
        """Create ASCII progress bar"""
        filled = int(percent / 5)  # 20 chars total
        empty = 20 - filled
        return f"[{'█' * filled}{'░' * empty}] {percent:3d}%"
    
    def on_worker_state_changed(self, event) -> None:
        """Handle worker completion"""
        if event.worker.name == "scan_worker" and event.worker.is_finished:
            result = event.worker.result
            if result and result.get("success"):
                self.graph_file = result["output_file"]
                self.load_graph_file(result["output_file"])
                self.status_message = f"✅ Scan complete! {result['findings_count']} findings"
            elif result and result.get("error"):
                self.status_message = f"❌ {result['error']}"
            else:
                self.status_message = "❌ Scan failed unexpectedly"

    def action_filter(self) -> None:
        """Cycle through severity filters: All → CRITICAL → HIGH → MEDIUM → LOW → All"""
        filter_cycle = [None, "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        
        # Find current position and move to next
        try:
            current_idx = filter_cycle.index(self.current_filter)
            next_idx = (current_idx + 1) % len(filter_cycle)
        except ValueError:
            next_idx = 0
        
        self.current_filter = filter_cycle[next_idx]
        self.apply_filter()
    
    def apply_filter(self) -> None:
        """Apply current severity filter to findings"""
        if self.current_filter is None:
            # Show all findings
            self.findings_data = self.all_findings
            filter_text = "ALL"
        else:
            # Filter by severity
            self.findings_data = [
                f for f in self.all_findings 
                if f.get("severity") == self.current_filter
            ]
            filter_text = self.current_filter
        
        # Update table
        self.findings_table.update_findings(self.findings_data)
        
        # Update detail panel
        if self.findings_data:
            self.detail_panel.show_finding(self.findings_data[0])
        else:
            self.detail_panel.show_empty()
        
        # Status message
        severity_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon = severity_icons.get(self.current_filter, "📋")
        self.status_message = f"{icon} Filter: {filter_text} ({len(self.findings_data)}/{len(self.all_findings)}) | f to cycle"

    def action_filter_all(self) -> None:
        """Show all findings"""
        self.current_filter = None
        self.apply_filter()
    
    def action_filter_critical(self) -> None:
        """Filter CRITICAL only"""
        self.current_filter = "CRITICAL"
        self.apply_filter()
    
    def action_filter_high(self) -> None:
        """Filter HIGH only"""
        self.current_filter = "HIGH"
        self.apply_filter()
    
    def action_filter_medium(self) -> None:
        """Filter MEDIUM only"""
        self.current_filter = "MEDIUM"
        self.apply_filter()
    
    def action_filter_low(self) -> None:
        """Filter LOW only"""
        self.current_filter = "LOW"
        self.apply_filter()

    def action_help(self) -> None:
        """Show help"""
        self.status_message = "s Scan | ↑↓ Navigate | f Filter | 1-4 Severity | r Refresh | q Quit"

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Handle row selection in findings table"""
        finding = self.findings_table.get_selected_finding()
        if finding:
            self.detail_panel.show_finding(finding)
            principal = finding.get('principal_name', 'Unknown')
            method = finding.get('privesc_method', 'Unknown')
            self.status_message = f"📍 {principal} → {method}"

    def action_cursor_down(self) -> None:
        """Move cursor down in findings table"""
        self.findings_table.action_cursor_down()

    def action_cursor_up(self) -> None:
        """Move cursor up in findings table"""
        self.findings_table.action_cursor_up()


def run_tui(graph_file: Optional[str] = None) -> None:
    """Run the Heimdall TUI application"""
    app = HeimdallTUI(graph_file=graph_file)
    app.run()
