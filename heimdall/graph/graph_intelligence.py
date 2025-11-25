"""
Graph Intelligence - Advanced graph analytics for IAM security
v1.9.0: TIER 1 - Critical Path Analysis, Centrality, and SCP Impact Simulation

Provides AWS Security Team-level insights:
- Find fastest attack paths (low privilege → admin)
- Identify bottleneck principals (appear in 80%+ of paths)
- Simulate SCP impact before deployment
"""

import networkx as nx
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
import re


# Pattern definitions for privilege classification
LOW_PRIVILEGE_PATTERNS = [
    r'.*readonly.*',
    r'.*viewer.*',
    r'.*read-only.*',
    r'.*intern.*',
    r'.*contractor.*',
    r'.*temp.*',
    r'.*guest.*',
    r'.*dev-.*',
    r'.*test-.*'
]

HIGH_VALUE_PATTERNS = [
    r'.*admin.*',
    r'.*poweruser.*',
    r'.*root.*',
    r'.*prod-.*',
    r'.*production.*',
    r'.*security.*',
    r'.*billing.*',
    r'.*organization.*',
    r'.*master.*',
    r'.*sso-admin.*'
]


@dataclass
class CriticalPath:
    """Represents a critical attack path in the IAM graph"""
    path: List[str]  # List of ARNs
    hops: int
    source: str  # Starting principal ARN
    target: str  # Target high-value principal ARN
    risk_score: float  # 0-10 scale
    cross_account_hops: int
    path_type: str  # 'direct' or 'indirect'
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BottleneckPrincipal:
    """Represents a bottleneck principal in attack paths"""
    principal: str  # ARN
    name: str
    type: str  # 'user' or 'role'
    bottleneck_score: float  # 0-1 scale (% of paths passing through)
    betweenness_centrality: float  # NetworkX centrality score
    paths_count: int  # Number of critical paths through this principal
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SCPImpactAnalysis:
    """Results of SCP impact simulation"""
    before_critical: int
    before_high: int
    before_medium: int
    before_low: int
    after_critical: int
    after_high: int
    after_medium: int
    after_low: int
    blocked_findings: List[str]  # Finding IDs
    reduction_percentage: float
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GraphIntelligence:
    """
    Advanced graph analytics for IAM security
    
    Provides:
    1. Critical Path Analysis - Find shortest attack paths
    2. Centrality Analysis - Identify bottleneck principals
    3. SCP Impact Simulation - What-if analysis for SCPs
    """
    
    def __init__(self, trust_graph: Dict[str, Any]):
        """
        Initialize graph intelligence analyzer
        
        Args:
            trust_graph: Trust graph from GraphBuilder (node-link format)
        """
        # Convert from node-link format to NetworkX DiGraph
        self.graph = nx.node_link_graph(trust_graph, edges='links')
        self.trust_graph_data = trust_graph
        
    def find_critical_paths(
        self,
        max_depth: int = 5,
        top_k: int = 10
    ) -> List[CriticalPath]:
        """
        Find critical attack paths from low-privilege to high-value principals
        
        Uses Dijkstra's algorithm with risk-based scoring to identify the most
        dangerous paths an attacker could exploit.
        
        Args:
            max_depth: Maximum path length to consider
            top_k: Number of top paths to return
            
        Returns:
            List of CriticalPath objects, sorted by risk score (highest first)
        """
        # Identify low-privilege and high-value nodes
        low_privilege_nodes = self._identify_low_privilege_nodes()
        high_value_nodes = self._identify_high_value_nodes()
        
        if not low_privilege_nodes or not high_value_nodes:
            return []
        
        critical_paths = []
        
        # Find paths from each low-privilege node to each high-value node
        for source in low_privilege_nodes:
            for target in high_value_nodes:
                if source == target:
                    continue
                
                try:
                    # Find all shortest paths (up to max_depth)
                    paths = list(nx.all_shortest_paths(
                        self.graph, 
                        source, 
                        target,
                        weight=None  # Unweighted for now
                    ))
                    
                    for path in paths:
                        # Filter by max depth
                        if len(path) - 1 > max_depth:
                            continue
                        
                        # Calculate metrics
                        hops = len(path) - 1
                        cross_account_hops = self._count_cross_account_hops(path)
                        risk_score = self._calculate_path_risk_score(
                            path, 
                            hops, 
                            cross_account_hops
                        )
                        
                        critical_paths.append(CriticalPath(
                            path=path,
                            hops=hops,
                            source=source,
                            target=target,
                            risk_score=risk_score,
                            cross_account_hops=cross_account_hops,
                            path_type='indirect' if hops > 1 else 'direct'
                        ))
                
                except nx.NetworkXNoPath:
                    # No path exists between source and target
                    continue
        
        # Sort by risk score (descending) and return top K
        critical_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return critical_paths[:top_k]
    
    def calculate_centrality(
        self,
        critical_paths: Optional[List[CriticalPath]] = None
    ) -> List[BottleneckPrincipal]:
        """
        Calculate betweenness centrality to identify bottleneck principals
        
        Finds principals that appear in many attack paths - removing them
        would significantly reduce attack surface.
        
        Args:
            critical_paths: Optional pre-computed critical paths. If None,
                           will calculate full graph betweenness centrality.
        
        Returns:
            List of BottleneckPrincipal objects, sorted by bottleneck score
        """
        bottleneck_principals = []
        
        if critical_paths:
            # Calculate bottleneck score based on critical paths
            path_count_per_node = {}
            total_paths = len(critical_paths)
            
            for path_obj in critical_paths:
                # Count each intermediate node (exclude source and target)
                for node in path_obj.path[1:-1]:
                    path_count_per_node[node] = path_count_per_node.get(node, 0) + 1
            
            # Create BottleneckPrincipal objects
            for node, count in path_count_per_node.items():
                node_data = self.graph.nodes.get(node, {})
                bottleneck_score = count / total_paths if total_paths > 0 else 0
                
                bottleneck_principals.append(BottleneckPrincipal(
                    principal=node,
                    name=node_data.get('name', node),
                    type=node_data.get('type', 'unknown'),
                    bottleneck_score=bottleneck_score,
                    betweenness_centrality=0.0,  # Not calculated in this mode
                    paths_count=count
                ))
        else:
            # Calculate full graph betweenness centrality
            # For large graphs, use approximate algorithm
            if self.graph.number_of_nodes() > 100:
                # Sample-based approximation
                centrality = nx.betweenness_centrality(
                    self.graph, 
                    k=min(100, self.graph.number_of_nodes()),
                    normalized=True
                )
            else:
                # Exact calculation for smaller graphs
                centrality = nx.betweenness_centrality(self.graph, normalized=True)
            
            # Filter to only user and role nodes
            for node, score in centrality.items():
                node_data = self.graph.nodes.get(node, {})
                node_type = node_data.get('type', '')
                
                if node_type in ['user', 'role'] and score > 0:
                    bottleneck_principals.append(BottleneckPrincipal(
                        principal=node,
                        name=node_data.get('name', node),
                        type=node_type,
                        bottleneck_score=score,  # Use centrality as score
                        betweenness_centrality=score,
                        paths_count=0  # Not available in this mode
                    ))
        
        # Sort by bottleneck score (descending)
        bottleneck_principals.sort(key=lambda b: b.bottleneck_score, reverse=True)
        return bottleneck_principals
    
    def simulate_scp_impact(
        self,
        scp_policy: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> SCPImpactAnalysis:
        """
        Simulate impact of adding an SCP policy
        
        Analyzes how many findings would be blocked if the given SCP
        were applied. Uses simplified policy evaluation (checks if required
        actions are explicitly denied by SCP).
        
        Args:
            scp_policy: SCP policy document (IAM policy format)
            findings: List of findings with required_permissions
            
        Returns:
            SCPImpactAnalysis with before/after counts
        """
        # Count findings by severity before SCP
        before_counts = self._count_by_severity(findings)
        
        # Determine which findings would be blocked
        blocked_finding_ids = []
        
        for finding in findings:
            required_perms = finding.get('required_permissions', [])
            
            if self._would_be_blocked_by_scp(required_perms, scp_policy):
                blocked_finding_ids.append(finding.get('id', ''))
        
        # Filter out blocked findings
        remaining_findings = [
            f for f in findings 
            if f.get('id', '') not in blocked_finding_ids
        ]
        
        # Count findings by severity after SCP
        after_counts = self._count_by_severity(remaining_findings)
        
        # Calculate reduction percentage
        total_before = len(findings)
        total_after = len(remaining_findings)
        reduction = ((total_before - total_after) / total_before * 100) if total_before > 0 else 0
        
        return SCPImpactAnalysis(
            before_critical=before_counts['CRITICAL'],
            before_high=before_counts['HIGH'],
            before_medium=before_counts['MEDIUM'],
            before_low=before_counts['LOW'],
            after_critical=after_counts['CRITICAL'],
            after_high=after_counts['HIGH'],
            after_medium=after_counts['MEDIUM'],
            after_low=after_counts['LOW'],
            blocked_findings=blocked_finding_ids,
            reduction_percentage=round(reduction, 2)
        )
    
    # ========== Helper Methods ==========
    
    def _identify_low_privilege_nodes(self) -> List[str]:
        """Identify nodes matching low-privilege patterns"""
        low_priv_nodes = []
        
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            name = node_data.get('name', '').lower()
            
            # Only consider users and roles
            if node_data.get('type') not in ['user', 'role']:
                continue
            
            # Check if name matches low-privilege patterns
            for pattern in LOW_PRIVILEGE_PATTERNS:
                if re.match(pattern, name, re.IGNORECASE):
                    low_priv_nodes.append(node)
                    break
        
        return low_priv_nodes
    
    def _identify_high_value_nodes(self) -> List[str]:
        """Identify nodes matching high-value patterns"""
        high_value_nodes = []
        
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            name = node_data.get('name', '').lower()
            
            # Only consider roles (high-value users are rare)
            if node_data.get('type') != 'role':
                continue
            
            # Check if name matches high-value patterns
            for pattern in HIGH_VALUE_PATTERNS:
                if re.match(pattern, name, re.IGNORECASE):
                    high_value_nodes.append(node)
                    break
        
        return high_value_nodes
    
    def _count_cross_account_hops(self, path: List[str]) -> int:
        """Count number of cross-account edges in a path"""
        cross_account_count = 0
        
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            
            # For DiGraph, check if edge exists first
            if self.graph.has_edge(source, target):
                edge_data = self.graph[source][target]
                if edge_data.get('cross_account', False):
                    cross_account_count += 1
        
        return cross_account_count
    
    def _calculate_path_risk_score(
        self,
        path: List[str],
        hops: int,
        cross_account_hops: int
    ) -> float:
        """
        Calculate risk score for a path (0-10 scale)
        
        Formula:
        - Shorter paths = higher risk (easier to exploit)
        - Cross-account hops = higher risk (harder to detect)
        - Target type affects base score
        """
        # Base score starts high
        base_score = 10.0
        
        # Penalty for longer paths (each hop reduces score)
        hop_penalty = hops * 1.2
        
        # Bonus for cross-account (harder to detect)
        cross_account_bonus = cross_account_hops * 1.5
        
        # Calculate final score
        risk_score = base_score - hop_penalty + cross_account_bonus
        
        # Clamp to 0-10 range
        risk_score = max(0.0, min(10.0, risk_score))
        
        return round(risk_score, 2)
    
    def _would_be_blocked_by_scp(
        self,
        required_permissions: List[str],
        scp_policy: Dict[str, Any]
    ) -> bool:
        """
        Check if required permissions would be blocked by SCP
        
        Simplified evaluation: checks if ALL required permissions
        are explicitly denied in the SCP.
        
        Note: Real SCP evaluation is complex (conditions, resources, etc.).
        This is a conservative first approximation.
        """
        denied_actions = set()
        
        # Extract denied actions from SCP
        for statement in scp_policy.get('Statement', []):
            if statement.get('Effect') == 'Deny':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    # Handle wildcards (simplified)
                    if '*' in action:
                        # Convert IAM wildcard to regex
                        regex_pattern = action.replace('*', '.*')
                        denied_actions.add(regex_pattern)
                    else:
                        denied_actions.add(action)
        
        # Check if ALL required permissions are denied
        all_blocked = True
        for perm in required_permissions:
            perm_blocked = False
            
            for denied in denied_actions:
                if '*' in denied or '.*' in denied:
                    # Regex match
                    if re.match(denied, perm, re.IGNORECASE):
                        perm_blocked = True
                        break
                elif perm.lower() == denied.lower():
                    perm_blocked = True
                    break
            
            if not perm_blocked:
                all_blocked = False
                break
        
        return all_blocked
    
    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            if severity in counts:
                counts[severity] += 1
        
        return counts
