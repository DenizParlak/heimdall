"""
Graph Analyzer - Trust graph path analysis and risk assessment.

This module provides path analysis capabilities for IAM trust graphs,
identifying privilege escalation opportunities based on AssumeRole relationships.

Key Features:
    - Path enumeration between principals using NetworkX
    - Risk scoring based on source/target privilege levels
    - Pattern matching for high-value targets and low-privilege sources
    - Support for cross-account and federated trust relationships

Note:
    This analyzer works on TRUST GRAPH relationships (AssumeRole).
    For PERMISSION-based privilege escalation (PassRole, etc.),
    see the PermissionAnalyzer in permission_analyzer.py.

Author: Heimdall Security Team
"""

from __future__ import annotations

import networkx as nx
from typing import List, Dict, Any, Optional, Tuple

# Type Aliases (Python 3.9+ compatible)
GraphData = Dict[str, Any]
PathResult = Dict[str, Any]


class PathAnalyzer:
    """
    Analyzes IAM trust graph for privilege escalation paths.
    
    This class builds a NetworkX graph from IAM trust relationships
    and provides methods to find paths between principals and assess risk.
    
    Attributes:
        graph: NetworkX DiGraph of trust relationships
        HIGH_VALUE_PATTERNS: Patterns indicating high-privilege targets
        LOW_PRIVILEGE_PATTERNS: Patterns indicating low-privilege sources
    """
    
    # High-value targets (roles that typically have elevated privileges)
    HIGH_VALUE_PATTERNS: Tuple[str, ...] = (
        'admin', 'administrator', 'administratoraccess', 'poweruser', 'root',
        'production', 'prod', 'full', 'owner', 'master', 'superuser',
        'awsreservedsso_administratoraccess',  # AWS SSO admin roles
    )
    
    # Low-privilege sources (principals that shouldn't have elevated access)
    LOW_PRIVILEGE_PATTERNS: Tuple[str, ...] = (
        'intern', 'contractor', 'guest', 'readonly', 'view',
        'developer', 'dev', 'test', 'sandbox',
    )
    
    def __init__(self, graph_data: Dict[str, Any]):
        """
        Initialize analyzer with graph data
        
        Args:
            graph_data: NetworkX node-link format graph
        """
        self.graph = nx.node_link_graph(graph_data, edges='links')
    
    def find_risky_paths(self, max_depth: int = 5) -> List[Dict[str, Any]]:
        """
        Find privilege escalation paths from low to high privilege principals
        
        Args:
            max_depth: Maximum path length to search
            
        Returns:
            List of risky paths with risk assessment
        """
        risky_paths = []
        
        # Identify low and high privilege nodes
        low_privilege_nodes = self._identify_low_privilege_nodes()
        high_privilege_nodes = self._identify_high_privilege_nodes()
        
        # Find paths from low to high
        for source in low_privilege_nodes:
            for target in high_privilege_nodes:
                try:
                    paths = list(nx.all_simple_paths(
                        self.graph,
                        source,
                        target,
                        cutoff=max_depth
                    ))
                    
                    for path in paths:
                        risk_assessment = self._assess_path_risk(path)
                        
                        risky_paths.append({
                            'path': path,
                            'source': source,
                            'target': target,
                            'hops': len(path) - 1,
                            **risk_assessment
                        })
                
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
        
        # Also check for publicly assumable roles
        if 'PUBLIC' in self.graph.nodes():
            for target in self.graph.successors('PUBLIC'):
                risky_paths.append({
                    'path': ['PUBLIC', target],
                    'source': 'PUBLIC',
                    'target': target,
                    'hops': 1,
                    'severity': 'CRITICAL',
                    'reason': 'Role can be assumed by anyone (public)',
                    'risk': 'CRITICAL'
                })
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        risky_paths.sort(key=lambda x: (
            severity_order.get(x['severity'], 4),
            x['hops']
        ))
        
        return risky_paths
    
    def find_paths(
        self,
        source: str,
        target: str,
        max_depth: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Find all paths between two specific principals
        
        Args:
            source: Source principal (ARN or short name)
            target: Target principal (ARN or short name)
            max_depth: Maximum path length
            
        Returns:
            List of paths with risk assessment
        """
        # Resolve short names to ARNs
        source_arn = self._resolve_principal(source)
        target_arn = self._resolve_principal(target)
        
        if not source_arn or not target_arn:
            return []
        
        try:
            paths = list(nx.all_simple_paths(
                self.graph,
                source_arn,
                target_arn,
                cutoff=max_depth
            ))
            
            results = []
            for path in paths:
                risk_assessment = self._assess_path_risk(path)
                results.append({
                    'path': path,
                    'hops': len(path) - 1,
                    **risk_assessment
                })
            
            return results
        
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
    
    def _identify_low_privilege_nodes(self) -> List[str]:
        """Identify nodes that appear to have low privileges"""
        low_priv = []
        
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            name = node_data.get('name', '').lower()
            
            # Check if name matches low-privilege patterns
            if any(pattern in name for pattern in self.LOW_PRIVILEGE_PATTERNS):
                low_priv.append(node)
            
            # Users are generally lower privilege than roles
            elif node_data.get('type') == 'user':
                low_priv.append(node)
        
        return low_priv
    
    def _identify_high_privilege_nodes(self) -> List[str]:
        """Identify nodes that appear to have high privileges"""
        high_priv = []
        
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            name = node_data.get('name', '').lower()
            
            # Check if name matches high-privilege patterns
            if any(pattern in name for pattern in self.HIGH_VALUE_PATTERNS):
                high_priv.append(node)
        
        return high_priv
    
    def _assess_path_risk(self, path: List[str]) -> Dict[str, Any]:
        """
        Assess the risk level of a privilege escalation path
        
        Args:
            path: List of principal ARNs forming a path
            
        Returns:
            Risk assessment with severity and reason
        """
        path_length = len(path) - 1
        source = path[0]
        target = path[-1]
        
        source_name = self.graph.nodes[source].get('name', '').lower()
        target_name = self.graph.nodes[target].get('name', '').lower()
        
        # Determine severity
        severity = 'LOW'
        reasons = []
        
        # Check path length (shorter = more critical)
        if path_length == 1:
            severity = 'HIGH'
            reasons.append('Direct assume-role access')
        elif path_length == 2:
            severity = 'MEDIUM'
            reasons.append('Two-hop privilege escalation')
        
        # Check source privilege level
        if any(pattern in source_name for pattern in self.LOW_PRIVILEGE_PATTERNS):
            if severity == 'HIGH':
                severity = 'CRITICAL'
            elif severity == 'MEDIUM':
                severity = 'HIGH'
            reasons.append(f'Low-privilege source ({source_name})')
        
        # Check target privilege level
        if any(pattern in target_name for pattern in self.HIGH_VALUE_PATTERNS):
            if severity == 'LOW':
                severity = 'MEDIUM'
            elif severity == 'MEDIUM':
                severity = 'HIGH'
            elif severity == 'HIGH':
                severity = 'CRITICAL'
            reasons.append(f'High-privilege target ({target_name})')
        
        # Check for risky edge conditions
        for i in range(len(path) - 1):
            edge_data = self.graph.get_edge_data(path[i], path[i + 1])
            if edge_data:
                edge_risk = edge_data.get('risk', 'LOW')
                if edge_risk == 'CRITICAL':
                    severity = 'CRITICAL'
                    reasons.append('Public or wildcard assume-role')
        
        return {
            'severity': severity,
            'reason': '; '.join(reasons) if reasons else 'Standard privilege escalation path',
            'risk': severity
        }
    
    def _resolve_principal(self, identifier: str) -> Optional[str]:
        """
        Resolve principal identifier to full ARN
        
        Args:
            identifier: Can be full ARN, partial name (user/name, role/name), or just name
            
        Returns:
            Full ARN or None if not found
        """
        # If it's already a full ARN
        if identifier.startswith('arn:aws:iam::'):
            return identifier if identifier in self.graph.nodes() else None
        
        # Search for matching nodes
        identifier_lower = identifier.lower()
        
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            name = node_data.get('name', '').lower()
            node_type = node_data.get('type', '')
            
            # Match by name
            if name == identifier_lower:
                return node
            
            # Match by type/name (e.g., "user/intern", "role/admin")
            if identifier_lower.startswith(f'{node_type}/'):
                expected_name = identifier_lower.split('/', 1)[1]
                if name == expected_name:
                    return node
        
        return None
