# ᚲᛊᚹ • CSV Exporter - Spreadsheet Bridge
"""
Export findings to CSV format for spreadsheet analysis.

For those who prefer to study Heimdall's observations in the
structured rows and columns of Midgard's spreadsheets.

Usage:
    CSVExporter.save(findings, 'findings.csv')
    csv_string = CSVExporter.export(findings)
"""

import csv
import io
from typing import List, Dict, Any, Optional


class CSVExporter:
    """Export findings to CSV format."""
    
    DEFAULT_COLUMNS = [
        'severity',
        'principal_name', 
        'principal_type',
        'privesc_method',
        'target_role_name',
        'principal_arn',
        'description',
        'remediation',
        'required_actions',
    ]
    
    @classmethod
    def export(cls, 
               findings: List[Dict[str, Any]], 
               columns: Optional[List[str]] = None,
               include_header: bool = True) -> str:
        """
        Export findings to CSV string.
        
        Args:
            findings: List of findings
            columns: Column names to include (default: all standard columns)
            include_header: Include header row
            
        Returns:
            CSV string
        """
        cols = columns or cls.DEFAULT_COLUMNS
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        if include_header:
            writer.writerow(cols)
        
        for finding in findings:
            row = []
            for col in cols:
                value = finding.get(col, '')
                
                # Handle list values
                if isinstance(value, list):
                    value = '; '.join(str(v) for v in value)
                elif isinstance(value, dict):
                    value = str(value)
                
                row.append(value)
            
            writer.writerow(row)
        
        return output.getvalue()
    
    @classmethod
    def save(cls, 
             findings: List[Dict[str, Any]], 
             output_path: str,
             **kwargs) -> None:
        """Save findings to CSV file."""
        csv_content = cls.export(findings, **kwargs)
        with open(output_path, 'w', newline='') as f:
            f.write(csv_content)
    
    @classmethod
    def export_summary(cls, findings: List[Dict[str, Any]]) -> str:
        """Export summary statistics to CSV."""
        # Count by severity
        severity_counts = {}
        method_counts = {}
        principal_counts = {}
        
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            method = finding.get('privesc_method', 'unknown')
            principal = finding.get('principal_name', 'unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            method_counts[method] = method_counts.get(method, 0) + 1
            principal_counts[principal] = principal_counts.get(principal, 0) + 1
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Severity summary
        writer.writerow(['Severity Summary'])
        writer.writerow(['Severity', 'Count'])
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            writer.writerow([sev, severity_counts.get(sev, 0)])
        writer.writerow([])
        
        # Top methods
        writer.writerow(['Top Privesc Methods'])
        writer.writerow(['Method', 'Count'])
        for method, count in sorted(method_counts.items(), key=lambda x: -x[1])[:10]:
            writer.writerow([method, count])
        writer.writerow([])
        
        # Top principals
        writer.writerow(['Top Affected Principals'])
        writer.writerow(['Principal', 'Finding Count'])
        for principal, count in sorted(principal_counts.items(), key=lambda x: -x[1])[:10]:
            writer.writerow([principal, count])
        
        return output.getvalue()
