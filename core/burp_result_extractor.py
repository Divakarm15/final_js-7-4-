#!/usr/bin/env python3
"""
burp_result_extractor.py — JS Scout Pro Burp Result Extraction Engine
====================================================================
Advanced result extraction and reporting system for Burp-powered scans.

Features:
  1. Real-time result extraction from Burp API
  2. JSON-based structured reporting
  3. HTML report generation
  4. CSV export for analysis
  5. Vulnerability severity classification
  6. Evidence collection and PoC generation
  7. Executive summary generation
  8. Trend analysis and metrics

Output Formats:
  - JSON (machine-readable)
  - HTML (human-readable dashboard)
  - CSV (spreadsheet analysis)
  - TXT (command-line summary)
"""

import json
import csv
import time
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    raise ImportError("[!] pip install requests")


class BurpResultExtractor:
    """Extracts and processes results from Burp Suite scans"""
    
    def __init__(self, api_controller):
        self.api = api_controller
        self.results_cache = {}
        self.findings = []
        
    def extract_all_results(self, scan_id: str) -> Dict[str, Any]:
        """Extract complete results from a Burp scan"""
        results = {
            'scan_metadata': self._get_scan_metadata(scan_id),
            'vulnerabilities': self._extract_vulnerabilities(scan_id),
            'statistics': self._calculate_statistics(),
            'timeline': self._generate_timeline(),
            'evidence': self._collect_evidence(),
            'recommendations': self._generate_recommendations()
        }
        
        self.results_cache[scan_id] = results
        return results
    
    def _get_scan_metadata(self, scan_id: str) -> Dict[str, Any]:
        """Get scan metadata"""
        try:
            status = self.api.get_scan_status(scan_id)
            if status:
                return {
                    'scan_id': scan_id,
                    'status': status.get('status'),
                    'start_time': status.get('start_time'),
                    'end_time': status.get('end_time'),
                    'duration_seconds': status.get('duration'),
                    'total_requests': status.get('request_count', 0),
                    'tool': 'JS Scout Pro v10 - Burp Automation Engine'
                }
        except Exception as e:
            print(f"Error getting scan metadata: {e}")
        
        return {
            'scan_id': scan_id,
            'tool': 'JS Scout Pro v10 - Burp Automation Engine',
            'timestamp': datetime.now().isoformat()
        }
    
    def _extract_vulnerabilities(self, scan_id: str) -> List[Dict[str, Any]]:
        """Extract and normalize vulnerabilities from Burp"""
        try:
            issues = self.api.get_issues(scan_id)
            normalized_vulns = []
            
            for issue in issues:
                normalized_vuln = self._normalize_vulnerability(issue)
                normalized_vulns.append(normalized_vuln)
            
            # Sort by severity
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
            normalized_vulns.sort(key=lambda x: severity_order.get(x.get('severity', 'Low'), 5))
            
            self.findings = normalized_vulns
            return normalized_vulns
            
        except Exception as e:
            print(f"Error extracting vulnerabilities: {e}")
            return []
    
    def _normalize_vulnerability(self, issue: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Burp issue to standard format"""
        return {
            'id': hashlib.md5(f"{issue.get('url', '')}{issue.get('name', '')}{time.time()}".encode()).hexdigest(),
            'type': self._map_vulnerability_type(issue.get('name', 'Unknown')),
            'severity': self._normalize_severity(issue.get('severity', 'Information')),
            'confidence': issue.get('confidence', 'Certain'),
            'url': issue.get('url', ''),
            'method': issue.get('request', {}).get('method', 'GET'),
            'parameter': self._extract_affected_parameter(issue),
            'description': issue.get('description', ''),
            'detail': issue.get('detail', ''),
            'remediation': issue.get('remediation', ''),
            'evidence': self._extract_evidence(issue),
            'request': issue.get('request', {}),
            'response': issue.get('response', {}),
            'timestamp': datetime.now().isoformat(),
            'tool': 'Burp Suite Professional',
            'references': self._get_references(issue)
        }
    
    def _map_vulnerability_type(self, burp_name: str) -> str:
        """Map Burp vulnerability names to standard types"""
        mapping = {
            'Cross-site scripting (reflected)': 'XSS',
            'Cross-site scripting (stored)': 'XSS',
            'SQL injection': 'SQL_INJECTION',
            'OS command injection': 'COMMAND_INJECTION',
            'Path traversal': 'PATH_TRAVERSAL',
            'Server-side request forgery': 'SSRF',
            'XML external entity injection': 'XXE',
            'Directory listing': 'DIRECTORY_LISTING',
            'Missing CSRF token': 'CSRF',
            'Cookie security': 'COOKIE_SECURITY',
            'CORS misconfiguration': 'CORS_MISCONFIGURATION',
            'Host header injection': 'HOST_HEADER_INJECTION',
            'Information disclosure': 'INFORMATION_DISCLOSURE',
            'Missing security headers': 'MISSING_SECURITY_HEADERS',
            'Clickjacking': 'CLICKJACKING'
        }
        
        for burp_type, standard_type in mapping.items():
            if burp_type.lower() in burp_name.lower():
                return standard_type
        
        return 'OTHER'
    
    def _normalize_severity(self, burp_severity: str) -> str:
        """Normalize Burp severity to standard scale"""
        severity_mapping = {
            'High': 'High',
            'Medium': 'Medium', 
            'Low': 'Low',
            'Information': 'Info'
        }
        return severity_mapping.get(burp_severity, 'Info')
    
    def _extract_affected_parameter(self, issue: Dict[str, Any]) -> str:
        """Extract affected parameter from issue"""
        # Try to extract parameter from various fields
        for field in ['name', 'issue_background', 'issue_detail']:
            content = issue.get(field, '')
            if 'parameter' in content.lower():
                # Simple extraction - can be enhanced
                import re
                match = re.search(r'parameter[\'"]?\s*[:=]\s*[\'"]?(\w+)', content, re.IGNORECASE)
                if match:
                    return match.group(1)
        return ''
    
    def _extract_evidence(self, issue: Dict[str, Any]) -> Dict[str, Any]:
        """Extract evidence from issue"""
        evidence = {
            'request_snippet': '',
            'response_snippet': '',
            'proof_of_concept': '',
            'screenshots': []
        }
        
        # Extract request/response snippets
        request = issue.get('request', {})
        response = issue.get('response', {})
        
        if request:
            evidence['request_snippet'] = str(request.get('headers', ''))[:500]
        
        if response:
            evidence['response_snippet'] = str(response.get('headers', ''))[:500]
            # Look for evidence in response body
            body = response.get('body', '')
            if body:
                evidence['response_snippet'] += '\n' + body[:500]
        
        return evidence
    
    def _get_references(self, issue: Dict[str, Any]) -> List[str]:
        """Get references for vulnerability"""
        references = []
        
        # Add OWASP references based on vulnerability type
        vuln_type = self._map_vulnerability_type(issue.get('name', ''))
        
        owasp_refs = {
            'XSS': ['https://owasp.org/www-community/attacks/xss/'],
            'SQL_INJECTION': ['https://owasp.org/www-community/attacks/SQL_Injection'],
            'COMMAND_INJECTION': ['https://owasp.org/www-community/attacks/Command_Injection'],
            'SSRF': ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
            'CSRF': ['https://owasp.org/www-community/attacks/csrf'],
            'PATH_TRAVERSAL': ['https://owasp.org/www-community/attacks/Path_Traversal']
        }
        
        return owasp_refs.get(vuln_type, [])
    
    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate comprehensive statistics"""
        if not self.findings:
            return {'total_vulnerabilities': 0}
        
        stats = {
            'total_vulnerabilities': len(self.findings),
            'severity_breakdown': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0},
            'type_breakdown': {},
            'confidence_breakdown': {'Certain': 0, 'Firm': 0, 'Tentative': 0},
            'affected_endpoints': set(),
            'risk_score': 0
        }
        
        for vuln in self.findings:
            # Severity breakdown
            severity = vuln.get('severity', 'Info')
            stats['severity_breakdown'][severity] += 1
            
            # Type breakdown
            vuln_type = vuln.get('type', 'Unknown')
            stats['type_breakdown'][vuln_type] = stats['type_breakdown'].get(vuln_type, 0) + 1
            
            # Confidence breakdown
            confidence = vuln.get('confidence', 'Certain')
            stats['confidence_breakdown'][confidence] += 1
            
            # Affected endpoints
            url = vuln.get('url', '')
            if url:
                parsed = urlparse(url)
                endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                stats['affected_endpoints'].add(endpoint)
        
        # Convert set to list for JSON serialization
        stats['affected_endpoints'] = list(stats['affected_endpoints'])
        
        # Calculate risk score (weighted by severity)
        weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2, 'Info': 1}
        stats['risk_score'] = sum(
            stats['severity_breakdown'][sev] * weight 
            for sev, weight in weights.items()
        )
        
        return stats
    
    def _generate_timeline(self) -> List[Dict[str, Any]]:
        """Generate scan timeline"""
        timeline = []
        
        if self.findings:
            # Group findings by hour
            hourly_counts = {}
            for vuln in self.findings:
                timestamp = vuln.get('timestamp', '')
                if timestamp:
                    hour = timestamp[:13]  # YYYY-MM-DDTHH
                    hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
            
            # Create timeline entries
            for hour, count in sorted(hourly_counts.items()):
                timeline.append({
                    'timestamp': hour + ':00:00',
                    'findings_discovered': count,
                    'cumulative_findings': sum(hourly_counts[h] for h in hourly_counts if h <= hour)
                })
        
        return timeline
    
    def _collect_evidence(self) -> Dict[str, Any]:
        """Collect all evidence from findings"""
        evidence = {
            'total_requests': 0,
            'total_responses': 0,
            'unique_domains': set(),
            'technologies_detected': set(),
            'sensitive_data_found': []
        }
        
        for vuln in self.findings:
            # Extract domains
            url = vuln.get('url', '')
            if url:
                parsed = urlparse(url)
                evidence['unique_domains'].add(parsed.netloc)
            
            # Look for sensitive data in evidence
            vuln_evidence = vuln.get('evidence', {})
            response_snippet = vuln_evidence.get('response_snippet', '')
            
            # Check for common sensitive patterns
            sensitive_patterns = [
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'password\s*[:=]\s*\S+',  # Password
                r'api[_-]?key\s*[:=]\s*\S+',  # API key
                r'secret\s*[:=]\s*\S+'  # Secret
            ]
            
            import re
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, response_snippet, re.IGNORECASE)
                for match in matches:
                    evidence['sensitive_data_found'].append({
                        'type': 'sensitive_pattern',
                        'pattern': pattern,
                        'match': match,
                        'url': url
                    })
        
        # Convert sets to lists
        evidence['unique_domains'] = list(evidence['unique_domains'])
        evidence['technologies_detected'] = list(evidence['technologies_detected'])
        
        return evidence
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # High-level recommendations based on vulnerability types found
        vuln_types = set(vuln.get('type') for vuln in self.findings)
        
        type_recommendations = {
            'XSS': {
                'priority': 'High',
                'title': 'Implement Content Security Policy (CSP)',
                'description': 'Deploy a strict CSP to prevent XSS attacks by controlling which resources can be loaded.',
                'implementation': 'Add CSP header: Content-Security-Policy: default-src \'self\''
            },
            'SQL_INJECTION': {
                'priority': 'Critical',
                'title': 'Implement Parameterized Queries',
                'description': 'Replace string concatenation with parameterized queries or prepared statements.',
                'implementation': 'Use ORM frameworks or database drivers that support parameter binding.'
            },
            'COMMAND_INJECTION': {
                'priority': 'Critical',
                'title': 'Avoid System Command Execution',
                'description': 'Eliminate direct system command execution. Use safer alternatives.',
                'implementation': 'Replace exec/system calls with language-specific APIs.'
            },
            'CSRF': {
                'priority': 'Medium',
                'title': 'Implement CSRF Protection',
                'description': 'Add CSRF tokens to all state-changing requests.',
                'implementation': 'Use framework CSRF protection or implement custom tokens.'
            }
        }
        
        for vuln_type in vuln_types:
            if vuln_type in type_recommendations:
                rec = type_recommendations[vuln_type].copy()
                rec['vulnerability_type'] = vuln_type
                recommendations.append(rec)
        
        return recommendations


class ReportGenerator:
    """Generate various report formats from extracted results"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_json_report(self, results: Dict[str, Any], filename: str = None) -> str:
        """Generate JSON report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"burp_scan_report_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        return str(output_path)
    
    def generate_html_report(self, results: Dict[str, Any], filename: str = None) -> str:
        """Generate HTML dashboard report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"burp_scan_report_{timestamp}.html"
        
        output_path = self.output_dir / filename
        
        html_content = self._generate_html_content(results)
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def generate_csv_report(self, results: Dict[str, Any], filename: str = None) -> str:
        """Generate CSV report for spreadsheet analysis"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"burp_scan_report_{timestamp}.csv"
        
        output_path = self.output_dir / filename
        
        vulnerabilities = results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return str(output_path)
        
        # Define CSV headers
        headers = [
            'ID', 'Type', 'Severity', 'Confidence', 'URL', 'Method', 
            'Parameter', 'Description', 'Remediation', 'Timestamp'
        ]
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for vuln in vulnerabilities:
                row = [
                    vuln.get('id', ''),
                    vuln.get('type', ''),
                    vuln.get('severity', ''),
                    vuln.get('confidence', ''),
                    vuln.get('url', ''),
                    vuln.get('method', ''),
                    vuln.get('parameter', ''),
                    vuln.get('description', ''),
                    vuln.get('remediation', ''),
                    vuln.get('timestamp', '')
                ]
                writer.writerow(row)
        
        return str(output_path)
    
    def _generate_html_content(self, results: Dict[str, Any]) -> str:
        """Generate HTML dashboard content"""
        metadata = results.get('scan_metadata', {})
        vulnerabilities = results.get('vulnerabilities', [])
        statistics = results.get('statistics', {})
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>JS Scout Pro - Burp Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        .severity-critical {{ background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%); }}
        .severity-high {{ background: linear-gradient(135deg, #ff6b6b 0%, #ff8e53 100%); }}
        .severity-medium {{ background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%); }}
        .severity-low {{ background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%); }}
        .vulnerability-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        .vulnerability-table th, .vulnerability-table td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        .vulnerability-table th {{ background-color: #f8f9fa; }}
        .severity-badge {{ padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8em; }}
        .severity-critical-badge {{ background-color: #dc3545; }}
        .severity-high-badge {{ background-color: #fd7e14; }}
        .severity-medium-badge {{ background-color: #ffc107; color: black; }}
        .severity-low-badge {{ background-color: #28a745; }}
        .severity-info-badge {{ background-color: #17a2b8; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 JS Scout Pro - Burp Scan Report</h1>
            <p>Automated Vulnerability Assessment Report</p>
            <p><strong>Scan ID:</strong> {metadata.get('scan_id', 'N/A')}</p>
            <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{statistics.get('total_vulnerabilities', 0)}</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat-card severity-critical">
                <div class="stat-number">{statistics.get('severity_breakdown', {}).get('Critical', 0)}</div>
                <div>Critical</div>
            </div>
            <div class="stat-card severity-high">
                <div class="stat-number">{statistics.get('severity_breakdown', {}).get('High', 0)}</div>
                <div>High</div>
            </div>
            <div class="stat-card severity-medium">
                <div class="stat-number">{statistics.get('severity_breakdown', {}).get('Medium', 0)}</div>
                <div>Medium</div>
            </div>
            <div class="stat-card severity-low">
                <div class="stat-number">{statistics.get('severity_breakdown', {}).get('Low', 0)}</div>
                <div>Low</div>
            </div>
        </div>
        
        <h2>🎯 Vulnerability Findings</h2>
        <table class="vulnerability-table">
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>URL</th>
                    <th>Method</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for vuln in vulnerabilities[:50]:  # Limit to first 50 for readability
            severity = vuln.get('severity', 'Info')
            severity_class = severity.lower().replace(' ', '-')
            
            html += f"""
                <tr>
                    <td>{vuln.get('type', 'Unknown')}</td>
                    <td><span class="severity-badge severity-{severity_class}-badge">{severity}</span></td>
                    <td><a href="{vuln.get('url', '')}" target="_blank">{vuln.get('url', '')[:50]}...</a></td>
                    <td>{vuln.get('method', 'GET')}</td>
                    <td>{vuln.get('description', '')[:100]}...</td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
        
        <h2>📊 Statistics</h2>
        <pre>
""" + json.dumps(statistics, indent=2) + """
        </pre>
    </div>
</body>
</html>
"""
        
        return html


if __name__ == "__main__":
    # Example usage
    from burp_automation import BurpAPIController
    
    # Initialize API controller
    api = BurpAPIController()
    
    # Extract results
    extractor = BurpResultExtractor(api)
    results = extractor.extract_all_results("scan_123")
    
    # Generate reports
    generator = ReportGenerator()
    json_path = generator.generate_json_report(results)
    html_path = generator.generate_html_report(results)
    csv_path = generator.generate_csv_report(results)
    
    print(f"Reports generated:")
    print(f"JSON: {json_path}")
    print(f"HTML: {html_path}")
    print(f"CSV: {csv_path}")
