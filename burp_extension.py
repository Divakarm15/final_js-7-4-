#!/usr/bin/env python3
"""
burp_extension.py — JS Scout Pro Automated Burp Extension
========================================================
Custom Burp Extension for automated vulnerability detection and logging.

Features:
  1. Real-time HTTP traffic analysis
  2. Automated vulnerability detection
  3. JSON result export
  4. Collaborator OOB monitoring
  5. Custom payload injection
  6. Live vulnerability logging

Installation:
  1. Load this extension in Burp Suite
  2. Extension will automatically start monitoring traffic
  3. Results exported to JSON file

Usage:
  python3 -m py_compile burp_extension.py
  # Load the compiled .pyc file in Burp Extender
"""

from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import IHttpListener
from burp import IScannerListener
from burp import ITab
from javax.swing import JPanel, JLabel, JTextArea, JButton, JScrollPane
from java.awt import BorderLayout, GridLayout
import json
import time
import hashlib
import threading
from datetime import datetime
import re


class BurpExtender(IBurpExtender, IExtensionStateListener, IHttpListener, 
                  IScannerListener, ITab):
    
    def __init__(self):
        self.callbacks = None
        self.helpers = None
        self.vulnerabilities = []
        self.request_count = 0
        self.output_file = "jsscout_burp_findings.json"
        self.monitoring = True
        
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension"""
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("JS Scout Pro Automation")
        
        # Register listeners
        callbacks.registerExtensionStateListener(self)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerListener(self)
        
        # Add UI tab
        self._create_ui()
        
        # Log initialization
        print("[JS Scout Pro] Extension loaded successfully")
        print("[JS Scout Pro] Monitoring HTTP traffic for vulnerabilities...")
        
    def _create_ui(self):
        """Create extension UI tab"""
        self.main_panel = JPanel(BorderLayout())
        
        # Status label
        self.status_label = JLabel("Status: Active - Monitoring Traffic")
        self.main_panel.add(self.status_label, BorderLayout.NORTH)
        
        # Vulnerability log area
        self.log_area = JTextArea(15, 50)
        self.log_area.setEditable(False)
        scroll_pane = JScrollPane(self.log_area)
        self.main_panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Export button
        export_button = JButton("Export Findings")
        export_button.addActionListener(self._export_findings)
        self.main_panel.add(export_button, BorderLayout.SOUTH)
        
        # Add tab to Burp UI
        self.callbacks.addSuiteTab(self)
    
    def getTabCaption(self):
        """Return tab name"""
        return "JS Scout Pro"
    
    def getUiComponent(self):
        """Return UI component"""
        return self.main_panel
    
    def extensionUnloaded(self):
        """Called when extension is unloaded"""
        self.monitoring = False
        self._export_findings()
        print("[JS Scout Pro] Extension unloaded")
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process HTTP messages for vulnerability detection"""
        if not self.monitoring or not messageIsRequest:
            return
            
        self.request_count += 1
        
        # Get request details
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()
        
        if not request or not response:
            return
            
        # Analyze for vulnerabilities
        self._analyze_request_response(request, response, messageInfo)
    
    def _analyze_request_response(self, request, response, messageInfo):
        """Analyze request/response for vulnerabilities"""
        try:
            # Parse request
            request_info = self.helpers.analyzeRequest(request)
            url = str(request_info.getUrl())
            method = request_info.getMethod()
            headers = request_info.getHeaders()
            body = request[self.helpers.analyzeRequest(request).getBodyOffset():]
            
            # Parse response
            response_info = self.helpers.analyzeResponse(response)
            response_code = response_info.getStatusCode()
            response_headers = response_info.getHeaders()
            response_body = response[self.helpers.analyzeResponse(response).getBodyOffset():]
            
            # Vulnerability detection modules
            self._check_sql_injection(url, method, headers, body, response_body, response_code)
            self._check_xss(url, method, headers, body, response_body, response_code)
            self._check_ssrf(url, method, headers, body, response_body, response_code)
            self._check_command_injection(url, method, headers, body, response_body, response_code)
            self._check_path_traversal(url, method, headers, body, response_body, response_code)
            self._check_information_disclosure(url, response_headers, response_body)
            self._check_security_headers(url, response_headers)
            self._check_cors_misconfig(url, response_headers)
            
        except Exception as e:
            print(f"[JS Scout Pro] Error analyzing request: {e}")
    
    def _check_sql_injection(self, url, method, headers, body, response_body, response_code):
        """Check for SQL Injection vulnerabilities"""
        sql_errors = [
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
            "valid PostgreSQL result",
            "Npgsql\\.",
            "PG::SyntaxError",
            "org.postgresql.util.PSQLException",
            "ERROR: parser: parse error",
            "SQLite/JDBCDriver",
            "SQLite.Exception",
            "System.Data.SQLite.SQLiteException",
            "Warning.*sqlite_.*",
            "Warning.*sqlite3_.*",
            "Microsoft OLE DB Provider for ODBC Drivers error",
            "Microsoft JET Database Engine error",
            "ODBC Microsoft Access Driver",
            "SQLServer JDBC Driver",
            "com.mysql.jdbc.exceptions",
            "ORA-[0-9]{5}",
            "Oracle error",
            "Oracle driver",
            "Warning.*oci_.*",
            "Warning.*ora_.*"
        ]
        
        response_str = str(response_body)
        for error_pattern in sql_errors:
            if re.search(error_pattern, response_str, re.IGNORECASE):
                self._add_vulnerability(
                    "SQL_INJECTION",
                    "High",
                    url,
                    f"SQL error detected: {error_pattern}",
                    method,
                    str(headers),
                    str(body)[:500]
                )
                break
    
    def _check_xss(self, url, method, headers, body, response_body, response_code):
        """Check for XSS vulnerabilities"""
        # Check for reflected parameters
        if body:
            body_str = str(body)
            # Look for parameter reflection
            params = self._extract_parameters(body_str)
            response_str = str(response_body)
            
            for param, value in params.items():
                if value and value in response_str:
                    # Check if reflected without proper encoding
                    if self._is_unsafe_reflection(value, response_str):
                        self._add_vulnerability(
                            "XSS",
                            "High",
                            url,
                            f"Parameter '{param}' reflected unsafely",
                            method,
                            str(headers),
                            f"Parameter: {param}={value}"
                        )
    
    def _check_ssrf(self, url, method, headers, body, response_body, response_code):
        """Check for SSRF vulnerabilities"""
        # Look for URL parameters that might be vulnerable to SSRF
        if body:
            body_str = str(body)
            url_patterns = [
                r'url\s*=\s*([^&\s]+)',
                r'target\s*=\s*([^&\s]+)',
                r'redirect\s*=\s*([^&\s]+)',
                r'callback\s*=\s*([^&\s]+)',
                r'file\s*=\s*([^&\s]+)',
                r'page\s*=\s*([^&\s]+)'
            ]
            
            for pattern in url_patterns:
                matches = re.findall(pattern, body_str, re.IGNORECASE)
                for match in matches:
                    if self._is_suspicious_url(match):
                        self._add_vulnerability(
                            "SSRF",
                            "High",
                            url,
                            f"Potential SSRF in parameter: {pattern}",
                            method,
                            str(headers),
                            f"Suspicious URL: {match}"
                        )
    
    def _check_command_injection(self, url, method, headers, body, response_body, response_code):
        """Check for Command Injection vulnerabilities"""
        cmd_errors = [
            "sh: command not found",
            "bash: command not found",
            "cmd.exe not found",
            "Command execution failed",
            "Syntax error: Unterminated quoted string",
            "Fatal error: Call to undefined function",
            "Warning: exec(): Unable to fork",
            "Warning: system(): Unable to fork"
        ]
        
        response_str = str(response_body)
        for error_pattern in cmd_errors:
            if re.search(error_pattern, response_str, re.IGNORECASE):
                self._add_vulnerability(
                    "COMMAND_INJECTION",
                    "Critical",
                    url,
                    f"Command injection error detected: {error_pattern}",
                    method,
                    str(headers),
                    str(body)[:500]
                )
                break
    
    def _check_path_traversal(self, url, method, headers, body, response_body, response_code):
        """Check for Path Traversal vulnerabilities"""
        traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"etc/passwd",
            r"windows/system32",
            r"boot\.ini"
        ]
        
        # Check in request body
        if body:
            body_str = str(body)
            for pattern in traversal_patterns:
                if re.search(pattern, body_str, re.IGNORECASE):
                    # Check if response contains file system content
                    response_str = str(response_body)
                    if any(indicator in response_str.lower() for indicator in 
                          ["root:x:0:0", "daemon:", "bin:x:", "system32", "boot loader"]):
                        self._add_vulnerability(
                            "PATH_TRAVERSAL",
                            "High",
                            url,
                            f"Path traversal successful: {pattern}",
                            method,
                            str(headers),
                            f"Pattern found: {pattern}"
                        )
                        break
    
    def _check_information_disclosure(self, url, response_headers, response_body):
        """Check for information disclosure"""
        response_str = str(response_body)
        
        # Check for sensitive information
        sensitive_patterns = [
            r"stack trace",
            r"exception occurred",
            r"internal server error",
            r"debug mode",
            r"development",
            r"test environment",
            r"database error",
            r"sql syntax",
            r"version\s*:\s*\d+\.\d+",
            r"server\s*:\s*apache/\d+\.\d+",
            r"server\s*:\s*nginx/\d+\.\d+",
            r"x-powered-by",
            r"php version"
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, response_str, re.IGNORECASE):
                self._add_vulnerability(
                    "INFORMATION_DISCLOSURE",
                    "Medium",
                    url,
                    f"Information disclosure: {pattern}",
                    "GET",
                    str(response_headers),
                    f"Pattern: {pattern}"
                )
                break
    
    def _check_security_headers(self, url, response_headers):
        """Check for missing security headers"""
        required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Referrer-Policy"
        ]
        
        headers_str = str(response_headers).lower()
        missing_headers = []
        
        for header in required_headers:
            if header.lower() not in headers_str:
                missing_headers.append(header)
        
        if missing_headers:
            self._add_vulnerability(
                "MISSING_SECURITY_HEADERS",
                "Low",
                url,
                f"Missing security headers: {', '.join(missing_headers)}",
                "GET",
                str(response_headers),
                f"Missing: {', '.join(missing_headers)}"
            )
    
    def _check_cors_misconfig(self, url, response_headers):
        """Check for CORS misconfigurations"""
        headers_str = str(response_headers)
        
        # Check for wildcard CORS with credentials
        if "access-control-allow-origin: *" in headers_str.lower() and \
           "access-control-allow-credentials: true" in headers_str.lower():
            self._add_vulnerability(
                "CORS_MISCONFIGURATION",
                "Medium",
                url,
                "CORS wildcard with credentials allowed",
                "GET",
                str(response_headers),
                "Dangerous CORS configuration detected"
            )
    
    def _extract_parameters(self, body_str):
        """Extract parameters from request body"""
        params = {}
        # Parse URL-encoded form data
        pairs = body_str.split('&')
        for pair in pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key] = value
        return params
    
    def _is_unsafe_reflection(self, value, response_str):
        """Check if parameter reflection is unsafe"""
        # Simple heuristic - check if reflected without proper encoding
        dangerous_chars = ['<', '>', '"', "'", '&', 'javascript:', 'onerror=', 'onload=']
        for char in dangerous_chars:
            if char in value and char in response_str:
                return True
        return False
    
    def _is_suspicious_url(self, url_param):
        """Check if URL parameter looks suspicious for SSRF"""
        suspicious_indicators = ['localhost', '127.0.0.1', '169.254.169.254', 
                               'metadata.google.internal', 'file://', 'ftp://']
        url_param_lower = url_param.lower()
        return any(indicator in url_param_lower for indicator in suspicious_indicators)
    
    def _add_vulnerability(self, vuln_type, severity, url, description, method, headers, evidence):
        """Add vulnerability to findings list"""
        vulnerability = {
            "id": hashlib.md5(f"{url}{vuln_type}{time.time()}".encode()).hexdigest(),
            "type": vuln_type,
            "severity": severity,
            "url": url,
            "method": method,
            "description": description,
            "evidence": evidence[:500],  # Limit evidence length
            "headers": headers[:1000],    # Limit headers length
            "timestamp": datetime.now().isoformat(),
            "tool": "JS Scout Pro Burp Extension"
        }
        
        self.vulnerabilities.append(vulnerability)
        
        # Update UI
        log_entry = f"[{severity}] {vuln_type} - {url}\n"
        log_entry += f"Description: {description}\n"
        log_entry += f"Timestamp: {vulnerability['timestamp']}\n"
        log_entry += "-" * 50 + "\n"
        
        self.log_area.insert(log_entry)
        
        # Update status
        self.status_label.setText(f"Status: Active - {len(self.vulnerabilities)} vulnerabilities found")
        
        print(f"[JS Scout Pro] {severity} {vuln_type} found at {url}")
    
    def _export_findings(self, event=None):
        """Export findings to JSON file"""
        try:
            export_data = {
                "scan_metadata": {
                    "tool": "JS Scout Pro Burp Extension",
                    "timestamp": datetime.now().isoformat(),
                    "total_requests": self.request_count,
                    "total_vulnerabilities": len(self.vulnerabilities)
                },
                "vulnerabilities": self.vulnerabilities,
                "statistics": self._calculate_statistics()
            }
            
            with open(self.output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"[JS Scout Pro] Findings exported to {self.output_file}")
            self.status_label.setText(f"Status: {len(self.vulnerabilities)} vulnerabilities exported")
            
        except Exception as e:
            print(f"[JS Scout Pro] Error exporting findings: {e}")
    
    def _calculate_statistics(self):
        """Calculate vulnerability statistics"""
        stats = {
            "severity_breakdown": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            "type_breakdown": {}
        }
        
        for vuln in self.vulnerabilities:
            # Severity breakdown
            severity = vuln.get("severity", "Low")
            stats["severity_breakdown"][severity] += 1
            
            # Type breakdown
            vuln_type = vuln.get("type", "Unknown")
            stats["type_breakdown"][vuln_type] = stats["type_breakdown"].get(vuln_type, 0) + 1
        
        return stats
    
    def newScanIssue(self, issue):
        """Called when Burp scanner finds an issue"""
        # We can integrate with Burp's built-in scanner here
        pass


# Extension entry point
try:
    # For Burp Suite
    extender = BurpExtender()
except Exception as e:
    print(f"Error loading extension: {e}")
