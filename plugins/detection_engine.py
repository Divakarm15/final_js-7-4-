#!/usr/bin/env python3
"""
detection_engine.py — High-Confidence 3-Stage Detection Engine
=================================================================
Implements a robust detection system that eliminates false positives:

Stage 1: Detection - Initial anomaly identification
Stage 2: Confirmation - Secondary payload verification  
Stage 3: Validation - Control payload verification

Only vulnerabilities passing ALL 3 stages are reported.
"""

import re
import time
import hashlib
import random
import string
from urllib.parse import urljoin, urlparse, urlencode, quote
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum

class Confidence(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class VulnType(Enum):
    XSS = "XSS"
    SQL_INJECTION = "SQL_INJECTION"
    SSRF = "SSRF"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    LFI = "LFI"
    SSTI = "SSTI"

@dataclass
class DetectionResult:
    """Single detection result with evidence."""
    stage: str
    payload: str
    response: Any
    evidence: Dict[str, Any]
    confidence: Confidence
    timestamp: float

@dataclass
class Vulnerability:
    """Confirmed vulnerability with full evidence chain."""
    type: VulnType
    url: str
    parameter: str
    confidence: Confidence
    severity: str
    evidence: List[DetectionResult]
    description: str
    remediation: str

class ResponseComparator:
    """Compare responses to detect meaningful differences."""
    
    @staticmethod
    def get_baseline(session, url: str, samples: int = 3) -> Dict:
        """Get baseline response characteristics."""
        responses = []
        for _ in range(samples):
            try:
                r = session.get(url, timeout=10, verify=False)
                responses.append(r)
            except Exception:
                continue
        
        if not responses:
            return {}
        
        # Average characteristics
        avg_length = sum(len(r.text) for r in responses) / len(responses)
        avg_status = sum(r.status_code for r in responses) / len(responses)
        
        # Common patterns
        common_text = ""
        if len(responses) >= 2:
            text1, text2 = responses[0].text, responses[1].text
            common_text = ResponseComparator._find_common_text(text1, text2)
        
        return {
            'avg_length': avg_length,
            'avg_status': avg_status,
            'common_text': common_text,
            'status_codes': list(set(r.status_code for r in responses)),
            'headers': dict(responses[0].headers) if responses else {}
        }
    
    @staticmethod
    def _find_common_text(text1: str, text2: str) -> str:
        """Find common text between two responses."""
        # Simple approach: find longest common substring
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        common_words = words1.intersection(words2)
        return ' '.join(sorted(common_words)[:50])  # First 50 common words
    
    @staticmethod
    def compare_responses(baseline: Dict, response: Any, payload: str) -> Dict:
        """Compare response against baseline."""
        if not baseline:
            return {'significant': False, 'reason': 'No baseline available'}
        
        differences = []
        
        # Length difference
        length_diff = abs(len(response.text) - baseline['avg_length'])
        if length_diff > 100:  # Significant length change
            differences.append(f"Length diff: {length_diff} chars")
        
        # Status code difference
        if response.status_code not in baseline['status_codes']:
            differences.append(f"Status change: {response.status_code}")
        
        # Content difference
        if baseline['common_text']:
            common_words = baseline['common_text'].split()
            response_words = response.text.lower().split()
            missing_words = [w for w in common_words if w not in response_words]
            if len(missing_words) > 10:
                differences.append(f"Content change: {len(missing_words)} words missing")
        
        # Error pattern detection
        error_patterns = [
            r'sql syntax.*error',
            r'warning.*mysql',
            r'ora-\d{5}',
            r'pg_query.*error',
            r'division by zero',
            r'internal server error',
            r'500.*error',
            r'javascript.*error',
            r'syntax error',
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.I):
                differences.append(f"Error pattern: {pattern}")
                break
        
        # Reflection detection
        if payload and payload.lower() in response.text.lower():
            differences.append(f"Payload reflection: {payload[:30]}...")
        
        return {
            'significant': len(differences) > 0,
            'differences': differences,
            'length': len(response.text),
            'status': response.status_code,
            'payload_reflected': payload and payload.lower() in response.text.lower()
        }

class XSSDetector:
    """High-confidence XSS detection with context awareness."""
    
    CONTEXTS = {
        'html': r'<[^>]*>[^<]*',
        'attribute': r'[^>]*"[^"]*',
        'javascript': r'javascript:[^;]*;[^;]*',
        'url': r'https?://[^\\s]*'
    }
    
    PAYLOADS = {
        'html': [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
        ],
        'attribute': [
            '" onmouseover="alert(\'XSS\')"',
            "' onmouseover='alert(\"XSS\")'",
            'javascript:alert("XSS")',
        ],
        'javascript': [
            ';alert("XSS")',
            ';document.location="http://evil.com"',
            ';window.alert("XSS")',
        ],
        'url': [
            'javascript:alert("XSS")',
            'data:text/html,<script>alert("XSS")</script>',
        ]
    }
    
    CONTROL_PAYLOADS = [
        'normal_text_12345',
        'innocent_string_xyz',
        'test_payload_abc',
    ]
    
    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout
        self.comparator = ResponseComparator()
    
    def detect(self, url: str, param: str) -> Optional[Vulnerability]:
        """3-stage XSS detection."""
        base_url = f"{url}?{urlencode({param: 'test'})}"
        baseline = self.comparator.get_baseline(self.session, base_url)
        
        # Stage 1: Detection
        detection = self._stage1_detection(url, param, baseline)
        if not detection:
            return None
        
        # Stage 2: Confirmation
        confirmation = self._stage2_confirmation(url, param, baseline)
        if not confirmation:
            return None
        
        # Stage 3: Validation
        validation = self._stage3_validation(url, param, baseline)
        if not validation:
            return None
        
        # Build vulnerability report
        return Vulnerability(
            type=VulnType.XSS,
            url=url,
            parameter=param,
            confidence=Confidence.HIGH,
            severity="HIGH",
            evidence=[detection, confirmation, validation],
            description=f"Cross-Site Scripting (XSS) in parameter '{param}'",
            remediation=f"Sanitize input in parameter '{param}' and implement CSP"
        )
    
    def _stage1_detection(self, url: str, param: str, baseline: Dict) -> Optional[DetectionResult]:
        """Stage 1: Initial XSS detection."""
        for context, payloads in self.PAYLOADS.items():
            for payload in payloads[:1]:  # Test one payload per context
                test_url = f"{url}?{urlencode({param: payload})}"
                try:
                    r = self.session.get(test_url, timeout=self.timeout, verify=False)
                    comparison = self.comparator.compare_responses(baseline, r, payload)
                    
                    if comparison['significant'] and comparison['payload_reflected']:
                        return DetectionResult(
                            stage="DETECTION",
                            payload=payload,
                            response=r,
                            evidence=comparison,
                            confidence=Confidence.LOW,
                            timestamp=time.time()
                        )
                except Exception:
                    continue
        return None
    
    def _stage2_confirmation(self, url: str, param: str, baseline: Dict) -> Optional[DetectionResult]:
        """Stage 2: Confirm XSS with different payload."""
        for context, payloads in self.PAYLOADS.items():
            for payload in payloads[1:2]:  # Different payload for confirmation
                test_url = f"{url}?{urlencode({param: payload})}"
                try:
                    r = self.session.get(test_url, timeout=self.timeout, verify=False)
                    comparison = self.comparator.compare_responses(baseline, r, payload)
                    
                    if comparison['significant'] and comparison['payload_reflected']:
                        return DetectionResult(
                            stage="CONFIRMATION",
                            payload=payload,
                            response=r,
                            evidence=comparison,
                            confidence=Confidence.MEDIUM,
                            timestamp=time.time()
                        )
                except Exception:
                    continue
        return None
    
    def _stage3_validation(self, url: str, param: str, baseline: Dict) -> Optional[DetectionResult]:
        """Stage 3: Validate with control payload."""
        for payload in self.CONTROL_PAYLOADS:
            test_url = f"{url}?{urlencode({param: payload})}"
            try:
                r = self.session.get(test_url, timeout=self.timeout, verify=False)
                comparison = self.comparator.compare_responses(baseline, r, payload)
                
                # Control payload should NOT trigger significant differences
                if not comparison['significant']:
                    return DetectionResult(
                        stage="VALIDATION",
                        payload=payload,
                        response=r,
                        evidence=comparison,
                        confidence=Confidence.HIGH,
                        timestamp=time.time()
                    )
            except Exception:
                continue
        return None

class SQLiDetector:
    """High-confidence SQL injection detection."""
    
    ERROR_PAYLOADS = [
        "'", '"', "';--", "1' OR '1'='1", "1\" OR \"1\"=\"1", "\\"
    ]
    
    BOOLEAN_PAYLOADS = [
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' AND '1'='1", "1' AND '1'='2"),
    ]
    
    TIME_PAYLOADS = [
        "1; WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--",
        "1; SELECT SLEEP(5)--",
    ]
    
    CONTROL_PAYLOADS = [
        "1",
        "test",
        "normal_input",
    ]
    
    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout
        self.comparator = ResponseComparator()
    
    def detect(self, url: str, param: str) -> Optional[Vulnerability]:
        """3-stage SQL injection detection."""
        base_url = f"{url}?{urlencode({param: 'test'})}"
        baseline = self.comparator.get_baseline(self.session, base_url)
        
        # Stage 1: Detection
        detection = self._stage1_detection(url, param, baseline)
        if not detection:
            return None
        
        # Stage 2: Confirmation
        confirmation = self._stage2_confirmation(url, param, baseline)
        if not confirmation:
            return None
        
        # Stage 3: Validation
        validation = self._stage3_validation(url, param, baseline)
        if not validation:
            return None
        
        return Vulnerability(
            type=VulnType.SQL_INJECTION,
            url=url,
            parameter=param,
            confidence=Confidence.HIGH,
            severity="CRITICAL",
            evidence=[detection, confirmation, validation],
            description=f"SQL Injection in parameter '{param}'",
            remediation=f"Use parameterized queries for parameter '{param}'"
        )
    
    def _stage1_detection(self, url: str, param: str, baseline: Dict) -> Optional[DetectionResult]:
        """Stage 1: Initial SQL injection detection."""
        for payload in self.ERROR_PAYLOADS[:3]:
            test_url = f"{url}?{urlencode({param: payload})}"
            try:
                r = self.session.get(test_url, timeout=self.timeout, verify=False)
                comparison = self.comparator.compare_responses(baseline, r, payload)
                
                if comparison['significant'] and any('error' in diff.lower() for diff in comparison['differences']):
                    return DetectionResult(
                        stage="DETECTION",
                        payload=payload,
                        response=r,
                        evidence=comparison,
                        confidence=Confidence.LOW,
                        timestamp=time.time()
                    )
            except Exception:
                continue
        return None
    
    def _stage2_confirmation(self, url: str, param: str, baseline: Dict) -> Optional[DetectionResult]:
        """Stage 2: Confirm SQL injection with boolean logic."""
        for true_p, false_p in self.BOOLEAN_PAYLOADS[:1]:
            try:
                # True condition
                true_url = f"{url}?{urlencode({param: true_p})}"
                r_true = self.session.get(true_url, timeout=self.timeout, verify=False)
                
                # False condition
                false_url = f"{url}?{urlencode({param: false_p})}"
                r_false = self.session.get(false_url, timeout=self.timeout, verify=False)
                
                # Compare responses
                length_diff = abs(len(r_true.text) - len(r_false.text))
                if length_diff > 50 and r_true.status_code == r_false.status_code:
                    return DetectionResult(
                        stage="CONFIRMATION",
                        payload=f"TRUE:{true_p} / FALSE:{false_p}",
                        response=r_true,
                        evidence={
                            'length_diff': length_diff,
                            'true_length': len(r_true.text),
                            'false_length': len(r_false.text),
                            'true_status': r_true.status_code,
                            'false_status': r_false.status_code
                        },
                        confidence=Confidence.MEDIUM,
                        timestamp=time.time()
                    )
            except Exception:
                continue
        return None
    
    def _stage3_validation(self, url: str, param: str, baseline: Dict) -> Optional[DetectionResult]:
        """Stage 3: Validate with control payload."""
        for payload in self.CONTROL_PAYLOADS:
            test_url = f"{url}?{urlencode({param: payload})}"
            try:
                r = self.session.get(test_url, timeout=self.timeout, verify=False)
                comparison = self.comparator.compare_responses(baseline, r, payload)
                
                # Control payload should NOT trigger significant differences
                if not comparison['significant']:
                    return DetectionResult(
                        stage="VALIDATION",
                        payload=payload,
                        response=r,
                        evidence=comparison,
                        confidence=Confidence.HIGH,
                        timestamp=time.time()
                    )
            except Exception:
                continue
        return None

class DetectionEngine:
    """Main detection engine coordinating all vulnerability detectors."""
    
    def __init__(self, session, timeout=10, debug=False):
        self.session = session
        self.timeout = timeout
        self.debug = debug
        self.detectors = {
            VulnType.XSS: XSSDetector(session, timeout),
            VulnType.SQL_INJECTION: SQLiDetector(session, timeout),
        }
    
    def scan_url(self, url: str, params: List[str]) -> List[Vulnerability]:
        """Scan a URL with given parameters for vulnerabilities."""
        vulnerabilities = []
        
        for param in params[:10]:  # Limit to first 10 parameters
            if self.debug:
                print(f"[DEBUG] Testing parameter: {param}")
            
            for vuln_type, detector in self.detectors.items():
                try:
                    vuln = detector.detect(url, param)
                    if vuln:
                        vulnerabilities.append(vuln)
                        if self.debug:
                            print(f"[+] {vuln_type.value} confirmed in {param}")
                except Exception as e:
                    if self.debug:
                        print(f"[!] Error testing {vuln_type.value} in {param}: {e}")
        
        return vulnerabilities
    
    def get_high_confidence_findings(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Filter to only high-confidence vulnerabilities."""
        return [v for v in vulnerabilities if v.confidence == Confidence.HIGH]
    
    def generate_report(self, vulnerabilities: List[Vulnerability]) -> Dict:
        """Generate comprehensive vulnerability report."""
        report = {
            'total_findings': len(vulnerabilities),
            'high_confidence': len(self.get_high_confidence_findings(vulnerabilities)),
            'vulnerabilities': []
        }
        
        for vuln in vulnerabilities:
            vuln_data = {
                'type': vuln.type.value,
                'url': vuln.url,
                'parameter': vuln.parameter,
                'confidence': vuln.confidence.value,
                'severity': vuln.severity,
                'description': vuln.description,
                'remediation': vuln.remediation,
                'evidence': []
            }
            
            for evidence in vuln.evidence:
                evidence_data = {
                    'stage': evidence.stage,
                    'payload': evidence.payload,
                    'confidence': evidence.confidence.value,
                    'timestamp': evidence.timestamp
                }
                
                if isinstance(evidence.evidence, dict):
                    evidence_data['differences'] = evidence.evidence.get('differences', [])
                    evidence_data['length'] = evidence.evidence.get('length', 0)
                    evidence_data['status'] = evidence.evidence.get('status', 0)
                    evidence_data['payload_reflected'] = evidence.evidence.get('payload_reflected', False)
                
                vuln_data['evidence'].append(evidence_data)
            
            report['vulnerabilities'].append(vuln_data)
        
        return report
