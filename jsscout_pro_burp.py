#!/usr/bin/env python3
"""
jsscout_pro_burp.py — JS Scout Pro v10 - Burp-Powered Automation Engine
=======================================================================
Complete automated web penetration testing with Burp Suite integration.

This is the MAIN entry point for the upgraded tool that combines:
  1. JS Scout Pro crawling and analysis
  2. Burp Suite automation (headless)
  3. Custom Burp extension deployment
  4. Automated vulnerability scanning
  5. Real-time result extraction
  6. Comprehensive reporting

Usage Examples:
  # Basic automated scan
  python3 jsscout_pro_burp.py https://target.com
  
  # With custom settings
  python3 jsscout_pro_burp.py https://target.com \
    --threads 20 \
    --depth 4 \
    --output ./results \
    --burp-path /usr/bin/burpsuite \
    --headless
  
  # With authentication
  python3 jsscout_pro_burp.py https://target.com \
    --cookies "session=abc123; csrf=xyz789" \
    --header "Authorization: Bearer TOKEN"
  
  # Collaborator OOB detection
  python3 jsscout_pro_burp.py https://target.com \
    --collab-domain abc.burpcollaborator.net

Architecture Flow:
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Target Site   │───▶│  JS Scout Pro   │───▶│  Burp Automation │───▶│   Burp Suite    │
│                 │    │   Crawler       │    │     Engine       │    │   (Headless)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │                       │
         ▼                       ▼                       ▼                       ▼
   Web Application        Endpoint Discovery        Proxy Routing          Vulnerability
   Analysis Engine        Parameter Extraction       Request Logging        Scanning + Detection
                          JS Analysis                Collaborator OOB        Extension API
                          Secret Finding              Session Handling        Real-time Results
"""

import os
import sys
import json
import time
import argparse
import threading
import logging
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Import existing JS Scout Pro modules
try:
    from jsscout import JSScout
    from plugins.advanced_vulns import AdvancedVulnChecker
    from plugins.xss_detector import XSSDetector
    from plugins.vulnerability_checks import VulnerabilityChecker
    from plugins.auth_checks import AuthChecker
    from core.endpoint_extractor import EndpointCollector
    from core.js_secret_analyzer import JSSecretAnalyzer
    from core.report_generator import ReportGenerator as JSReportGenerator
    from utils.logger import make_logger
except ImportError as e:
    print(f"[!] Missing JS Scout Pro module: {e}")
    print("[!] Please ensure all JS Scout Pro modules are in the same directory")
    sys.exit(1)

# Import new Burp automation modules
try:
    from core.burp_automation import BurpAutomationEngine, BurpAutomationContext
    from core.burp_result_extractor import BurpResultExtractor, ReportGenerator
    from core.burp_integration import BurpConfig, BurpCollaborator
except ImportError as e:
    print(f"[!] Missing Burp automation module: {e}")
    sys.exit(1)


class JSScoutProBurp:
    """Main integration class for JS Scout Pro + Burp automation"""
    
    def __init__(self, target_url, options=None):
        self.target_url = target_url
        self.options = options or {}
        
        # Initialize logging
        self.logger = self._setup_logging()
        
        # Initialize components
        self.jsscout = None
        self.burp_engine = None
        self.result_extractor = None
        
        # Scan results storage
        self.scan_results = {
            'jsscout_findings': [],
            'burp_findings': [],
            'combined_findings': [],
            'metadata': {}
        }
        
        # Output directory
        self.output_dir = Path(self.options.get('output', 'output')) / self._get_domain()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"JS Scout Pro v10 - Burp Automation initialized")
        self.logger.info(f"Target: {target_url}")
        self.logger.info(f"Output directory: {self.output_dir}")
    
    def _setup_logging(self):
        """Setup comprehensive logging"""
        log_level = logging.DEBUG if self.options.get('verbose') else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / 'automation.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging.getLogger('jsscout_pro_burp')
    
    def _get_domain(self):
        """Extract domain from target URL"""
        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        return parsed.netloc.replace(':', '_')
    
    def run_complete_scan(self):
        """Execute the complete automated scan pipeline"""
        start_time = time.time()
        
        try:
            self.logger.info("🚀 Starting complete automated scan pipeline...")
            
            # Phase 1: Initialize Burp Suite
            self.logger.info("📡 Phase 1: Initializing Burp Suite automation...")
            self._initialize_burp()
            
            # Phase 2: JS Scout Pro crawling and analysis
            self.logger.info("🕷️  Phase 2: JS Scout Pro crawling and analysis...")
            self._run_jsscout_analysis()
            
            # Phase 3: Burp Suite automated scanning
            self.logger.info("🔍 Phase 3: Burp Suite automated scanning...")
            self._run_burp_scanning()
            
            # Phase 4: Combine and analyze results
            self.logger.info("🧠 Phase 4: Combining and analyzing results...")
            self._combine_results()
            
            # Phase 5: Generate comprehensive reports
            self.logger.info("📊 Phase 5: Generating comprehensive reports...")
            self._generate_reports()
            
            # Phase 6: Cleanup
            self.logger.info("🧹 Phase 6: Cleanup and finalization...")
            self._cleanup()
            
            total_time = time.time() - start_time
            self.logger.info(f"✅ Complete scan finished in {total_time:.2f} seconds")
            
            return self.scan_results
            
        except Exception as e:
            self.logger.error(f"❌ Scan failed: {e}")
            self._cleanup()
            raise
    
    def _initialize_burp(self):
        """Initialize Burp Suite automation"""
        burp_path = self.options.get('burp_path')
        headless = self.options.get('headless', True)
        project_file = self.options.get('project_file')
        
        # Start Burp automation context
        self.burp_engine = BurpAutomationContext(
            burp_path=burp_path,
            project_file=project_file,
            headless=headless
        )
        
        # Enter context manager
        self.burp_engine.__enter__()
        
        # Install custom extension if provided
        extension_path = Path(__file__).parent / 'burp_extension.py'
        if extension_path.exists():
            self.logger.info("Installing custom Burp extension...")
            # Note: Extension installation would need to be handled via Burp API
            # This is a placeholder for the actual implementation
        
        # Initialize result extractor
        self.result_extractor = BurpResultExtractor(self.burp_engine.api_controller)
        
        self.logger.info("✅ Burp Suite automation initialized")
    
    def _run_jsscout_analysis(self):
        """Run JS Scout Pro crawling and vulnerability analysis"""
        # Configure JS Scout Pro options
        jsscout_options = {
            'threads': self.options.get('threads', 10),
            'timeout': self.options.get('timeout', 15),
            'pages': self.options.get('pages', 200),
            'depth': self.options.get('depth', 3),
            'cookies': self.options.get('cookies'),
            'headers': self.options.get('headers', []),
            'burp': True,  # Route through Burp
            'burp_host': '127.0.0.1',
            'burp_port': 8080,
            'collab_domain': self.options.get('collab_domain'),
            'output': str(self.output_dir / 'jsscout'),
            'verbose': self.options.get('verbose')
        }
        
        # Initialize JS Scout Pro
        self.jsscout = JSScout(self.target_url, jsscout_options)
        
        # Run the scan
        self.logger.info("Starting JS Scout Pro analysis...")
        jsscout_results = self.jsscout.run_scan()
        
        # Store results
        self.scan_results['jsscout_findings'] = jsscout_results.get('findings', [])
        self.scan_results['metadata']['jsscout'] = jsscout_results.get('metadata', {})
        
        self.logger.info(f"✅ JS Scout Pro analysis completed - {len(self.scan_results['jsscout_findings'])} findings")
    
    def _run_burp_scanning(self):
        """Run Burp Suite automated scanning"""
        if not self.burp_engine:
            raise RuntimeError("Burp engine not initialized")
        
        # Configure scan options
        scan_options = {
            'crawl_depth': self.options.get('depth', 3),
            'active_scan': True,
            'passive_scan': True,
            'scan_types': ['xss', 'sql_injection', 'ssrf', 'command_injection', 'path_traversal']
        }
        
        # Run automated scan
        self.logger.info("Starting Burp Suite automated scanning...")
        burp_results = self.burp_engine.scan_target(self.target_url, scan_options)
        
        # Extract detailed results
        detailed_results = self.result_extractor.extract_all_results(burp_results['scan_id'])
        
        # Store results
        self.scan_results['burp_findings'] = detailed_results.get('vulnerabilities', [])
        self.scan_results['metadata']['burp'] = detailed_results.get('scan_metadata', {})
        
        self.logger.info(f"✅ Burp Suite scanning completed - {len(self.scan_results['burp_findings'])} findings")
    
    def _combine_results(self):
        """Combine and deduplicate results from both scanners"""
        all_findings = []
        
        # Add JS Scout Pro findings
        for finding in self.scan_results['jsscout_findings']:
            finding['scanner'] = 'JS_Scout_Pro'
            finding['id'] = f"jsp_{finding.get('id', str(hash(finding)))}"
            all_findings.append(finding)
        
        # Add Burp findings
        for finding in self.scan_results['burp_findings']:
            finding['scanner'] = 'Burp_Suite'
            finding['id'] = f"burp_{finding.get('id', str(hash(finding)))}"
            all_findings.append(finding)
        
        # Deduplicate based on URL and vulnerability type
        self.scan_results['combined_findings'] = self._deduplicate_findings(all_findings)
        
        self.logger.info(f"✅ Results combined - {len(self.scan_results['combined_findings'])} unique findings")
    
    def _deduplicate_findings(self, findings):
        """Deduplicate findings based on URL and vulnerability type"""
        unique_findings = []
        seen = set()
        
        for finding in findings:
            # Create deduplication key
            key = (finding.get('url', ''), finding.get('type', ''), finding.get('parameter', ''))
            
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
            else:
                # Merge findings if they appear in both scanners
                existing = next((f for f in unique_findings if 
                               (f.get('url', ''), f.get('type', ''), f.get('parameter', '')) == key), None)
                if existing:
                    existing['scanners'] = existing.get('scanners', [existing['scanner']])
                    if finding['scanner'] not in existing['scanners']:
                        existing['scanners'].append(finding['scanner'])
                        existing['confidence'] = 'High'  # Increase confidence if found by multiple scanners
        
        return unique_findings
    
    def _generate_reports(self):
        """Generate comprehensive reports"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Prepare complete results
        complete_results = {
            'scan_metadata': {
                'target_url': self.target_url,
                'scan_timestamp': datetime.now().isoformat(),
                'tool': 'JS Scout Pro v10 - Burp Automation Engine',
                'options': self.options
            },
            'findings': self.scan_results['combined_findings'],
            'statistics': self._calculate_comprehensive_statistics(),
            'jsscout_metadata': self.scan_results['metadata'].get('jsscout', {}),
            'burp_metadata': self.scan_results['metadata'].get('burp', {}),
            'recommendations': self._generate_comprehensive_recommendations()
        }
        
        # Generate JSON report
        json_path = self.output_dir / f"complete_scan_report_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(complete_results, f, indent=2, default=str)
        
        # Generate HTML report
        report_generator = ReportGenerator(str(self.output_dir))
        html_path = report_generator.generate_html_report(complete_results, f"complete_scan_report_{timestamp}.html")
        
        # Generate CSV report
        csv_path = report_generator.generate_csv_report(complete_results, f"complete_scan_report_{timestamp}.csv")
        
        # Generate executive summary
        summary_path = self._generate_executive_summary(complete_results, timestamp)
        
        # Update scan results
        self.scan_results['report_paths'] = {
            'json': str(json_path),
            'html': str(html_path),
            'csv': str(csv_path),
            'summary': str(summary_path)
        }
        
        self.logger.info(f"✅ Reports generated:")
        for report_type, path in self.scan_results['report_paths'].items():
            self.logger.info(f"  {report_type.upper()}: {path}")
    
    def _calculate_comprehensive_statistics(self):
        """Calculate comprehensive statistics across all findings"""
        findings = self.scan_results['combined_findings']
        
        stats = {
            'total_findings': len(findings),
            'severity_breakdown': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0},
            'type_breakdown': {},
            'scanner_breakdown': {'JS_Scout_Pro': 0, 'Burp_Suite': 0},
            'affected_endpoints': set(),
            'risk_score': 0
        }
        
        for finding in findings:
            # Severity breakdown
            severity = finding.get('severity', 'Info')
            stats['severity_breakdown'][severity] += 1
            
            # Type breakdown
            vuln_type = finding.get('type', 'Unknown')
            stats['type_breakdown'][vuln_type] = stats['type_breakdown'].get(vuln_type, 0) + 1
            
            # Scanner breakdown
            scanner = finding.get('scanner', 'Unknown')
            stats['scanner_breakdown'][scanner] += 1
            
            # Affected endpoints
            url = finding.get('url', '')
            if url:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                stats['affected_endpoints'].add(endpoint)
        
        # Convert set to list
        stats['affected_endpoints'] = list(stats['affected_endpoints'])
        
        # Calculate risk score
        weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2, 'Info': 1}
        stats['risk_score'] = sum(
            stats['severity_breakdown'][sev] * weight 
            for sev, weight in weights.items()
        )
        
        return stats
    
    def _generate_comprehensive_recommendations(self):
        """Generate comprehensive security recommendations"""
        findings = self.scan_results['combined_findings']
        recommendations = []
        
        # Analyze vulnerability types and generate recommendations
        vuln_types = set(finding.get('type') for finding in findings)
        
        # Critical recommendations
        if 'SQL_INJECTION' in vuln_types:
            recommendations.append({
                'priority': 'Critical',
                'category': 'Injection Security',
                'title': 'Implement Comprehensive SQL Injection Protection',
                'description': 'SQL injection vulnerabilities detected. Implement parameterized queries, input validation, and ORM frameworks.',
                'affected_endpoints': [f['url'] for f in findings if f.get('type') == 'SQL_INJECTION']
            })
        
        if 'COMMAND_INJECTION' in vuln_types:
            recommendations.append({
                'priority': 'Critical',
                'category': 'Injection Security',
                'title': 'Eliminate Command Injection Risks',
                'description': 'Command injection vulnerabilities detected. Remove system command execution and use safe alternatives.',
                'affected_endpoints': [f['url'] for f in findings if f.get('type') == 'COMMAND_INJECTION']
            })
        
        # High priority recommendations
        if 'XSS' in vuln_types:
            recommendations.append({
                'priority': 'High',
                'category': 'Client-Side Security',
                'title': 'Implement Comprehensive XSS Protection',
                'description': 'Cross-site scripting vulnerabilities detected. Implement Content Security Policy, output encoding, and input validation.',
                'affected_endpoints': [f['url'] for f in findings if f.get('type') == 'XSS']
            })
        
        if 'SSRF' in vuln_types:
            recommendations.append({
                'priority': 'High',
                'category': 'Server-Side Security',
                'title': 'Implement SSRF Protection',
                'description': 'Server-side request forgery vulnerabilities detected. Implement URL allowlists and network segmentation.',
                'affected_endpoints': [f['url'] for f in findings if f.get('type') == 'SSRF']
            })
        
        # Medium priority recommendations
        if 'CSRF' in vuln_types:
            recommendations.append({
                'priority': 'Medium',
                'category': 'Session Security',
                'title': 'Implement CSRF Protection',
                'description': 'CSRF vulnerabilities detected. Implement anti-CSRF tokens and same-site cookie policies.',
                'affected_endpoints': [f['url'] for f in findings if f.get('type') == 'CSRF']
            })
        
        if 'MISSING_SECURITY_HEADERS' in vuln_types:
            recommendations.append({
                'priority': 'Medium',
                'category': 'Security Configuration',
                'title': 'Implement Security Headers',
                'description': 'Missing security headers detected. Implement CSP, HSTS, X-Frame-Options, and other security headers.',
                'affected_endpoints': [f['url'] for f in findings if f.get('type') == 'MISSING_SECURITY_HEADERS']
            })
        
        return recommendations
    
    def _generate_executive_summary(self, results, timestamp):
        """Generate executive summary report"""
        summary_path = self.output_dir / f"executive_summary_{timestamp}.txt"
        
        stats = results.get('statistics', {})
        findings = results.get('findings', [])
        
        summary_content = f"""
JS SCOUT PRO v10 - EXECUTIVE SUMMARY
=====================================
Target: {self.target_url}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Tool: JS Scout Pro v10 - Burp Automation Engine

OVERVIEW
--------
Total Vulnerabilities Found: {stats.get('total_findings', 0)}
Overall Risk Score: {stats.get('risk_score', 0)}

SEVERITY BREAKDOWN
------------------
Critical: {stats.get('severity_breakdown', {}).get('Critical', 0)}
High: {stats.get('severity_breakdown', {}).get('High', 0)}
Medium: {stats.get('severity_breakdown', {}).get('Medium', 0)}
Low: {stats.get('severity_breakdown', {}).get('Low', 0)}
Info: {stats.get('severity_breakdown', {}).get('Info', 0)}

TOP VULNERABILITY TYPES
----------------------
"""
        
        # Add top vulnerability types
        type_breakdown = stats.get('type_breakdown', {})
        sorted_types = sorted(type_breakdown.items(), key=lambda x: x[1], reverse=True)
        
        for vuln_type, count in sorted_types[:10]:
            summary_content += f"{vuln_type}: {count}\n"
        
        summary_content += f"""
CRITICAL FINDINGS
-----------------
"""
        
        critical_findings = [f for f in findings if f.get('severity') == 'Critical']
        for finding in critical_findings[:5]:
            summary_content += f"- {finding.get('type', 'Unknown')} at {finding.get('url', 'N/A')}\n"
            summary_content += f"  {finding.get('description', '')[:100]}...\n\n"
        
        summary_content += f"""
HIGH PRIORITY RECOMMENDATIONS
------------------------------
"""
        
        recommendations = results.get('recommendations', [])
        high_priority_recs = [r for r in recommendations if r.get('priority') in ['Critical', 'High']]
        
        for rec in high_priority_recs[:5]:
            summary_content += f"1. {rec.get('title', 'Untitled Recommendation')}\n"
            summary_content += f"   {rec.get('description', '')[:150]}...\n\n"
        
        summary_content += f"""
NEXT STEPS
----------
1. Address all Critical and High severity vulnerabilities immediately
2. Implement security headers and configurations
3. Conduct regular security assessments
4. Establish secure development practices
5. Monitor for new vulnerabilities and threats

REPORT FILES
------------
Complete Report: {self.output_dir}/complete_scan_report_{timestamp}.json
HTML Dashboard: {self.output_dir}/complete_scan_report_{timestamp}.html
CSV Data: {self.output_dir}/complete_scan_report_{timestamp}.csv

Generated by JS Scout Pro v10 - Burp Automation Engine
"""
        
        with open(summary_path, 'w') as f:
            f.write(summary_content)
        
        return summary_path
    
    def _cleanup(self):
        """Cleanup resources"""
        try:
            if self.burp_engine:
                self.burp_engine.__exit__(None, None, None)
            
            if self.jsscout:
                # Cleanup JS Scout resources if needed
                pass
            
            self.logger.info("✅ Cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="JS Scout Pro v10 - Burp-Powered Automated Web Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 jsscout_pro_burp.py https://target.com
  python3 jsscout_pro_burp.py https://target.com --threads 20 --depth 4
  python3 jsscout_pro_burp.py https://target.com --cookies "session=abc123"
  python3 jsscout_pro_burp.py https://target.com --collab-domain abc.burpcollaborator.net
        """
    )
    
    # Target
    parser.add_argument('target', help='Target URL to scan')
    
    # Scan options
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('--pages', type=int, default=200, help='Maximum pages to crawl (default: 200)')
    parser.add_argument('--depth', type=int, default=3, help='Crawl depth (default: 3)')
    parser.add_argument('--output', default='output', help='Output directory (default: output)')
    
    # Authentication
    parser.add_argument('--cookies', help='Cookie string (e.g., "session=abc; csrf=xyz")')
    parser.add_argument('--header', action='append', dest='headers', help='Extra header (can be repeated)')
    
    # Burp options
    parser.add_argument('--burp-path', help='Path to Burp Suite executable')
    parser.add_argument('--project-file', help='Burp project file path')
    parser.add_argument('--no-headless', action='store_true', help='Run Burp in GUI mode')
    parser.add_argument('--collab-domain', help='Burp Collaborator domain for OOB detection')
    
    # Other options
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--version', action='version', version='JS Scout Pro v10 - Burp Automation')
    
    args = parser.parse_args()
    
    # Convert args to options dict
    options = {
        'threads': args.threads,
        'timeout': args.timeout,
        'pages': args.pages,
        'depth': args.depth,
        'output': args.output,
        'cookies': args.cookies,
        'headers': args.headers or [],
        'burp_path': args.burp_path,
        'project_file': args.project_file,
        'headless': not args.no_headless,
        'collab_domain': args.collab_domain,
        'verbose': args.verbose
    }
    
    try:
        # Initialize and run scanner
        scanner = JSScoutProBurp(args.target, options)
        results = scanner.run_complete_scan()
        
        # Print summary
        stats = results.get('statistics', {})
        print(f"\n🎉 Scan completed successfully!")
        print(f"📊 Total findings: {stats.get('total_findings', 0)}")
        print(f"🔥 Critical: {stats.get('severity_breakdown', {}).get('Critical', 0)}")
        print(f"⚠️  High: {stats.get('severity_breakdown', {}).get('High', 0)}")
        print(f"📈 Risk Score: {stats.get('risk_score', 0)}")
        
        if 'report_paths' in results:
            print(f"\n📄 Reports generated:")
            for report_type, path in results['report_paths'].items():
                print(f"  {report_type.upper()}: {path}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
