#!/usr/bin/env python3
"""
burp_automation.py — JS Scout Pro Burp Suite Automation Engine
================================================================
COMPLETE automated Burp Suite integration with ZERO manual interaction:

Features:
  1. Automatic Burp Suite startup (headless/minimized)
  2. Programmatic Burp configuration
  3. Burp Extension deployment and management
  4. Automated scan triggering and monitoring
  5. Real-time result extraction via API
  6. Collaborator OOB detection automation
  7. Complete pipeline orchestration

Architecture:
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   JS Scout      │───▶│  Burp Automation  │───▶│   Burp Suite    │
│   Scanner       │    │     Engine        │    │   (Headless)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
   Web Crawling          Proxy Routing         Extension API
   Endpoint Discovery    Request Logging       Vulnerability Scanning
   Payload Injection     Collaborator OOB      Real-time Results
"""

import os
import sys
import json
import time
import socket
import subprocess
import threading
import logging
from pathlib import Path
from urllib.parse import urljoin, urlparse
from datetime import datetime, timedelta

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    raise ImportError("[!] pip install requests")

log = logging.getLogger('jsscout.burp_automation')


class BurpProcessManager:
    """Manages Burp Suite process lifecycle automatically"""
    
    def __init__(self, burp_path=None, project_file=None, headless=True):
        self.burp_path = burp_path or self._find_burp_executable()
        self.project_file = project_file
        self.headless = headless
        self.process = None
        self.api_port = self._find_free_port(1337)
        self.proxy_port = 8080
        
    def _find_burp_executable(self):
        """Find Burp Suite executable on common paths"""
        common_paths = [
            "/usr/bin/burpsuite",
            "/opt/burpsuite/burpsuite_pro.sh",
            "/Applications/Burp Suite Community Edition.app/Contents/MacOS/burpsuite",
            "C:\\Program Files\\BurpSuiteCommunity\\burpsuite_community.exe",
            str(Path.home() / "BurpSuite" / "burpsuite_pro.sh"),
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return path
        
        # Try to find in PATH
        result = subprocess.run(["which", "burpsuite"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
            
        raise FileNotFoundError("Burp Suite executable not found. Please install Burp Suite.")
    
    def _find_free_port(self, start_port):
        """Find a free port starting from start_port"""
        for port in range(start_port, start_port + 100):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(('127.0.0.1', port))
                sock.close()
                return port
            except OSError:
                continue
        raise RuntimeError("No free ports available")
    
    def start_burp(self):
        """Start Burp Suite headlessly with API enabled"""
        if self.process and self.process.poll() is None:
            log.info("Burp Suite already running")
            return True
            
        # Prepare command arguments
        cmd = [
            self.burp_path,
            "--headless" if self.headless else "--project-file=" + str(self.project_file) if self.project_file else "",
            "--disable-update-check",
            "--unpause-spider-when-idle",
            "--unpause-scanner-when-idle",
        ]
        
        # Add API configuration
        cmd.extend([
            f"--api-port={self.api_port}",
            "--api-key=jsscout-automation-key",
            "--api-disable-https",
        ])
        
        # Filter out empty strings
        cmd = [arg for arg in cmd if arg]
        
        log.info(f"Starting Burp Suite with API on port {self.api_port}")
        
        try:
            # Start Burp process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True
            )
            
            # Wait for API to be ready
            if self._wait_for_api_ready():
                log.info("Burp Suite API ready")
                return True
            else:
                log.error("Burp Suite API failed to start")
                self.stop_burp()
                return False
                
        except Exception as e:
            log.error(f"Failed to start Burp Suite: {e}")
            return False
    
    def _wait_for_api_ready(self, timeout=60):
        """Wait for Burp API to become responsive"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"http://127.0.0.1:{self.api_port}/", timeout=5)
                if response.status_code == 200:
                    return True
            except:
                pass
            time.sleep(2)
        return False
    
    def stop_burp(self):
        """Stop Burp Suite process"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = None
            log.info("Burp Suite stopped")


class BurpAPIController:
    """Controls Burp Suite via REST API"""
    
    def __init__(self, api_port=1337, api_key="jsscout-automation-key"):
        self.api_base = f"http://127.0.0.1:{api_port}"
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        })
    
    def check_connection(self):
        """Check if Burp API is accessible"""
        try:
            response = self.session.get(f"{self.api_base}/", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def get_scan_status(self, scan_id):
        """Get status of a specific scan"""
        try:
            response = self.session.get(f"{self.api_base}/v0/scanner/status/{scan_id}")
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            log.error(f"Failed to get scan status: {e}")
        return None
    
    def start_scan(self, target_url):
        """Start scanning a target URL"""
        try:
            payload = {
                "url": target_url,
                "scan_type": "crawl_and_audit"
            }
            response = self.session.post(f"{self.api_base}/v0/scanner/scans", json=payload)
            if response.status_code == 201:
                return response.json().get('scan_id')
        except Exception as e:
            log.error(f"Failed to start scan: {e}")
        return None
    
    def get_issues(self, scan_id):
        """Get vulnerability findings from a scan"""
        try:
            response = self.session.get(f"{self.api_base}/v0/scanner/issues/{scan_id}")
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            log.error(f"Failed to get issues: {e}")
        return []
    
    def send_to_spider(self, url):
        """Send URL to Burp spider"""
        try:
            payload = {"url": url}
            response = self.session.post(f"{self.api_base}/v0/spider/scans", json=payload)
            return response.status_code == 201
        except Exception as e:
            log.error(f"Failed to send to spider: {e}")
        return False
    
    def get_spider_status(self, spider_id):
        """Get spider crawl status"""
        try:
            response = self.session.get(f"{self.api_base}/v0/spider/status/{spider_id}")
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            log.error(f"Failed to get spider status: {e}")
        return None


class BurpExtensionManager:
    """Manages custom Burp extensions for automation"""
    
    def __init__(self, api_controller):
        self.api = api_controller
        self.extensions = {}
    
    def install_extension(self, extension_path, extension_name):
        """Install a custom Burp extension"""
        try:
            with open(extension_path, 'rb') as f:
                files = {'extension_file': (extension_name, f, 'application/java-archive')}
                response = requests.post(
                    f"{self.api.api_base}/v0/extensions",
                    files=files,
                    headers={'X-API-Key': self.api.api_key}
                )
                if response.status_code == 201:
                    self.extensions[extension_name] = response.json()
                    log.info(f"Extension {extension_name} installed successfully")
                    return True
        except Exception as e:
            log.error(f"Failed to install extension {extension_name}: {e}")
        return False
    
    def get_extension_status(self, extension_name):
        """Get status of installed extension"""
        try:
            response = self.api.session.get(f"{self.api.api_base}/v0/extensions")
            if response.status_code == 200:
                extensions = response.json()
                return extensions.get(extension_name)
        except Exception as e:
            log.error(f"Failed to get extension status: {e}")
        return None


class BurpCollaboratorAutomation:
    """Automated Burp Collaborator for OOB vulnerability detection"""
    
    def __init__(self, api_controller, collaborator_domain=None):
        self.api = api_controller
        self.collaborator_domain = collaborator_domain
        self.payloads = {}
        self.callbacks = {}
    
    def generate_payload(self, payload_type="ssrf", custom_id=None):
        """Generate unique Collaborator payload"""
        if not self.collaborator_domain:
            # Use Burp's built-in Collaborator
            try:
                response = self.api.session.post(f"{self.api.api_base}/v0/collaborator/payloads")
                if response.status_code == 201:
                    payload_data = response.json()
                    payload_id = payload_data.get('payload_id')
                    self.payloads[payload_id] = payload_data
                    return payload_data.get('payload')
            except Exception as e:
                log.error(f"Failed to generate Collaborator payload: {e}")
        
        # Fallback to custom domain
        if custom_id is None:
            custom_id = f"jsscout-{payload_type}-{int(time.time())}"
        
        payload = f"{custom_id}.{self.collaborator_domain}"
        self.payloads[payload] = {"type": payload_type, "id": custom_id}
        return payload
    
    def poll_callbacks(self, payload_id=None, timeout=300):
        """Poll for Collaborator callbacks"""
        if payload_id:
            # Poll specific payload
            try:
                response = self.api.session.get(f"{self.api.api_base}/v0/collaborator/interactions/{payload_id}")
                if response.status_code == 200:
                    interactions = response.json()
                    if interactions:
                        self.callbacks[payload_id] = interactions
                        return interactions
            except Exception as e:
                log.error(f"Failed to poll callbacks for {payload_id}: {e}")
        else:
            # Poll all payloads
            for payload_id in list(self.payloads.keys()):
                interactions = self.poll_callbacks(payload_id)
                if interactions:
                    return interactions
        return []


class BurpAutomationEngine:
    """Main orchestration engine for complete Burp automation"""
    
    def __init__(self, burp_path=None, project_file=None, headless=True):
        self.process_manager = BurpProcessManager(burp_path, project_file, headless)
        self.api_controller = BurpAPIController(self.process_manager.api_port)
        self.extension_manager = BurpExtensionManager(self.api_controller)
        self.collaborator = BurpCollaboratorAutomation(self.api_controller)
        self.is_running = False
    
    def start(self):
        """Start the complete Burp automation setup"""
        log.info("Starting Burp automation engine...")
        
        # Start Burp Suite
        if not self.process_manager.start_burp():
            raise RuntimeError("Failed to start Burp Suite")
        
        # Verify API connection
        if not self.api_controller.check_connection():
            raise RuntimeError("Burp API not accessible")
        
        self.is_running = True
        log.info("Burp automation engine ready")
        return True
    
    def stop(self):
        """Stop the automation engine"""
        log.info("Stopping Burp automation engine...")
        self.process_manager.stop_burp()
        self.is_running = False
    
    def scan_target(self, target_url, scan_options=None):
        """Perform complete automated scan of target"""
        if not self.is_running:
            raise RuntimeError("Automation engine not started")
        
        scan_options = scan_options or {}
        
        # Phase 1: Spider the target
        log.info(f"Starting spider for {target_url}")
        spider_id = self.api_controller.send_to_spider(target_url)
        if not spider_id:
            raise RuntimeError("Failed to start spider")
        
        # Wait for spider to complete
        while True:
            status = self.api_controller.get_spider_status(spider_id)
            if status and status.get('status') == 'completed':
                break
            time.sleep(5)
        
        # Phase 2: Start active scan
        log.info("Starting active scan")
        scan_id = self.api_controller.start_scan(target_url)
        if not scan_id:
            raise RuntimeError("Failed to start scan")
        
        # Phase 3: Monitor scan progress
        while True:
            status = self.api_controller.get_scan_status(scan_id)
            if status and status.get('status') == 'completed':
                break
            time.sleep(10)
        
        # Phase 4: Extract results
        log.info("Extracting scan results")
        issues = self.api_controller.get_issues(scan_id)
        
        return {
            'scan_id': scan_id,
            'spider_id': spider_id,
            'issues': issues,
            'completed_at': datetime.now().isoformat()
        }
    
    def generate_report(self, scan_results, output_path):
        """Generate comprehensive report from scan results"""
        report = {
            'scan_metadata': {
                'scan_id': scan_results['scan_id'],
                'spider_id': scan_results['spider_id'],
                'completed_at': scan_results['completed_at'],
                'tool': 'JS Scout Pro v10 - Burp Automation Engine'
            },
            'vulnerabilities': scan_results['issues'],
            'statistics': {
                'total_issues': len(scan_results['issues']),
                'severity_breakdown': self._calculate_severity_breakdown(scan_results['issues'])
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        log.info(f"Report generated: {output_path}")
        return report
    
    def _calculate_severity_breakdown(self, issues):
        """Calculate vulnerability severity breakdown"""
        breakdown = {'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for issue in issues:
            severity = issue.get('severity', 'Info')
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown


# Context manager for easy usage
class BurpAutomationContext:
    """Context manager for Burp automation"""
    
    def __init__(self, burp_path=None, project_file=None, headless=True):
        self.engine = BurpAutomationEngine(burp_path, project_file, headless)
    
    def __enter__(self):
        self.engine.start()
        return self.engine
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.engine.stop()


if __name__ == "__main__":
    # Example usage
    with BurpAutomationContext(headless=True) as burp:
        results = burp.scan_target("https://example.com")
        burp.generate_report(results, "scan_results.json")
        print(f"Scan completed. Found {len(results['issues'])} issues")
