#!/usr/bin/env python3
"""
technology_detector.py - Advanced Technology Detection Engine
============================================================
Comprehensive technology fingerprinting similar to Wappalyzer.
Detects web servers, frameworks, JS libraries, and third-party services.
"""

import re
import json
import hashlib
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Tuple

class TechnologyDetector:
    """Advanced technology detection engine."""
    
    def __init__(self, log_fn=None):
        self.log = log_fn or print
        self.results = {
            'server': {},
            'backend': {},
            'frameworks': [],
            'js_libraries': [],
            'third_party': [],
            'endpoints': [],
            'external_domains': []
        }
        
        # Technology detection patterns
        self.server_patterns = {
            'Apache': [
                re.compile(r'Apache[/\s](\d+\.\d+\.\d+)', re.I),
                re.compile(r'Apache', re.I)
            ],
            'Nginx': [
                re.compile(r'nginx[/\s](\d+\.\d+\.\d+)', re.I),
                re.compile(r'nginx', re.I)
            ],
            'IIS': [
                re.compile(r'IIS[/\s](\d+\.\d+)', re.I),
                re.compile(r'Microsoft-IIS', re.I)
            ],
            'Cloudflare': [
                re.compile(r'cloudflare', re.I),
                re.compile(r'CF-RAY:', re.I)
            ],
            'LiteSpeed': [
                re.compile(r'LiteSpeed', re.I)
            ],
            'Caddy': [
                re.compile(r'Caddy', re.I)
            ]
        }
        
        self.backend_patterns = {
            'PHP': [
                re.compile(r'PHP[/\s](\d+\.\d+\.\d+)', re.I),
                re.compile(r'X-Powered-By:\s*PHP', re.I),
                re.compile(r'\.php$', re.I)
            ],
            'Node.js': [
                re.compile(r'Node\.js', re.I),
                re.compile(r'Express', re.I)
            ],
            'Python': [
                re.compile(r'Python[/\s](\d+\.\d+\.\d+)', re.I),
                re.compile(r'Django', re.I),
                re.compile(r'Flask', re.I),
                re.compile(r'WSGI', re.I)
            ],
            'Java': [
                re.compile(r'Java[/\s](\d+\.\d+)', re.I),
                re.compile(r'Servlet', re.I),
                re.compile(r'JSP', re.I),
                re.compile(r'Spring', re.I)
            ],
            'Ruby': [
                re.compile(r'Ruby[/\s](\d+\.\d+\.\d+)', re.I),
                re.compile(r'Rails', re.I),
                re.compile(r'Phusion', re.I)
            ],
            'Go': [
                re.compile(r'Go[/\s](\d+\.\d+)', re.I)
            ],
            'ASP.NET': [
                re.compile(r'ASP\.NET', re.I),
                re.compile(r'\.aspx$', re.I)
            ]
        }
        
        self.framework_patterns = {
            'React': [
                re.compile(r'react[/\s](\d+\.\d+\.\d+)', re.I),
                re.compile(r'React', re.I),
                re.compile(r'react-dom', re.I)
            ],
            'Angular': [
                re.compile(r'angular[/\s](\d+\.\d+\.\d+)', re.I),
                re.compile(r'ng-version=', re.I),
                re.compile(r'Angular', re.I)
            ],
            'Vue.js': [
                re.compile(r'vue[/\s](\d+\.\d+\.\d+)', re.I),
                re.compile(r'Vue\.js', re.I),
                re.compile(r'v\d+\.\d+\.\d+', re.I)
            ],
            'jQuery': [
                re.compile(r'jquery[/\s-](\d+\.\d+\.\d+)', re.I),
                re.compile(r'jQuery', re.I),
                re.compile(r'\$\.fn\.jquery', re.I)
            ],
            'Bootstrap': [
                re.compile(r'bootstrap[/\s-](\d+\.\d+\.\d+)', re.I),
                re.compile(r'Bootstrap', re.I)
            ],
            'Django': [
                re.compile(r'Django[/\s](\d+\.\d+\.\d+)', re.I),
                re.compile(r'csrfmiddlewaretoken', re.I)
            ],
            'Laravel': [
                re.compile(r'Laravel', re.I),
                re.compile(r'laravel_session', re.I)
            ],
            'WordPress': [
                re.compile(r'WordPress[/\s](\d+\.\d+\.\d+)', re.I),
                re.compile(r'wp-content', re.I),
                re.compile(r'wp-includes', re.I)
            ],
            'Drupal': [
                re.compile(r'Drupal[/\s](\d+)', re.I),
                re.compile(r'Drupal.settings', re.I)
            ]
        }
        
        self.js_library_patterns = {
            'jQuery': [
                re.compile(r'jquery[-/](\d+\.\d+\.\d+)[.-]min\.js', re.I),
                re.compile(r'jQuery\s*=\s*jQuery\s*\|\|\s*\{\}', re.I),
                re.compile(r'\$\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)["\']', re.I)
            ],
            'React': [
                re.compile(r'react[-/](\d+\.\d+\.\d+)[.-]min\.js', re.I),
                re.compile(r'React\.createElement', re.I),
                re.compile(r'react-dom[-/](\d+\.\d+\.\d+)[.-]min\.js', re.I)
            ],
            'Vue.js': [
                re.compile(r'vue[-/](\d+\.\d+\.\d+)[.-]min\.js', re.I),
                re.compile(r'Vue\.config\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']', re.I)
            ],
            'Angular': [
                re.compile(r'angular[-/](\d+\.\d+\.\d+)[.-]min\.js', re.I),
                re.compile(r'ng-version=["\'](\d+\.\d+\.\d+)["\']', re.I)
            ],
            'Bootstrap': [
                re.compile(r'bootstrap[-/](\d+\.\d+\.\d+)[.-]min\.js', re.I),
                re.compile(r'bootstrap[-/](\d+\.\d+\.\d+)[.-]min\.css', re.I)
            ],
            'Font Awesome': [
                re.compile(r'font-awesome[-/](\d+\.\d+\.\d+)[.-]min\.css', re.I),
                re.compile(r'fa-', re.I)
            ],
            'Chart.js': [
                re.compile(r'chart\.js[-/](\d+\.\d+\.\d+)[.-]min\.js', re.I),
                re.compile(r'Chart\.', re.I)
            ],
            'Moment.js': [
                re.compile(r'moment[-/](\d+\.\d+\.\d+)[.-]min\.js', re.I),
                re.compile(r'moment\(', re.I)
            ],
            'Lodash': [
                re.compile(r'lodash[-/](\d+\.\d+\.\d+)[.-]min\.js', re.I),
                re.compile(r'_\.', re.I)
            ]
        }
        
        self.third_party_patterns = {
            'Google Analytics': [
                re.compile(r'google-analytics\.com', re.I),
                re.compile(r'ga\(', re.I),
                re.compile(r'gtag\(', re.I)
            ],
            'Google Tag Manager': [
                re.compile(r'googletagmanager\.com', re.I),
                re.compile(r'dataLayer', re.I)
            ],
            'Cloudflare': [
                re.compile(r'cloudflare\.com', re.I),
                re.compile(r'CF-RAY:', re.I)
            ],
            'Akamai': [
                re.compile(r'akamai\.net', re.I),
                re.compile(r'akamaized\.net', re.I)
            ],
            'Fastly': [
                re.compile(r'fastly\.net', re.I),
                re.compile(r'Fastly-', re.I)
            ],
            'AWS CloudFront': [
                re.compile(r'cloudfront\.net', re.I),
                re.compile(r'awsstatic\.com', re.I)
            ],
            'CDNJS': [
                re.compile(r'cdnjs\.cloudflare\.com', re.I)
            ],
            'jsDelivr': [
                re.compile(r'cdn\.jsdelivr\.net', re.I)
            ],
            'UNPKG': [
                re.compile(r'unpkg\.com', re.I)
            ],
            'Google Fonts': [
                re.compile(r'fonts\.googleapis\.com', re.I),
                re.compile(r'fonts\.gstatic\.com', re.I)
            ],
            'Font Awesome': [
                re.compile(r'fontawesome\.com', re.I),
                re.compile(r'fa-', re.I)
            ],
            'Firebase': [
                re.compile(r'firebase\.com', re.I),
                re.compile(r'firebaseio\.com', re.I)
            ],
            'Auth0': [
                re.compile(r'auth0\.com', re.I),
                re.compile(r'auth0-js', re.I)
            ],
            'Stripe': [
                re.compile(r'stripe\.com', re.I),
                re.compile(r'stripe\.js', re.I)
            ],
            'PayPal': [
                re.compile(r'paypal\.com', re.I),
                re.compile(r'paypal\.js', re.I)
            ]
        }
    
    def detect_from_headers(self, headers: Dict[str, str]) -> None:
        """Detect technologies from HTTP headers."""
        self.log("[DEBUG] Analyzing HTTP headers for technology detection...")
        
        headers_str = '\n'.join(f'{k}: {v}' for k, v in headers.items())
        
        # Detect web server
        for server, patterns in self.server_patterns.items():
            for pattern in patterns:
                if pattern.search(headers_str):
                    version_match = pattern.search(headers_str)
                    version = version_match.group(1) if version_match and version_match.lastindex else None
                    self.results['server'] = {
                        'name': server,
                        'version': version
                    }
                    self.log(f"[DEBUG] Detected server: {server} {version or ''}")
                    break
            if self.results['server']:
                break
        
        # Detect backend
        for backend, patterns in self.backend_patterns.items():
            for pattern in patterns:
                if pattern.search(headers_str):
                    version_match = pattern.search(headers_str)
                    version = version_match.group(1) if version_match and version_match.lastindex else None
                    self.results['backend'] = {
                        'name': backend,
                        'version': version
                    }
                    self.log(f"[DEBUG] Detected backend: {backend} {version or ''}")
                    break
            if self.results['backend']:
                break
    
    def detect_from_html(self, html_content: str, url: str) -> None:
        """Detect technologies from HTML content."""
        self.log("[DEBUG] Analyzing HTML content for technology detection...")
        
        # Detect frameworks from HTML
        for framework, patterns in self.framework_patterns.items():
            for pattern in patterns:
                if pattern.search(html_content):
                    if framework not in [f['name'] for f in self.results['frameworks']]:
                        version_match = pattern.search(html_content)
                        version = version_match.group(1) if version_match and version_match.lastindex else None
                        self.results['frameworks'].append({
                            'name': framework,
                            'version': version,
                            'source': 'html'
                        })
                        self.log(f"[DEBUG] Detected framework: {framework} {version or ''}")
    
    def detect_js_libraries(self, js_files: List[str], js_content: Dict[str, str]) -> None:
        """Detect JavaScript libraries and versions."""
        self.log(f"[DEBUG] Analyzing {len(js_files)} JS files for library detection...")
        
        for js_file in js_files:
            filename = Path(js_file).name.lower()
            content = js_content.get(js_file, '')
            
            # Detect from filename
            for library, patterns in self.js_library_patterns.items():
                for pattern in patterns:
                    # Check filename
                    if pattern.search(filename):
                        version_match = pattern.search(filename)
                        version = version_match.group(1) if version_match and version_match.lastindex else None
                        
                        # Check if already detected
                        if not any(lib['name'] == library and lib['file'] == js_file for lib in self.results['js_libraries']):
                            self.results['js_libraries'].append({
                                'name': library,
                                'version': version,
                                'file': js_file,
                                'source': 'filename'
                            })
                            self.log(f"[DEBUG] Detected JS library from filename: {library} {version or ''}")
                            break
                    
                    # Check content
                    if content and pattern.search(content):
                        version_match = pattern.search(content)
                        version = version_match.group(1) if version_match and version_match.lastindex else None
                        
                        # Check if already detected
                        if not any(lib['name'] == library and lib['file'] == js_file for lib in self.results['js_libraries']):
                            self.results['js_libraries'].append({
                                'name': library,
                                'version': version,
                                'file': js_file,
                                'source': 'content'
                            })
                            self.log(f"[DEBUG] Detected JS library from content: {library} {version or ''}")
                            break
    
    def detect_third_party(self, urls: List[str], content: str) -> None:
        """Detect third-party services."""
        self.log("[DEBUG] Analyzing URLs for third-party services...")
        
        all_text = ' '.join(urls) + ' ' + content
        
        for service, patterns in self.third_party_patterns.items():
            for pattern in patterns:
                if pattern.search(all_text):
                    if service not in [s['name'] for s in self.results['third_party']]:
                        self.results['third_party'].append({
                            'name': service,
                            'detected': True
                        })
                        self.log(f"[DEBUG] Detected third-party service: {service}")
                        break
    
    def extract_external_domains(self, urls: List[str], base_domain: str) -> None:
        """Extract external domains from URLs."""
        self.log("[DEBUG] Extracting external domains...")
        
        domains = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                if domain and domain != base_domain and not domain.startswith('www.'):
                    domains.add(domain)
            except:
                continue
        
        self.results['external_domains'] = sorted(list(domains))
        self.log(f"[DEBUG] Found {len(self.results['external_domains'])} external domains")
    
    def analyze_endpoints(self, urls: List[str]) -> None:
        """Analyze endpoints for API patterns."""
        self.log("[DEBUG] Analyzing endpoints for API patterns...")
        
        api_patterns = [
            re.compile(r'/api/[^/]+', re.I),
            re.compile(r'/v\d+/', re.I),
            re.compile(r'/rest/', re.I),
            re.compile(r'/graphql', re.I),
            re.compile(r'/oauth/', re.I),
            re.compile(r'/auth/', re.I),
            re.compile(r'/login', re.I),
            re.compile(r'/admin', re.I)
        ]
        
        endpoints = []
        for url in urls:
            for pattern in api_patterns:
                if pattern.search(url):
                    endpoints.append(url)
                    break
        
        self.results['endpoints'] = list(set(endpoints))
        self.log(f"[DEBUG] Found {len(self.results['endpoints'])} API endpoints")
    
    def run_detection(self, session, base_url: str, visited_urls: List[str], 
                     js_files: List[str], js_content: Dict[str, str]) -> Dict:
        """Run complete technology detection."""
        self.log("[DEBUG] Starting comprehensive technology detection...")
        
        try:
            # Get main page headers
            response = session.get(base_url, timeout=10)
            headers = dict(response.headers)
            html_content = response.text
            
            # Detect from headers
            self.detect_from_headers(headers)
            
            # Detect from HTML
            self.detect_from_html(html_content, base_url)
            
            # Detect JS libraries
            self.detect_js_libraries(js_files, js_content)
            
            # Detect third-party services
            all_urls = visited_urls + js_files
            self.detect_third_party(all_urls, html_content)
            
            # Extract external domains
            base_domain = urlparse(base_url).netloc
            self.extract_external_domains(all_urls, base_domain)
            
            # Analyze endpoints
            self.analyze_endpoints(visited_urls)
            
            self.log("[DEBUG] Technology detection completed")
            return self.results
            
        except Exception as e:
            self.log(f"[!] Technology detection error: {e}")
            return self.results
