"""
KameLionStack Tool Orchestrator
Orchestrates all pentesting tools: Nmap, Nuclei, SQLMap, Nikto, ffuf, gobuster, etc.
"""

import subprocess
import json
import time
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
import re
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ToolOrchestrator:
    """Orchestrates execution of all pentesting tools"""
    
    def __init__(self):
        self.results = {
            "nmap": None,
            "nuclei": None,
            "nikto": None,
            "ffuf": None,
            "gobuster": None,
            "sqlmap": None,
            "subfinder": None,
            "httpx": None,
        }
        
        # Tool paths
        self.tools = {
            "nmap": r"C:\Program Files (x86)\Nmap\nmap.exe",
            "nuclei": r"C:\Users\souha\go\bin\nuclei.exe",
            "sqlmap": r"C:\Python314\Scripts\sqlmap.exe",
            "perl": r"C:\Strawberry\perl\bin\perl.exe",
            "wsl": "wsl",
        }
        
        # WSL tools (run via wsl command)
        self.wsl_tools = ["nikto", "ffuf", "gobuster", "subfinder", "httpx"]
    
    def run_command(self, cmd: List[str], timeout: int = 300, use_wsl: bool = False) -> Dict[str, Any]:
        """Execute command and return results with proper error handling"""
        try:
            if use_wsl:
                cmd = ["wsl"] + cmd
            
            logger.info(f"Executing: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if not use_wsl else 0
            )
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s")
            return {"success": False, "error": "timeout", "timeout": timeout}
        except FileNotFoundError as e:
            logger.error(f"Tool not found: {e}")
            return {"success": False, "error": "tool_not_found", "details": str(e)}
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return {"success": False, "error": str(e)}
    
    def nmap_scan(self, target: str, scan_type: str = "quick") -> Dict[str, Any]:
        """
        Run Nmap scan
        Scan types: quick, full, vuln, all_ports
        """
        logger.info(f"[NMAP] Starting {scan_type} scan on {target}")
        
        # Parse target to get hostname
        parsed = urlparse(target if "://" in target else f"http://{target}")
        hostname = parsed.hostname or target
        
        # Define scan profiles
        scan_profiles = {
            "quick": ["-sV", "-T4", "-F"],  # Fast version detection
            "full": ["-sV", "-sC", "-T4", "-p-"],  # Full port scan with scripts
            "vuln": ["-sV", "--script=vuln", "-T4"],  # Vulnerability scripts
            "all_ports": ["-p-", "-T4"],  # All 65535 ports
        }
        
        cmd = [self.tools["nmap"]] + scan_profiles.get(scan_type, scan_profiles["quick"])
        cmd.extend(["-oX", "-", hostname])  # XML output to stdout
        
        result = self.run_command(cmd, timeout=600)
        
        if result["success"]:
            self.results["nmap"] = self.parse_nmap_output(result["stdout"])
            logger.info(f"[NMAP] Found {len(self.results['nmap'].get('ports', []))} open ports")
        
        return self.results["nmap"] or {}
    
    def parse_nmap_output(self, xml_output: str) -> Dict[str, Any]:
        """Parse Nmap XML output"""
        findings = {
            "ports": [],
            "services": [],
            "os": None,
            "vulnerabilities": []
        }
        
        # Basic regex parsing (better than nothing without xml library)
        port_pattern = r'portid="(\d+)".*?service name="(.*?)".*?product="(.*?)"'
        ports = re.findall(port_pattern, xml_output, re.DOTALL)
        
        for port, service, product in ports:
            findings["ports"].append({
                "port": port,
                "service": service,
                "product": product
            })
        
        # Extract vulnerabilities if vuln scan
        if "script id=" in xml_output:
            vuln_pattern = r'script id="(.*?)".*?output="(.*?)"'
            vulns = re.findall(vuln_pattern, xml_output, re.DOTALL)
            findings["vulnerabilities"] = [{"script": v[0], "output": v[1][:200]} for v in vulns]
        
        return findings
    
    def nuclei_scan(self, target: str, templates: str = "cves,vulnerabilities") -> Dict[str, Any]:
        """
        Run Nuclei scan with templates
        Templates: cves, vulnerabilities, exposures, misconfigurations, default-logins
        """
        logger.info(f"[NUCLEI] Scanning {target} with templates: {templates}")
        
        cmd = [
            self.tools["nuclei"],
            "-u", target,
            "-t", templates,
            "-json",
            "-silent"
        ]
        
        result = self.run_command(cmd, timeout=300)
        
        if result["success"]:
            self.results["nuclei"] = self.parse_nuclei_output(result["stdout"])
            logger.info(f"[NUCLEI] Found {len(self.results['nuclei'].get('findings', []))} issues")
        
        return self.results["nuclei"] or {}
    
    def parse_nuclei_output(self, json_lines: str) -> Dict[str, Any]:
        """Parse Nuclei JSON output"""
        findings = {"findings": [], "severity_count": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
        
        for line in json_lines.strip().split('\n'):
            if not line:
                continue
            try:
                result = json.loads(line)
                severity = result.get("info", {}).get("severity", "info").lower()
                
                findings["findings"].append({
                    "template": result.get("template-id"),
                    "name": result.get("info", {}).get("name"),
                    "severity": severity,
                    "matched_at": result.get("matched-at"),
                    "description": result.get("info", {}).get("description", "")[:200]
                })
                
                findings["severity_count"][severity] = findings["severity_count"].get(severity, 0) + 1
            except json.JSONDecodeError:
                continue
        
        return findings
    
    def nikto_scan(self, target: str) -> Dict[str, Any]:
        """Run Nikto web server scanner via WSL"""
        logger.info(f"[NIKTO] Scanning {target}")
        
        cmd = ["nikto", "-h", target, "-Format", "json", "-output", "-"]
        result = self.run_command(cmd, timeout=300, use_wsl=True)
        
        if result["success"]:
            self.results["nikto"] = self.parse_nikto_output(result["stdout"])
            logger.info(f"[NIKTO] Found {len(self.results['nikto'].get('vulnerabilities', []))} issues")
        
        return self.results["nikto"] or {}
    
    def parse_nikto_output(self, output: str) -> Dict[str, Any]:
        """Parse Nikto output"""
        vulnerabilities = []
        
        # Nikto outputs OSVDB references and descriptions
        for line in output.split('\n'):
            if "OSVDB" in line or "Retrieved" in line:
                vulnerabilities.append({"description": line.strip()[:200]})
        
        return {"vulnerabilities": vulnerabilities, "count": len(vulnerabilities)}
    
    def ffuf_scan(self, target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> Dict[str, Any]:
        """Run ffuf directory fuzzer via WSL"""
        logger.info(f"[FFUF] Fuzzing directories on {target}")
        
        # Ensure target has FUZZ keyword
        if "FUZZ" not in target:
            target = target.rstrip('/') + "/FUZZ"
        
        cmd = [
            "ffuf",
            "-u", target,
            "-w", wordlist,
            "-mc", "200,301,302,401,403",
            "-o", "-",
            "-of", "json",
            "-t", "50"
        ]
        
        result = self.run_command(cmd, timeout=180, use_wsl=True)
        
        if result["success"]:
            self.results["ffuf"] = self.parse_ffuf_output(result["stdout"])
            logger.info(f"[FFUF] Found {len(self.results['ffuf'].get('results', []))} paths")
        
        return self.results["ffuf"] or {}
    
    def parse_ffuf_output(self, json_output: str) -> Dict[str, Any]:
        """Parse ffuf JSON output"""
        try:
            data = json.loads(json_output)
            results = []
            
            for item in data.get("results", []):
                results.append({
                    "url": item.get("url"),
                    "status": item.get("status"),
                    "length": item.get("length"),
                    "words": item.get("words")
                })
            
            return {"results": results, "count": len(results)}
        except json.JSONDecodeError:
            return {"results": [], "count": 0}
    
    def gobuster_scan(self, target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> Dict[str, Any]:
        """Run Gobuster directory brute-force via WSL"""
        logger.info(f"[GOBUSTER] Brute-forcing directories on {target}")
        
        cmd = [
            "gobuster", "dir",
            "-u", target,
            "-w", wordlist,
            "-q",
            "-o", "-"
        ]
        
        result = self.run_command(cmd, timeout=180, use_wsl=True)
        
        if result["success"]:
            self.results["gobuster"] = self.parse_gobuster_output(result["stdout"])
            logger.info(f"[GOBUSTER] Found {len(self.results['gobuster'].get('directories', []))} paths")
        
        return self.results["gobuster"] or {}
    
    def parse_gobuster_output(self, output: str) -> Dict[str, Any]:
        """Parse Gobuster output"""
        directories = []
        
        for line in output.split('\n'):
            if line.startswith('/'):
                parts = line.split()
                if len(parts) >= 2:
                    directories.append({
                        "path": parts[0],
                        "status": parts[1].strip('()')
                    })
        
        return {"directories": directories, "count": len(directories)}
    
    def sqlmap_scan(self, target: str, params: List[str] = None) -> Dict[str, Any]:
        """Run SQLMap for SQL injection testing"""
        logger.info(f"[SQLMAP] Testing SQL injection on {target}")
        
        cmd = [
            self.tools["sqlmap"],
            "-u", target,
            "--batch",
            "--risk=2",
            "--level=2",
            "--technique=BEUSTQ",
            "--output-dir=sqlmap_output",
            "--format=JSON"
        ]
        
        if params:
            cmd.extend(["-p", ",".join(params)])
        
        result = self.run_command(cmd, timeout=300)
        
        if result["success"]:
            self.results["sqlmap"] = self.parse_sqlmap_output(result["stdout"])
            logger.info(f"[SQLMAP] Found {self.results['sqlmap'].get('injectable', 0)} injectable parameters")
        
        return self.results["sqlmap"] or {}
    
    def parse_sqlmap_output(self, output: str) -> Dict[str, Any]:
        """Parse SQLMap output"""
        findings = {"injectable": 0, "parameters": [], "databases": []}
        
        # Look for injection points
        if "Parameter:" in output and "is vulnerable" in output:
            findings["injectable"] += 1
            
            # Extract parameter names
            param_pattern = r"Parameter: (.*?) \(.*?\)"
            params = re.findall(param_pattern, output)
            findings["parameters"] = list(set(params))
        
        # Extract database info if found
        if "available databases" in output.lower():
            db_pattern = r"\[.*?\] (.*?)$"
            dbs = re.findall(db_pattern, output, re.MULTILINE)
            findings["databases"] = dbs[:10]  # Limit to first 10
        
        return findings
    
    def subfinder_scan(self, domain: str) -> Dict[str, Any]:
        """Run Subfinder for subdomain discovery via WSL"""
        logger.info(f"[SUBFINDER] Finding subdomains for {domain}")
        
        # Extract domain from URL if needed
        parsed = urlparse(domain if "://" in domain else f"http://{domain}")
        domain = parsed.hostname or domain
        
        cmd = ["subfinder", "-d", domain, "-silent", "-json"]
        result = self.run_command(cmd, timeout=120, use_wsl=True)
        
        if result["success"]:
            self.results["subfinder"] = self.parse_subfinder_output(result["stdout"])
            logger.info(f"[SUBFINDER] Found {len(self.results['subfinder'].get('subdomains', []))} subdomains")
        
        return self.results["subfinder"] or {}
    
    def parse_subfinder_output(self, json_lines: str) -> Dict[str, Any]:
        """Parse Subfinder JSON output"""
        subdomains = []
        
        for line in json_lines.strip().split('\n'):
            if not line:
                continue
            try:
                data = json.loads(line)
                subdomains.append(data.get("host", ""))
            except json.JSONDecodeError:
                continue
        
        return {"subdomains": list(set(subdomains)), "count": len(subdomains)}
    
    def httpx_scan(self, targets: List[str]) -> Dict[str, Any]:
        """Run httpx to probe live hosts via WSL"""
        logger.info(f"[HTTPX] Probing {len(targets)} targets")
        
        # Create temp file with targets
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(targets))
            temp_file = f.name
        
        cmd = ["httpx", "-l", temp_file, "-silent", "-json"]
        result = self.run_command(cmd, timeout=180, use_wsl=True)
        
        # Cleanup
        Path(temp_file).unlink(missing_ok=True)
        
        if result["success"]:
            self.results["httpx"] = self.parse_httpx_output(result["stdout"])
            logger.info(f"[HTTPX] Found {len(self.results['httpx'].get('live_hosts', []))} live hosts")
        
        return self.results["httpx"] or {}
    
    def parse_httpx_output(self, json_lines: str) -> Dict[str, Any]:
        """Parse httpx JSON output"""
        live_hosts = []
        
        for line in json_lines.strip().split('\n'):
            if not line:
                continue
            try:
                data = json.loads(line)
                live_hosts.append({
                    "url": data.get("url"),
                    "status_code": data.get("status_code"),
                    "title": data.get("title", ""),
                    "tech": data.get("tech", [])
                })
            except json.JSONDecodeError:
                continue
        
        return {"live_hosts": live_hosts, "count": len(live_hosts)}
    
    def get_all_results(self) -> Dict[str, Any]:
        """Get combined results from all tools"""
        return {
            "tools": self.results,
            "summary": self.generate_summary()
        }
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary of all findings"""
        summary = {
            "total_vulnerabilities": 0,
            "critical_issues": 0,
            "high_issues": 0,
            "open_ports": 0,
            "directories_found": 0,
            "subdomains_found": 0,
        }
        
        # Count from Nmap
        if self.results["nmap"]:
            summary["open_ports"] = len(self.results["nmap"].get("ports", []))
        
        # Count from Nuclei
        if self.results["nuclei"]:
            severity = self.results["nuclei"].get("severity_count", {})
            summary["critical_issues"] = severity.get("critical", 0)
            summary["high_issues"] = severity.get("high", 0)
            summary["total_vulnerabilities"] += len(self.results["nuclei"].get("findings", []))
        
        # Count from Nikto
        if self.results["nikto"]:
            summary["total_vulnerabilities"] += len(self.results["nikto"].get("vulnerabilities", []))
        
        # Count directories
        if self.results["ffuf"]:
            summary["directories_found"] += self.results["ffuf"].get("count", 0)
        if self.results["gobuster"]:
            summary["directories_found"] += self.results["gobuster"].get("count", 0)
        
        # Count subdomains
        if self.results["subfinder"]:
            summary["subdomains_found"] = self.results["subfinder"].get("count", 0)
        
        return summary


# Testing function
if __name__ == "__main__":
    orchestrator = ToolOrchestrator()
    
    # Test on httpbin.org
    target = "http://httpbin.org"
    
    print("=== Testing Tool Orchestrator ===")
    print(f"Target: {target}\n")
    
    # Run basic scans
    print("[1/3] Running Nmap quick scan...")
    nmap_results = orchestrator.nmap_scan(target, "quick")
    print(f"✓ Nmap: Found {len(nmap_results.get('ports', []))} ports\n")
    
    print("[2/3] Running Nuclei scan...")
    nuclei_results = orchestrator.nuclei_scan(target, "cves")
    print(f"✓ Nuclei: Found {len(nuclei_results.get('findings', []))} issues\n")
    
    print("[3/3] Running Subfinder...")
    subfinder_results = orchestrator.subfinder_scan("httpbin.org")
    print(f"✓ Subfinder: Found {subfinder_results.get('count', 0)} subdomains\n")
    
    # Get summary
    summary = orchestrator.generate_summary()
    print("=== Summary ===")
    print(json.dumps(summary, indent=2))
