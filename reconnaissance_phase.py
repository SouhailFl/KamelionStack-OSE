"""
KameLionStack Reconnaissance Phase
Complete information gathering before exploitation
"""

import logging
from typing import Dict, List, Any
from urllib.parse import urlparse
from tool_orchestrator import ToolOrchestrator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReconnaissanceEngine:
    """Complete reconnaissance workflow"""
    
    def __init__(self):
        self.orchestrator = ToolOrchestrator()
        self.recon_data = {
            "target_info": {},
            "network_map": {},
            "web_discovery": {},
            "subdomains": {},
            "technologies": {},
            "attack_surface": []
        }
    
    def run_full_reconnaissance(self, target: str, mode: str = "standard") -> Dict[str, Any]:
        """
        Run complete reconnaissance workflow
        Modes: quick, standard, deep
        """
        logger.info(f"🔍 Starting {mode} reconnaissance on {target}")
        
        # Parse target
        parsed = urlparse(target if "://" in target else f"http://{target}")
        domain = parsed.hostname or target
        
        if mode == "quick":
            return self._quick_recon(target, domain)
        elif mode == "deep":
            return self._deep_recon(target, domain)
        else:
            return self._standard_recon(target, domain)
    
    def _quick_recon(self, target: str, domain: str) -> Dict[str, Any]:
        """Quick reconnaissance (2-3 minutes)"""
        logger.info("⚡ Quick recon mode")
        
        # Phase 1: Port scan (quick)
        logger.info("Phase 1/3: Quick port scan")
        nmap_data = self.orchestrator.nmap_scan(target, "quick")
        self.recon_data["network_map"] = nmap_data
        
        # Phase 2: Subdomain enum
        logger.info("Phase 2/3: Subdomain discovery")
        subdomain_data = self.orchestrator.subfinder_scan(domain)
        self.recon_data["subdomains"] = subdomain_data
        
        # Phase 3: Quick directory scan
        logger.info("Phase 3/3: Quick directory scan")
        ffuf_data = self.orchestrator.ffuf_scan(target)
        self.recon_data["web_discovery"] = ffuf_data
        
        return self._compile_results()
    
    def _standard_recon(self, target: str, domain: str) -> Dict[str, Any]:
        """Standard reconnaissance (5-10 minutes)"""
        logger.info("🎯 Standard recon mode")
        
        # Phase 1: Network mapping
        logger.info("Phase 1/5: Network mapping")
        nmap_data = self.orchestrator.nmap_scan(target, "full")
        self.recon_data["network_map"] = nmap_data
        
        # Phase 2: Subdomain discovery
        logger.info("Phase 2/5: Subdomain enumeration")
        subdomain_data = self.orchestrator.subfinder_scan(domain)
        self.recon_data["subdomains"] = subdomain_data
        
        # Phase 3: Live host probing
        logger.info("Phase 3/5: Probing live hosts")
        if subdomain_data.get("subdomains"):
            httpx_data = self.orchestrator.httpx_scan(subdomain_data["subdomains"][:20])
            self.recon_data["technologies"] = httpx_data
        
        # Phase 4: Directory fuzzing
        logger.info("Phase 4/5: Directory discovery")
        ffuf_data = self.orchestrator.ffuf_scan(target)
        gobuster_data = self.orchestrator.gobuster_scan(target)
        self.recon_data["web_discovery"] = {
            "ffuf": ffuf_data,
            "gobuster": gobuster_data
        }
        
        # Phase 5: Web server scanning
        logger.info("Phase 5/5: Web server analysis")
        nikto_data = self.orchestrator.nikto_scan(target)
        self.recon_data["web_server"] = nikto_data
        
        return self._compile_results()
    
    def _deep_recon(self, target: str, domain: str) -> Dict[str, Any]:
        """Deep reconnaissance (15-20 minutes)"""
        logger.info("🔬 Deep recon mode")
        
        # Phase 1: Complete port scan
        logger.info("Phase 1/7: Complete port scan (all 65535 ports)")
        nmap_full = self.orchestrator.nmap_scan(target, "all_ports")
        nmap_vuln = self.orchestrator.nmap_scan(target, "vuln")
        self.recon_data["network_map"] = {
            "full_scan": nmap_full,
            "vuln_scan": nmap_vuln
        }
        
        # Phase 2: Subdomain discovery
        logger.info("Phase 2/7: Extensive subdomain enumeration")
        subdomain_data = self.orchestrator.subfinder_scan(domain)
        self.recon_data["subdomains"] = subdomain_data
        
        # Phase 3: Live host probing
        logger.info("Phase 3/7: Probing all discovered hosts")
        if subdomain_data.get("subdomains"):
            httpx_data = self.orchestrator.httpx_scan(subdomain_data["subdomains"])
            self.recon_data["technologies"] = httpx_data
        
        # Phase 4: Nuclei vulnerability scan
        logger.info("Phase 4/7: Nuclei template scanning")
        nuclei_data = self.orchestrator.nuclei_scan(target, "cves,vulnerabilities,exposures,misconfigurations")
        self.recon_data["nuclei"] = nuclei_data
        
        # Phase 5: Directory brute-forcing
        logger.info("Phase 5/7: Extensive directory discovery")
        ffuf_data = self.orchestrator.ffuf_scan(target)
        gobuster_data = self.orchestrator.gobuster_scan(target)
        self.recon_data["web_discovery"] = {
            "ffuf": ffuf_data,
            "gobuster": gobuster_data
        }
        
        # Phase 6: Web server scanning
        logger.info("Phase 6/7: Deep web server analysis")
        nikto_data = self.orchestrator.nikto_scan(target)
        self.recon_data["web_server"] = nikto_data
        
        # Phase 7: SQL injection testing
        logger.info("Phase 7/7: Automated SQL injection testing")
        discovered_pages = self._extract_pages_from_discovery()
        for page in discovered_pages[:5]:  # Test top 5 pages
            sqlmap_data = self.orchestrator.sqlmap_scan(page)
            if sqlmap_data.get("injectable", 0) > 0:
                if "sqlmap" not in self.recon_data:
                    self.recon_data["sqlmap"] = []
                self.recon_data["sqlmap"].append(sqlmap_data)
        
        return self._compile_results()
    
    def _extract_pages_from_discovery(self) -> List[str]:
        """Extract discovered pages for further testing"""
        pages = []
        
        web_disco = self.recon_data.get("web_discovery", {})
        
        # From ffuf
        if "ffuf" in web_disco:
            for result in web_disco["ffuf"].get("results", []):
                if result.get("url"):
                    pages.append(result["url"])
        
        # From gobuster
        if "gobuster" in web_disco:
            for result in web_disco["gobuster"].get("directories", []):
                if result.get("path"):
                    pages.append(result["path"])
        
        return pages
    
    def _compile_results(self) -> Dict[str, Any]:
        """Compile reconnaissance results with attack surface analysis"""
        
        attack_surface = self._analyze_attack_surface()
        
        return {
            "reconnaissance": self.recon_data,
            "attack_surface": attack_surface,
            "summary": self._generate_summary()
        }
    
    def _analyze_attack_surface(self) -> Dict[str, Any]:
        """Analyze attack surface based on recon data"""
        attack_surface = {
            "open_ports": [],
            "exposed_services": [],
            "vulnerable_endpoints": [],
            "interesting_paths": [],
            "subdomains": [],
            "priority_targets": []
        }
        
        # Open ports
        network = self.recon_data.get("network_map", {})
        if isinstance(network, dict) and "ports" in network:
            attack_surface["open_ports"] = network["ports"]
        elif isinstance(network, dict) and "full_scan" in network:
            attack_surface["open_ports"] = network["full_scan"].get("ports", [])
        
        # Exposed services
        for port_info in attack_surface["open_ports"]:
            service = port_info.get("service", "unknown")
            if service in ["http", "https", "ssh", "ftp", "mysql", "postgresql", "mongodb", "redis"]:
                attack_surface["exposed_services"].append({
                    "port": port_info.get("port"),
                    "service": service,
                    "product": port_info.get("product", "unknown")
                })
        
        # Vulnerable endpoints from Nuclei
        nuclei = self.recon_data.get("nuclei", {})
        if nuclei and "findings" in nuclei:
            for finding in nuclei["findings"]:
                if finding.get("severity") in ["critical", "high"]:
                    attack_surface["vulnerable_endpoints"].append({
                        "name": finding.get("name"),
                        "severity": finding.get("severity"),
                        "template": finding.get("template")
                    })
        
        # Interesting paths
        web_disco = self.recon_data.get("web_discovery", {})
        interesting_keywords = ["admin", "api", "backup", "config", "dashboard", "login", "panel", "phpmyadmin"]
        
        for tool_name in ["ffuf", "gobuster"]:
            if tool_name in web_disco:
                results = web_disco[tool_name].get("results" if tool_name == "ffuf" else "directories", [])
                for item in results:
                    path = item.get("url" if tool_name == "ffuf" else "path", "")
                    if any(keyword in path.lower() for keyword in interesting_keywords):
                        attack_surface["interesting_paths"].append(path)
        
        # Subdomains
        subs = self.recon_data.get("subdomains", {})
        if subs and "subdomains" in subs:
            attack_surface["subdomains"] = subs["subdomains"][:10]  # Top 10
        
        # Priority targets (high-value findings)
        priority_targets = []
        
        # Admin panels
        for path in attack_surface["interesting_paths"]:
            if "admin" in path.lower() or "login" in path.lower():
                priority_targets.append({"type": "admin_panel", "target": path, "priority": "HIGH"})
        
        # Critical vulnerabilities
        for vuln in attack_surface["vulnerable_endpoints"]:
            if vuln.get("severity") == "critical":
                priority_targets.append({"type": "critical_vuln", "target": vuln.get("name"), "priority": "CRITICAL"})
        
        # Database services exposed
        for service in attack_surface["exposed_services"]:
            if service.get("service") in ["mysql", "postgresql", "mongodb", "redis"]:
                priority_targets.append({"type": "database_exposed", "target": f"{service.get('service')}:{service.get('port')}", "priority": "HIGH"})
        
        attack_surface["priority_targets"] = priority_targets
        
        return attack_surface
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate reconnaissance summary"""
        summary = {
            "open_ports": 0,
            "services_found": 0,
            "subdomains_found": 0,
            "directories_found": 0,
            "vulnerabilities_found": 0,
            "critical_findings": 0,
            "high_findings": 0
        }
        
        # Count open ports
        network = self.recon_data.get("network_map", {})
        if isinstance(network, dict) and "ports" in network:
            summary["open_ports"] = len(network["ports"])
        elif isinstance(network, dict) and "full_scan" in network:
            summary["open_ports"] = len(network.get("full_scan", {}).get("ports", []))
        
        # Count services
        summary["services_found"] = summary["open_ports"]
        
        # Count subdomains
        subs = self.recon_data.get("subdomains", {})
        summary["subdomains_found"] = subs.get("count", 0)
        
        # Count directories
        web_disco = self.recon_data.get("web_discovery", {})
        if "ffuf" in web_disco:
            summary["directories_found"] += web_disco["ffuf"].get("count", 0)
        if "gobuster" in web_disco:
            summary["directories_found"] += web_disco["gobuster"].get("count", 0)
        
        # Count vulnerabilities
        nuclei = self.recon_data.get("nuclei", {})
        if nuclei:
            severity = nuclei.get("severity_count", {})
            summary["critical_findings"] = severity.get("critical", 0)
            summary["high_findings"] = severity.get("high", 0)
            summary["vulnerabilities_found"] = len(nuclei.get("findings", []))
        
        return summary


# Testing function
if __name__ == "__main__":
    recon = ReconnaissanceEngine()
    
    target = "http://httpbin.org"
    
    print("=== Testing Reconnaissance Engine ===")
    print(f"Target: {target}\n")
    
    # Run quick recon
    print("Running QUICK reconnaissance...\n")
    results = recon.run_full_reconnaissance(target, mode="quick")
    
    print("\n=== Reconnaissance Complete ===")
    print(f"Summary: {results['summary']}")
    print(f"\nAttack Surface: {len(results['attack_surface']['priority_targets'])} priority targets")
