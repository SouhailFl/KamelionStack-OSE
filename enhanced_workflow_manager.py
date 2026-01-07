"""
KameLionStack Enhanced AI Workflow Manager
Integrates tool orchestration + reconnaissance + existing scanners + AI analysis
"""

import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

# Import existing modules
from active_scanner import ActiveScanner
from session_scanner import SessionScanner
from advanced_vuln_scanner import AdvancedVulnerabilityScanner
from waf_bypass import WAFBypass
from exploit_generator import ExploitGenerator
from ollama_integration import analyze_vulnerabilities

# Import new modules
from tool_orchestrator import ToolOrchestrator
from reconnaissance_phase import ReconnaissanceEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EnhancedWorkflowManager:
    """
    Complete pentesting workflow:
    1. Reconnaissance Phase (new)
    2. Active Scanning (existing)
    3. Session Testing (existing)
    4. Advanced Scanning (existing)
    5. Tool-based Testing (new)
    6. AI Analysis & Exploit Generation (existing + enhanced)
    """
    
    def __init__(self):
        self.orchestrator = ToolOrchestrator()
        self.recon_engine = ReconnaissanceEngine()
        self.active_scanner = ActiveScanner()
        self.session_scanner = SessionScanner()
        self.advanced_scanner = AdvancedVulnerabilityScanner()
        self.waf_bypass = WAFBypass()
        self.exploit_generator = ExploitGenerator()
        self.results = {
            "recon": None,
            "active_scan": None,
            "session_scan": None,
            "advanced_scan": None,
            "tool_results": None,
            "waf_detection": None,
            "ai_analysis": None,
            "exploits": []
        }
        self.start_time = None
        self.end_time = None
    
    def run_complete_pentest(
        self,
        target: str,
        recon_mode: str = "standard",
        max_iterations: int = 10,
        use_tools: bool = True,
        tool_mode: str = "standard"
    ) -> Dict[str, Any]:
        """
        Run complete pentesting workflow
        
        Args:
            target: Target URL/domain
            recon_mode: quick/standard/deep
            max_iterations: Max AI iterations
            use_tools: Whether to use external tools
            tool_mode: Tool execution mode (quick/standard/full)
        """
        self.start_time = time.time()
        logger.info(f"🦎 Starting COMPLETE pentest on {target}")
        
        try:
            # PHASE 1: RECONNAISSANCE (NEW)
            logger.info("="*60)
            logger.info("PHASE 1: RECONNAISSANCE")
            logger.info("="*60)
            if use_tools:
                recon_results = self._phase_reconnaissance(target, recon_mode)
                self.results["recon"] = recon_results
            else:
                logger.info("⏭️  Skipping reconnaissance (use_tools=False)")
            
            # PHASE 2: ACTIVE SCANNING
            logger.info("="*60)
            logger.info("PHASE 2: ACTIVE SCANNING")
            logger.info("="*60)
            active_results = self._phase_active_scan(target)
            self.results["active_scan"] = active_results
            
            # PHASE 3: SESSION SECURITY
            logger.info("="*60)
            logger.info("PHASE 3: SESSION SECURITY TESTING")
            logger.info("="*60)
            session_results = self._phase_session_scan(target)
            self.results["session_scan"] = session_results
            
            # PHASE 4: ADVANCED VULNERABILITIES
            logger.info("="*60)
            logger.info("PHASE 4: ADVANCED VULNERABILITY SCANNING")
            logger.info("="*60)
            advanced_results = self._phase_advanced_scan(target)
            self.results["advanced_scan"] = advanced_results
            
            # PHASE 5: TOOL-BASED TESTING (NEW)
            logger.info("="*60)
            logger.info("PHASE 5: TOOL-BASED SCANNING")
            logger.info("="*60)
            if use_tools and tool_mode != "none":
                tool_results = self._phase_tool_scanning(target, tool_mode, recon_results if use_tools else None)
                self.results["tool_results"] = tool_results
            else:
                logger.info("⏭️  Skipping tool-based scanning")
            
            # PHASE 6: WAF DETECTION
            logger.info("="*60)
            logger.info("PHASE 6: WAF DETECTION & BYPASS")
            logger.info("="*60)
            waf_results = self._phase_waf_detection(target)
            self.results["waf_detection"] = waf_results
            
            # PHASE 7: AI ANALYSIS & EXPLOIT GENERATION
            logger.info("="*60)
            logger.info("PHASE 7: AI ANALYSIS & EXPLOIT GENERATION")
            logger.info("="*60)
            ai_results = self._phase_ai_analysis(target, max_iterations)
            self.results["ai_analysis"] = ai_results
            
            self.end_time = time.time()
            
            return self._compile_final_report()
            
        except Exception as e:
            logger.error(f"❌ Workflow error: {e}")
            self.end_time = time.time()
            return self._compile_final_report(error=str(e))
    
    def _phase_reconnaissance(self, target: str, mode: str) -> Dict[str, Any]:
        """Phase 1: Complete reconnaissance"""
        logger.info(f"🔍 Running {mode} reconnaissance...")
        
        try:
            recon_data = self.recon_engine.run_full_reconnaissance(target, mode)
            
            # Log summary
            summary = recon_data.get("summary", {})
            logger.info(f"✓ Reconnaissance complete:")
            logger.info(f"  - Open ports: {summary.get('open_ports', 0)}")
            logger.info(f"  - Subdomains: {summary.get('subdomains_found', 0)}")
            logger.info(f"  - Directories: {summary.get('directories_found', 0)}")
            logger.info(f"  - Vulnerabilities: {summary.get('vulnerabilities_found', 0)}")
            
            # Log priority targets
            attack_surface = recon_data.get("attack_surface", {})
            priority_targets = attack_surface.get("priority_targets", [])
            if priority_targets:
                logger.info(f"🎯 Found {len(priority_targets)} priority targets:")
                for target in priority_targets[:5]:
                    logger.info(f"  - [{target.get('priority')}] {target.get('type')}: {target.get('target')}")
            
            return recon_data
            
        except Exception as e:
            logger.error(f"Reconnaissance phase error: {e}")
            return {"error": str(e)}
    
    def _phase_active_scan(self, target: str) -> Dict[str, Any]:
        """Phase 2: Active vulnerability scanning"""
        logger.info("🔍 Running active scan (SQL/XSS/LFI)...")
        
        try:
            scan_results = self.active_scanner.scan_target(target)
            formatted = self.active_scanner.format_results(scan_results)
            vuln_count = len(formatted)
            logger.info(f"✓ Active scan complete: {vuln_count} vulnerabilities found")
            return {"vulnerabilities": formatted, "raw_results": scan_results}
        except Exception as e:
            logger.error(f"Active scan error: {e}")
            return {"error": str(e), "vulnerabilities": []}
    
    def _phase_session_scan(self, target: str) -> Dict[str, Any]:
        """Phase 3: Session security testing"""
        logger.info("🔐 Running session security tests...")
        
        try:
            scan_results = self.session_scanner.scan_target(target)
            formatted = self.session_scanner.format_results(scan_results)
            vuln_count = len(formatted)
            logger.info(f"✓ Session scan complete: {vuln_count} issues found")
            return {"vulnerabilities": formatted, "raw_results": scan_results}
        except Exception as e:
            logger.error(f"Session scan error: {e}")
            return {"error": str(e), "vulnerabilities": []}
    
    def _phase_advanced_scan(self, target: str) -> Dict[str, Any]:
        """Phase 4: Advanced vulnerability scanning"""
        logger.info("💥 Running advanced vulnerability tests...")
        
        try:
            scan_results = self.advanced_scanner.scan_target(target)
            formatted = self.advanced_scanner.format_results(scan_results)
            vuln_count = len(formatted)
            logger.info(f"✓ Advanced scan complete: {vuln_count} vulnerabilities found")
            return {"vulnerabilities": formatted, "raw_results": scan_results}
        except Exception as e:
            logger.error(f"Advanced scan error: {e}")
            return {"error": str(e), "vulnerabilities": []}
    
    def _phase_tool_scanning(self, target: str, mode: str, recon_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Phase 5: Tool-based scanning"""
        logger.info(f"🛠️  Running tool-based scanning ({mode} mode)...")
        
        tool_results = {}
        
        try:
            if mode == "quick":
                # Quick mode: Just Nuclei
                logger.info("Running Nuclei CVE scan...")
                tool_results["nuclei"] = self.orchestrator.nuclei_scan(target, "cves")
                
            elif mode == "standard":
                # Standard mode: Nuclei + SQLMap on discovered pages
                logger.info("Running Nuclei vulnerability scan...")
                tool_results["nuclei"] = self.orchestrator.nuclei_scan(target, "cves,vulnerabilities")
                
                # Extract interesting URLs from recon
                if recon_data:
                    interesting_urls = self._extract_interesting_urls(recon_data, target)
                    if interesting_urls:
                        logger.info(f"Running SQLMap on {len(interesting_urls)} pages...")
                        sqlmap_results = []
                        for url in interesting_urls[:3]:  # Test top 3
                            result = self.orchestrator.sqlmap_scan(url)
                            if result.get("injectable", 0) > 0:
                                sqlmap_results.append(result)
                        tool_results["sqlmap"] = sqlmap_results
                
            elif mode == "full":
                # Full mode: All tools
                logger.info("Running Nuclei with all templates...")
                tool_results["nuclei"] = self.orchestrator.nuclei_scan(
                    target, 
                    "cves,vulnerabilities,exposures,misconfigurations,default-logins"
                )
                
                logger.info("Running Nikto web server scan...")
                tool_results["nikto"] = self.orchestrator.nikto_scan(target)
                
                # SQLMap on discovered pages
                if recon_data:
                    interesting_urls = self._extract_interesting_urls(recon_data, target)
                    if interesting_urls:
                        logger.info(f"Running SQLMap on {len(interesting_urls)} pages...")
                        sqlmap_results = []
                        for url in interesting_urls[:5]:  # Test top 5
                            result = self.orchestrator.sqlmap_scan(url)
                            if result.get("injectable", 0) > 0:
                                sqlmap_results.append(result)
                        tool_results["sqlmap"] = sqlmap_results
            
            # Log results
            total_findings = 0
            if "nuclei" in tool_results:
                count = len(tool_results["nuclei"].get("findings", []))
                total_findings += count
                logger.info(f"  ✓ Nuclei: {count} findings")
            
            if "sqlmap" in tool_results:
                injectable = sum(r.get("injectable", 0) for r in tool_results["sqlmap"])
                total_findings += injectable
                logger.info(f"  ✓ SQLMap: {injectable} injectable parameters")
            
            if "nikto" in tool_results:
                count = len(tool_results["nikto"].get("vulnerabilities", []))
                total_findings += count
                logger.info(f"  ✓ Nikto: {count} findings")
            
            logger.info(f"✓ Tool scanning complete: {total_findings} total findings")
            
            return tool_results
            
        except Exception as e:
            logger.error(f"Tool scanning error: {e}")
            return {"error": str(e)}
    
    def _extract_interesting_urls(self, recon_data: Dict, base_target: str) -> List[str]:
        """Extract interesting URLs from reconnaissance data"""
        urls = []
        
        # From attack surface
        attack_surface = recon_data.get("attack_surface", {})
        interesting_paths = attack_surface.get("interesting_paths", [])
        
        # Convert paths to full URLs
        for path in interesting_paths[:10]:  # Top 10
            if path.startswith("http"):
                urls.append(path)
            else:
                urls.append(f"{base_target.rstrip('/')}/{path.lstrip('/')}")
        
        return urls
    
    def _phase_waf_detection(self, target: str) -> Dict[str, Any]:
        """Phase 6: WAF detection"""
        logger.info("🛡️  Detecting WAF/security protections...")
        
        try:
            results = self.waf_bypass.detect_waf(target)
            if results.get("waf_detected"):
                logger.info(f"⚠️  WAF detected: {results.get('waf_type', 'Unknown')}")
            else:
                logger.info("✓ No WAF detected")
            return results
        except Exception as e:
            logger.error(f"WAF detection error: {e}")
            return {"error": str(e), "waf_detected": False}
    
    def _phase_ai_analysis(self, target: str, max_iterations: int) -> Dict[str, Any]:
        """Phase 7: AI analysis and exploit generation"""
        logger.info(f"🤖 Running AI analysis ({max_iterations} iterations)...")
        
        try:
            # Collect all vulnerabilities
            all_vulns = self._collect_all_vulnerabilities()
            
            if not all_vulns:
                logger.info("ℹ️  No vulnerabilities to analyze")
                return {"message": "No vulnerabilities found", "exploits": []}
            
            logger.info(f"📊 Analyzing {len(all_vulns)} vulnerabilities...")
            
            # AI analysis
            ai_analysis = analyze_vulnerabilities(all_vulns, target)
            
            # Generate exploits for high-severity vulns
            exploits = []
            high_severity_vulns = [v for v in all_vulns if v.get("severity") in ["CRITICAL", "HIGH"]]
            
            logger.info(f"🔨 Generating exploits for {len(high_severity_vulns)} high-severity vulnerabilities...")
            for vuln in high_severity_vulns[:max_iterations]:
                # Convert vulnerability format for exploit generator
                vuln_type = vuln.get("type", "").lower()
                
                if "sql" in vuln_type:
                    scan_data = {"sql_injection": [{"url": vuln.get("url", ""), "param": vuln.get("parameter", "id"), "payload": vuln.get("payload", "")}]}
                elif "xss" in vuln_type:
                    scan_data = {"xss": [{"url": vuln.get("url", ""), "param": vuln.get("parameter", "q"), "payload": vuln.get("payload", "")}]}
                elif "lfi" in vuln_type or "file" in vuln_type:
                    scan_data = {"lfi": [{"url": vuln.get("url", ""), "param": vuln.get("parameter", "file"), "payload": vuln.get("payload", "")}]}
                else:
                    continue  # Skip unknown types
                
                exploit_list = self.exploit_generator.generate_exploits_from_scan(scan_data)
                if exploit_list:
                    exploits.extend(exploit_list)
            
            self.results["exploits"] = exploits
            
            logger.info(f"✓ AI analysis complete: {len(exploits)} exploits generated")
            
            return {
                "analysis": ai_analysis,
                "exploits": exploits,
                "vulnerabilities_analyzed": len(all_vulns),
                "exploits_generated": len(exploits)
            }
            
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return {"error": str(e), "exploits": []}
    
    def _collect_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Collect all vulnerabilities from all phases"""
        all_vulns = []
        
        # From active scan
        if self.results["active_scan"]:
            all_vulns.extend(self.results["active_scan"].get("vulnerabilities", []))
        
        # From session scan
        if self.results["session_scan"]:
            all_vulns.extend(self.results["session_scan"].get("vulnerabilities", []))
        
        # From advanced scan
        if self.results["advanced_scan"]:
            all_vulns.extend(self.results["advanced_scan"].get("vulnerabilities", []))
        
        # From tool results
        if self.results["tool_results"]:
            # Nuclei findings
            if "nuclei" in self.results["tool_results"]:
                for finding in self.results["tool_results"]["nuclei"].get("findings", []):
                    all_vulns.append({
                        "type": "Nuclei: " + finding.get("name", "Unknown"),
                        "severity": finding.get("severity", "INFO").upper(),
                        "url": finding.get("matched_at", ""),
                        "description": finding.get("description", "")
                    })
            
            # SQLMap findings
            if "sqlmap" in self.results["tool_results"]:
                for result in self.results["tool_results"]["sqlmap"]:
                    if result.get("injectable", 0) > 0:
                        all_vulns.append({
                            "type": "SQL Injection (SQLMap)",
                            "severity": "HIGH",
                            "parameters": result.get("parameters", []),
                            "databases": result.get("databases", [])
                        })
            
            # Nikto findings
            if "nikto" in self.results["tool_results"]:
                for vuln in self.results["tool_results"]["nikto"].get("vulnerabilities", []):
                    all_vulns.append({
                        "type": "Web Server Issue (Nikto)",
                        "severity": "MEDIUM",
                        "description": vuln.get("description", "")
                    })
        
        # From reconnaissance
        if self.results["recon"]:
            attack_surface = self.results["recon"].get("attack_surface", {})
            for vuln in attack_surface.get("vulnerable_endpoints", []):
                all_vulns.append({
                    "type": vuln.get("name", "Unknown"),
                    "severity": vuln.get("severity", "INFO").upper(),
                    "template": vuln.get("template", "")
                })
        
        return all_vulns
    
    def _compile_final_report(self, error: Optional[str] = None) -> Dict[str, Any]:
        """Compile final comprehensive report"""
        duration = (self.end_time - self.start_time) if self.end_time else 0
        
        # Count vulnerabilities by severity
        all_vulns = self._collect_all_vulnerabilities()
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for vuln in all_vulns:
            severity = vuln.get("severity", "INFO").upper()
            if severity in severity_count:
                severity_count[severity] += 1
        
        report = {
            "scan_info": {
                "start_time": datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else None,
                "end_time": datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else None,
                "duration_seconds": round(duration, 2),
                "scan_date": datetime.now().isoformat()
            },
            "summary": {
                "total_vulnerabilities": len(all_vulns),
                "exploits_generated": len(self.results.get("exploits", [])),
                "severity_breakdown": severity_count,
                "phases_completed": sum(1 for v in self.results.values() if v is not None)
            },
            "reconnaissance": self.results.get("recon"),
            "active_scan": self.results.get("active_scan"),
            "session_scan": self.results.get("session_scan"),
            "advanced_scan": self.results.get("advanced_scan"),
            "tool_results": self.results.get("tool_results"),
            "waf_detection": self.results.get("waf_detection"),
            "ai_analysis": self.results.get("ai_analysis"),
            "exploits": self.results.get("exploits", []),
            "vulnerabilities": all_vulns
        }
        
        if error:
            report["error"] = error
            report["status"] = "incomplete"
        else:
            report["status"] = "complete"
        
        return report


# Testing function
if __name__ == "__main__":
    workflow = EnhancedWorkflowManager()
    
    target = "http://httpbin.org"
    
    print("=== Testing Enhanced Workflow ===")
    print(f"Target: {target}\n")
    
    # Run with tools enabled, standard mode
    results = workflow.run_complete_pentest(
        target=target,
        recon_mode="quick",  # quick recon
        max_iterations=5,     # 5 AI iterations
        use_tools=True,       # enable external tools
        tool_mode="standard"  # standard tool scanning
    )
    
    print("\n" + "="*60)
    print("FINAL REPORT")
    print("="*60)
    print(f"Duration: {results['scan_info']['duration_seconds']}s")
    print(f"Vulnerabilities: {results['summary']['total_vulnerabilities']}")
    print(f"Exploits: {results['summary']['exploits_generated']}")
    print(f"Severity: {results['summary']['severity_breakdown']}")
