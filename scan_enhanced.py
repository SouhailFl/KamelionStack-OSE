"""
Enhanced KameLionStack Scanner CLI
Uses the new enhanced workflow with all tools
"""

import sys
import requests
import json
import time
from datetime import datetime
from pathlib import Path

def print_banner():
    print("="*70)
    print("🦎 KameLionStack - Enhanced LLM Pentesting")
    print("="*70)

def print_colored(text, severity="INFO"):
    colors = {
        "INFO": "\033[94m",      # Blue
        "SUCCESS": "\033[92m",   # Green
        "WARNING": "\033[93m",   # Yellow
        "ERROR": "\033[91m",     # Red
        "CRITICAL": "\033[95m",  # Magenta
        "HIGH": "\033[91m",      # Red
        "MEDIUM": "\033[93m",    # Yellow
        "LOW": "\033[94m",       # Blue
    }
    reset = "\033[0m"
    color = colors.get(severity.upper(), "")
    print(f"{color}{text}{reset}")

def enhanced_scan(target, recon_mode="quick", max_iterations=10, use_tools=True, tool_mode="standard"):
    """Run enhanced scan with all tools"""
    
    # Ensure target has schema
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    print_banner()
    print(f"🎯 Target: {target}")
    print(f"🔍 Recon Mode: {recon_mode}")
    print(f"🛠️  Tools: {'Enabled' if use_tools else 'Disabled'}")
    print(f"🎚️  Tool Mode: {tool_mode}")
    print(f"🔄 Max Iterations: {max_iterations}")
    print(f"🤖 AI Model: Llama 3.2 3B (GPU-accelerated)")
    print("⏳ Starting enhanced scan...\n")
    
    # API endpoint
    url = "http://localhost:8888/api/workflow/enhanced"
    
    payload = {
        "target": target,
        "recon_mode": recon_mode,
        "max_iterations": max_iterations,
        "use_tools": use_tools,
        "tool_mode": tool_mode
    }
    
    start_time = time.time()
    
    try:
        response = requests.post(url, json=payload, timeout=900)  # 15 min timeout
        
        if response.status_code == 200:
            results = response.json()
            elapsed = time.time() - start_time
            
            # Display results
            display_results(results, elapsed)
            
            # Save report
            save_report(results, target)
            
        else:
            print_colored(f"❌ Error: {response.json().get('error', 'Unknown error')}", "ERROR")
            
    except requests.exceptions.Timeout:
        elapsed = time.time() - start_time
        print_colored(f"❌ Error: Scan timeout after {elapsed:.1f} seconds", "ERROR")
        print_colored("💡 Try again or reduce max_iterations/tool_mode", "WARNING")
        
    except requests.exceptions.ConnectionError:
        print_colored("❌ Error: Cannot connect to server", "ERROR")
        print_colored("💡 Make sure the server is running: python kamelionstack_server.py", "WARNING")
        
    except Exception as e:
        print_colored(f"❌ Error: {str(e)}", "ERROR")

def display_results(results, elapsed):
    """Display scan results beautifully"""
    
    print("="*70)
    print_colored("📊 SCAN RESULTS", "SUCCESS")
    print("="*70)
    
    # Scan info
    scan_info = results.get("scan_info", {})
    print(f"⏱️  Scan Time: {elapsed:.1f} seconds")
    
    # Summary
    summary = results.get("summary", {})
    print(f"🔍 Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    print(f"💥 Exploits Generated: {summary.get('exploits_generated', 0)}")
    print(f"📈 Phases Completed: {summary.get('phases_completed', 0)}/7")
    
    # Severity breakdown
    severity = summary.get("severity_breakdown", {})
    print(f"\n📊 Severity Breakdown:")
    if severity.get("CRITICAL", 0) > 0:
        print_colored(f"   ⚠️  CRITICAL: {severity['CRITICAL']}", "CRITICAL")
    if severity.get("HIGH", 0) > 0:
        print_colored(f"   ⚠️  HIGH: {severity['HIGH']}", "HIGH")
    if severity.get("MEDIUM", 0) > 0:
        print_colored(f"   ⚠️  MEDIUM: {severity['MEDIUM']}", "MEDIUM")
    if severity.get("LOW", 0) > 0:
        print_colored(f"   ⚠️  LOW: {severity['LOW']}", "LOW")
    if severity.get("INFO", 0) > 0:
        print_colored(f"   ℹ️  INFO: {severity['INFO']}", "INFO")
    
    # Reconnaissance summary
    recon = results.get("reconnaissance")
    if recon:
        recon_summary = recon.get("summary", {})
        print(f"\n🔍 Reconnaissance Results:")
        print(f"   • Open Ports: {recon_summary.get('open_ports', 0)}")
        print(f"   • Subdomains: {recon_summary.get('subdomains_found', 0)}")
        print(f"   • Directories: {recon_summary.get('directories_found', 0)}")
        print(f"   • Vulnerabilities: {recon_summary.get('vulnerabilities_found', 0)}")
        
        # Priority targets
        attack_surface = recon.get("attack_surface", {})
        priority = attack_surface.get("priority_targets", [])
        if priority:
            print(f"\n🎯 Priority Targets Found: {len(priority)}")
            for i, target in enumerate(priority[:5], 1):
                priority_level = target.get("priority", "UNKNOWN")
                target_type = target.get("type", "unknown")
                target_name = target.get("target", "")
                print_colored(f"   {i}. [{priority_level}] {target_type}: {target_name}", priority_level)
    
    # Top vulnerabilities
    vulnerabilities = results.get("vulnerabilities", [])
    if vulnerabilities:
        print(f"\n🔍 Top Vulnerabilities:")
        for i, vuln in enumerate(vulnerabilities[:10], 1):
            vuln_type = vuln.get("type", "Unknown")
            vuln_severity = vuln.get("severity", "INFO")
            vuln_url = vuln.get("url", "")
            if vuln_url:
                print_colored(f"   {i}. [{vuln_severity}] {vuln_type} - {vuln_url}", vuln_severity)
            else:
                print_colored(f"   {i}. [{vuln_severity}] {vuln_type}", vuln_severity)
        
        if len(vulnerabilities) > 10:
            print(f"   ... and {len(vulnerabilities) - 10} more")
    
    # Exploits
    exploits = results.get("exploits", [])
    if exploits:
        print(f"\n💥 Generated Exploits: {len(exploits)}")
        for i, exploit in enumerate(exploits[:5], 1):
            print(f"   {i}. {exploit.get('vulnerability_type', 'Unknown exploit')}")
        
        if len(exploits) > 5:
            print(f"   ... and {len(exploits) - 5} more")
    
    print("\n" + "="*70)
    print_colored("✅ SCAN COMPLETE!", "SUCCESS")
    print("="*70)

def save_report(results, target):
    """Save scan report to JSON file in Reports directory"""
    # Create Reports directory if it doesn't exist
    reports_dir = Path(r"C:\Users\souha\KamelionStack-OSE(Offensive Security Engine)\Reports")
    reports_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = reports_dir / f"enhanced_scan_report_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    
    file_size = filename.stat().st_size
    print(f"\n📄 Full report saved: {filename} ({file_size:,} bytes)")

def show_usage():
    """Show usage information"""
    print("Usage:")
    print("  python scan_enhanced.py <target> [recon_mode] [max_iterations] [tool_mode]")
    print()
    print("Arguments:")
    print("  target         : Target URL or domain (required)")
    print("  recon_mode     : quick/standard/deep (default: quick)")
    print("  max_iterations : AI iterations 1-20 (default: 10)")
    print("  tool_mode      : quick/standard/full (default: standard)")
    print()
    print("Examples:")
    print("  python scan_enhanced.py https://example.com")
    print("  python scan_enhanced.py https://example.com quick 5 quick")
    print("  python scan_enhanced.py https://example.com standard 10 standard")
    print("  python scan_enhanced.py https://example.com deep 20 full")
    print()
    print("Recon Modes:")
    print("  quick    : Fast recon (2-3 min) - Port scan + subdomains + directories")
    print("  standard : Normal recon (5-10 min) - Full scan + tools")
    print("  deep     : Deep recon (15-20 min) - All ports + all tools")
    print()
    print("Tool Modes:")
    print("  quick    : Nuclei CVE scan only")
    print("  standard : Nuclei + SQLMap on discovered pages")
    print("  full     : Nuclei + Nikto + SQLMap on all pages")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        show_usage()
        sys.exit(1)
    
    target = sys.argv[1]
    recon_mode = sys.argv[2] if len(sys.argv) > 2 else "quick"
    max_iterations = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    tool_mode = sys.argv[4] if len(sys.argv) > 4 else "standard"
    
    # Validate modes
    if recon_mode not in ["quick", "standard", "deep"]:
        print_colored(f"❌ Invalid recon_mode: {recon_mode}", "ERROR")
        print_colored("💡 Use: quick, standard, or deep", "WARNING")
        sys.exit(1)
    
    if tool_mode not in ["quick", "standard", "full"]:
        print_colored(f"❌ Invalid tool_mode: {tool_mode}", "ERROR")
        print_colored("💡 Use: quick, standard, or full", "WARNING")
        sys.exit(1)
    
    if not 1 <= max_iterations <= 20:
        print_colored(f"❌ Invalid max_iterations: {max_iterations}", "ERROR")
        print_colored("💡 Use a number between 1 and 20", "WARNING")
        sys.exit(1)
    
    enhanced_scan(target, recon_mode, max_iterations, True, tool_mode)
