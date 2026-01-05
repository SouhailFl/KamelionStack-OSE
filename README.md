# KameLionStack OSE

> AI-Powered Automated Penetration Testing - One Command, Complete Analysis

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Stop clicking through tools manually. KameLionStack orchestrates your entire pentest workflow with AI-driven intelligence.

```bash
python scan_enhanced.py https://target.com standard 10 standard
```

One command runs: Nmap → Nuclei → SQLMap → Nikto → ffuf → AI Analysis → Exploits. Automatically.

---

## What It Does

```
INPUT: target.com
  ↓
Scans all ports + services (Nmap)
Finds all subdomains (Subfinder + httpx)  
Discovers hidden directories (ffuf + gobuster)
Runs 1000+ CVE checks (Nuclei)
Tests SQL injection everywhere (SQLMap)
Checks session security (JWT/Cookies/CSRF)
Detects & bypasses WAFs
AI analyzes everything (Local LLM)
Generates working exploits
  ↓
OUTPUT: Complete pentest report in 5-10 minutes
```

**Real Results:**
- 50-200+ vulnerabilities per scan
- Actual CVEs detected (not false positives)
- Ready-to-use exploit commands
- Professional JSON reports

---

## Quick Start

### Prerequisites

**Python & Ollama:**
```bash
# Python 3.8+
python --version

# Ollama (for AI)
https://ollama.ai/download
```

**AI Model Setup:**

Choose based on your GPU:

| GPU VRAM | Recommended Model | Speed | Quality |
|----------|-------------------|-------|---------|
| 4GB or less | `qwen2.5-coder:3b` | 15-20 tok/sec | 85% |
| 6GB+ | `qwen2.5-coder:7b` | 30-40 tok/sec | 90% |
| 8GB+ | `qwen2.5-coder:14b` | 20-30 tok/sec | 95% |

```bash
# For 4GB VRAM (RTX 2050, GTX 1650, etc.)
ollama pull qwen2.5-coder:3b

# For 6GB+ VRAM
ollama pull qwen2.5-coder:7b
```

**Pentesting Tools (install what you need):**
```bash
# Core tools (recommended)
- Nmap: https://nmap.org/download.html
- Nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
- SQLMap: pip install sqlmap

# Optional (for advanced features)
- Nikto: apt install nikto
- ffuf: go install github.com/ffuf/ffuf@latest
- gobuster: go install github.com/OJ/gobuster/v3@latest
- Subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
- httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

**Check installed tools:**
```bash
AUDIT_TOOLS.bat  # Shows which tools you have
```

### Installation

```bash
git clone https://github.com/yourusername/kamelionstack-ose.git
cd kamelionstack-ose

# Install Python dependencies
pip install -r requirements.txt

# Start Ollama service
ollama serve

# Start KameLionStack server
python kamelionstack_server.py
```

### Run Your First Scan

```bash
# Quick scan (2-3 min)
python scan_enhanced.py https://target.com quick 5 quick

# Standard scan (5-10 min) - RECOMMENDED
python scan_enhanced.py https://target.com standard 10 standard

# Deep scan (15-20 min)
python scan_enhanced.py https://target.com deep 20 full
```

Results saved to: `Reports/enhanced_scan_report_[timestamp].json`

---

## Scan Modes

| Mode | Time | What It Does | Best For |
|------|------|--------------|----------|
| quick | 2-3 min | Fast port scan + subdomains + Nuclei CVEs | Bug bounty recon |
| standard | 5-10 min | Full scan + all tools + SQLMap + AI analysis | Professional pentests |
| deep | 15-20 min | All 65K ports + extensive fuzzing + everything | Red team engagements |

---

## What Gets Tested

### Automated Testing (43+ vulnerability types)
- SQL Injection (manual payloads + SQLMap)  
- XSS (Reflected, Stored, DOM)  
- LFI/RFI  
- Command Injection  
- SSRF  
- XXE  
- JWT Security (13 tests)  
- Session Management  
- CSRF Protection  
- Authentication Bypass  
- WAF Detection (10+ types)  
- 1000+ CVE templates (Nuclei)  
- Web server misconfigurations  
- Default credentials  
- Exposed panels  

### Tools Orchestrated
- **Nmap** - Port/service detection
- **Nuclei** - CVE & vulnerability scanning
- **SQLMap** - SQL injection testing
- **Nikto** - Web server analysis
- **ffuf & gobuster** - Directory fuzzing
- **Subfinder & httpx** - Subdomain discovery

---

## Usage Examples

### Basic Scan
```bash
python scan_enhanced.py http://testphp.vulnweb.com
```

### API Usage
```bash
curl -X POST http://localhost:8888/api/workflow/enhanced \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "recon_mode": "standard"}'
```

### Custom Configuration
```python
# Scan with specific settings
python scan_enhanced.py https://target.com \
  quick           # Recon mode: quick/standard/deep
  5               # AI iterations: 1-20
  standard        # Tool mode: quick/standard/full
```

---

## Example Output

```
KameLionStack - Enhanced LLM Pentesting
======================================================================
Target: http://testphp.vulnweb.com
Scan Time: 352 seconds

RESULTS:
Vulnerabilities: 38
Exploits Generated: 5
Phases: 7/7 complete

SEVERITY:
   CRITICAL: 12
   HIGH: 15
   MEDIUM: 8
   LOW: 3

DISCOVERED:
   Open Ports: 3
   Subdomains: 2
   Directories: 15
   CVEs: 8

SCAN COMPLETE
Report: Reports/enhanced_scan_report_20251229.json
```

---

## Architecture

```
CLI/API Request
      ↓
Flask Server (kamelionstack_server.py)
      ↓
Enhanced Workflow Manager
      ↓
      ├─→ Reconnaissance (Nmap, Subfinder, httpx, ffuf)
      ├─→ Active Scanning (SQL, XSS, LFI)
      ├─→ Session Testing (JWT, Cookies, CSRF)
      ├─→ Advanced Testing (Command Injection, SSRF, XXE)
      ├─→ Tool Scanning (Nuclei, SQLMap, Nikto)
      ├─→ WAF Detection
      └─→ AI Analysis (Local LLM) → Exploits
```

---

## Configuration

**Scan Modes:**
- `quick` - Fast recon (2-3 min)
- `standard` - Balanced scan (5-10 min)
- `deep` - Complete pentest (15-20 min)

**Tool Modes:**
- `quick` - Nuclei CVEs only
- `standard` - Nuclei + SQLMap
- `full` - All tools + Nikto

**AI Iterations:** 1-20 (default: 10)
- Higher = more detailed analysis
- 5 = quick, 10 = standard, 20 = thorough

---

## Project Structure

```
kamelionstack-ose/
├── kamelionstack_server.py       # Main server
├── scan_enhanced.py              # CLI scanner
├── enhanced_workflow_manager.py  # Workflow orchestrator
├── tool_orchestrator.py          # Tool integration
├── reconnaissance_phase.py       # Recon phase
├── active_scanner.py             # SQL/XSS/LFI scanner
├── session_scanner.py            # JWT/Cookie tester
├── advanced_vuln_scanner.py      # Command/SSRF/XXE
├── waf_bypass.py                 # WAF detection
├── exploit_generator.py          # Exploit creation
├── ollama_integration.py         # AI integration
├── owasp_payloads.py             # Payload database
└── requirements.txt              # Dependencies
```

---

## Legal Notice

**For authorized testing only.**

- Get written permission before testing  
- Follow responsible disclosure  
- Comply with local laws  

Unauthorized access is illegal. We're not responsible for misuse.

---

## Contributing

Pull requests welcome! Please:
1. Test your changes
2. Update documentation
3. Follow existing code style

---

## License

MIT License - See LICENSE file

---

## Credits

Built with:
- [Ollama](https://ollama.ai/) - Local LLM
- [ProjectDiscovery](https://projectdiscovery.io/) - Nuclei, Subfinder, httpx
- [SQLMap](https://sqlmap.org/) - SQL injection testing
- [Nmap](https://nmap.org/) - Network scanning
- OWASP payloads & methodology

---

**Made for security professionals by security amateurs supervised by Claude (who's actually pretty good at this stuff but won't admit it)** 😂

*Disclaimer: No AI models were harmed in the making of this tool. Some were mildly confused about why we kept asking them to generate exploits, though.*
