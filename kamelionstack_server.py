#!/usr/bin/env python3
"""KameLionStack - LLM Pentesting Server"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import subprocess
import os
import sys
import time
import logging
import requests
import requests.exceptions
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import OrderedDict
from ollama_integration import get_ollama_client
from owasp_payloads import OwaspPayloads
from exploit_generator import ExploitGenerator
from enhanced_workflow_manager import EnhancedWorkflowManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

class Config:
    VERSION = "1.0.0 LLM Edition"
    DEFAULT_LLM = "llama3.2:3b-instruct-q4_K_M"
    CACHE_SIZE = 1000
    MAX_PROCESS_TIME = 300
    SERVER_PORT = 8888
    DEBUG = True

class SmartCache:
    def __init__(self, max_size=1000):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        if key in self.cache:
            self.hits += 1
            self.cache.move_to_end(key)
            return self.cache[key]
        self.misses += 1
        return None
    
    def set(self, key: str, value: Any):
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.max_size:
            self.cache.popitem(last=False)
    
    def stats(self) -> Dict[str, Any]:
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {"size": len(self.cache), "max_size": self.max_size, "hits": self.hits, "misses": self.misses, "hit_rate": f"{hit_rate:.2f}%"}

# Globals
cache = SmartCache(Config.CACHE_SIZE)
active_processes = {}
llm_client = None
ai_system = None
exploit_generator = None
enhanced_workflow = None

class AIAgentSystem:
    def __init__(self, llm_client):
        self.llm = llm_client
        self.agents = {
            'IntelligentDecisionEngine': self._decision_engine,
            'BugBountyWorkflow': self._bugbounty_workflow,
            'CTFWorkflow': self._ctf_workflow,
            'CVEIntelligence': self._cve_intelligence,
            'ExploitGenerator': self._exploit_generator,
            'VulnerabilityCorrelator': self._vulnerability_correlator,
            'TechnologyDetector': self._technology_detector,
            'RateLimitDetector': self._ratelimit_detector,
            'FailureRecovery': self._failure_recovery,
            'PerformanceMonitor': self._performance_monitor,
            'ParameterOptimizer': self._parameter_optimizer,
            'ReportAnalyzer': self._report_analyzer
        }
    
    def _decision_engine(self, context):
        return {"action": "scan", "confidence": 0.95}
    
    def _bugbounty_workflow(self, target):
        return {"workflow": "bugbounty", "steps": []}
    
    def _ctf_workflow(self, challenge):
        return {"workflow": "ctf", "hints": []}
    
    def _cve_intelligence(self, vulnerability):
        return {"cve_id": None, "severity": "unknown"}
    
    def _exploit_generator(self, vuln_data):
        return {"exploit": None}
    
    def _vulnerability_correlator(self, vulns):
        return {"correlations": []}
    
    def _technology_detector(self, response):
        return {"technologies": []}
    
    def _ratelimit_detector(self, responses):
        return {"rate_limited": False}
    
    def _failure_recovery(self, error):
        return {"retry": True, "backoff": 2}
    
    def _performance_monitor(self, metrics):
        return {"status": "healthy"}
    
    def _parameter_optimizer(self, params):
        return params
    
    def _report_analyzer(self, report):
        return {"insights": []}
    
    def execute(self, agent_name, **kwargs):
        if agent_name in self.agents:
            return self.agents[agent_name](kwargs)
        return {"error": "Agent not found"}
    
    def list_agents(self):
        return list(self.agents.keys())

@app.route('/')
def index():
    return jsonify({"status": "online", "version": Config.VERSION})

@app.route('/api/workflow/enhanced', methods=['POST'])
def enhanced_workflow_endpoint():
    """Run ENHANCED autonomous pentesting with all tools (NEW)"""
    global enhanced_workflow
    
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400
    
    data = request.get_json()
    target = data.get('target')
    recon_mode = data.get('recon_mode', 'standard')  # quick/standard/deep
    max_iterations = data.get('max_iterations', 10)
    use_tools = data.get('use_tools', True)
    tool_mode = data.get('tool_mode', 'standard')  # quick/standard/full
    
    if not target:
        return jsonify({'error': 'target parameter required'}), 400
    
    try:
        logger.info(f"Starting ENHANCED workflow on {target}")
        logger.info(f"Recon: {recon_mode}, Tools: {use_tools}, Tool Mode: {tool_mode}")
        
        results = enhanced_workflow.run_complete_pentest(
            target=target,
            recon_mode=recon_mode,
            max_iterations=max_iterations,
            use_tools=use_tools,
            tool_mode=tool_mode
        )
        
        return jsonify(results)
    except Exception as e:
        logger.error(f"Enhanced workflow error: {str(e)}")
        return jsonify({'error': str(e), 'details': str(e)}), 500

@app.route('/api/exploits/generate', methods=['POST'])
def generate_exploits():
    """Generate exploits from scan results"""
    global exploit_generator
    
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400
    
    data = request.get_json()
    scan_results = data.get('scan_results', {})
    format_type = data.get('format', 'json')
    
    if not scan_results:
        return jsonify({'error': 'scan_results required'}), 400
    
    try:
        exploits = exploit_generator.generate_exploits_from_scan(scan_results)
        
        if format_type == 'html':
            content = exploit_generator.generate_html_exploit_report(exploits)
            return jsonify({'content': content, 'format': 'html', 'count': len(exploits)})
        
        elif format_type == 'text':
            content = '\n'.join([exploit_generator.format_exploit_report(e) for e in exploits])
            return jsonify({'content': content, 'format': 'text', 'count': len(exploits)})
        
        else:
            exploits_json = [{
                'vulnerability_type': e.vulnerability_type,
                'target_url': e.target_url,
                'parameter': e.parameter,
                'payload': e.payload,
                'command': e.command,
                'manual_steps': e.manual_steps,
                'curl_example': e.curl_example,
                'expected_output': e.expected_output,
                'risk_level': e.risk_level,
                'remediation': e.remediation
            } for e in exploits]
            
            return jsonify({'exploits': exploits_json, 'count': len(exploits)})
    
    except Exception as e:
        logger.error(f"Exploit generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': Config.VERSION,
        'timestamp': datetime.now().isoformat()
    })

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def animate_text(text, delay=0.03):
    """Print text with typing animation"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def print_banner():
    """Animated ASCII banner"""
    clear_screen()
    
    banner = [
        "\033[38;5;159m██╗  ██╗ █████╗ ███╗   ███╗███████╗██╗     ██╗ ██████╗ ███╗   ██╗███████╗████████╗ █████╗  ██████╗██╗  ██╗",
        "\033[38;5;123m██║ ██╔╝██╔══██╗████╗ ████║██╔════╝██║     ██║██╔═══██╗████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝",
        "\033[38;5;87m█████╔╝ ███████║██╔████╔██║█████╗  ██║     ██║██║   ██║██╔██╗ ██║███████╗   ██║   ███████║██║     █████╔╝ ",
        "\033[38;5;51m██╔═██╗ ██╔══██║██║╚██╔╝██║██╔══╝  ██║     ██║██║   ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██╔═██╗ ",
        "\033[38;5;51m██║  ██╗██║  ██║██║ ╚═╝ ██║███████╗███████╗██║╚██████╔╝██║ ╚████║███████║   ██║   ██║  ██║╚██████╗██║  ██╗",
        "\033[38;5;51m╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝\033[0m"
    ]
    
    print("\n")
    for line in banner:
        print(line)
        time.sleep(0.1)
    
    print("\n")
    print("\033[96m" + "="*90 + "\033[0m")
    animate_text("\033[93m              🔥 AI-POWERED AUTONOMOUS PENETRATION TESTING FRAMEWORK 🔥\033[0m", 0.02)
    print("\033[96m" + "="*90 + "\033[0m")
    time.sleep(0.3)
    
    # Info section
    print("\n")
    animate_text(f"\033[92m[✓] Version:\033[0m {Config.VERSION}", 0.01)
    animate_text(f"\033[92m[✓] Author:\033[0m Souhail Fellaki", 0.01)
    animate_text(f"\033[92m[✓] GitHub:\033[0m https://github.com/SouhailFl/KamelionStack-OSE", 0.01)
    print("\n")
    time.sleep(0.3)

def initialize_server():
    global llm_client, ai_system, exploit_generator, enhanced_workflow
    
    print_banner()
    
    print("\033[96m" + "="*90 + "\033[0m")
    print("\033[93m                              SYSTEM INITIALIZATION\033[0m")
    print("\033[96m" + "="*90 + "\033[0m")
    print("\n")
    
    # Initialize components with animation
    sys.stdout.write("\033[94m[*] Initializing AI Engine...\033[0m ")
    sys.stdout.flush()
    for i in range(3):
        time.sleep(0.3)
        sys.stdout.write(".")
        sys.stdout.flush()
    
    llm_client = get_ollama_client(Config.DEFAULT_LLM)
    ai_system = AIAgentSystem(llm_client)
    print(" \033[92m✓\033[0m")
    print(f"    ├─ \033[90mLoaded {len(ai_system.list_agents())} AI agents\033[0m")
    time.sleep(0.2)
    
    sys.stdout.write("\033[94m[*] Loading OWASP 2025 Payloads...\033[0m ")
    sys.stdout.flush()
    for i in range(3):
        time.sleep(0.3)
        sys.stdout.write(".")
        sys.stdout.flush()
    
    payloads = OwaspPayloads.build_database()
    total_payloads = sum(len(data['all_payloads']) for data in payloads.values())
    print(" \033[92m✓\033[0m")
    print(f"    ├─ \033[90m{total_payloads} payloads across {len(payloads)} vulnerability types\033[0m")
    time.sleep(0.2)
    
    sys.stdout.write("\033[94m[*] Initializing Tool Orchestrator...\033[0m ")
    sys.stdout.flush()
    for i in range(3):
        time.sleep(0.3)
        sys.stdout.write(".")
        sys.stdout.flush()
    
    exploit_generator = ExploitGenerator()
    enhanced_workflow = EnhancedWorkflowManager()
    print(" \033[92m✓\033[0m")
    print("    ├─ \033[90mNmap, Nuclei, SQLMap, Nikto, ffuf, gobuster, subfinder, httpx\033[0m")
    time.sleep(0.2)
    
    print("\n")
    print("\033[96m" + "="*90 + "\033[0m")
    print("\033[92m                            ✓ SYSTEM READY ✓\033[0m")
    print("\033[96m" + "="*90 + "\033[0m")
    print("\n")
    
    print(f"\033[93m🌐 Server:\033[0m http://localhost:{Config.SERVER_PORT}")
    print(f"\033[93m🎯 Endpoints:\033[0m")
    print(f"   ├─ \033[90m/api/workflow/enhanced\033[0m (Complete pentesting workflow)")
    print(f"   └─ \033[90m/api/exploits/generate\033[0m (Generate exploits from results)")
    print("\n")
    print("\033[96m" + "="*90 + "\033[0m")
    print("\033[92m[!] Server starting...\033[0m")
    print("\033[96m" + "="*90 + "\033[0m")
    print("\n")
    time.sleep(0.5)

if __name__ == '__main__':
    initialize_server()
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)  # Suppress Flask dev server warning
    app.run(host='0.0.0.0', port=Config.SERVER_PORT, debug=False, use_reloader=False)  # Disable reloader to prevent double initialization
