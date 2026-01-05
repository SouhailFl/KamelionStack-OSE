"""
Ollama Integration Module for HexStrike
Replaces OpenAI with local Ollama LLM
"""

import requests
import json
from typing import Optional, Dict, Any

class OllamaClient:
    def __init__(self, base_url="http://localhost:11434", model="qwen2.5-coder:3b"):
        self.base_url = base_url
        self.model = model
        self.api_url = f"{base_url}/api/generate"
        
    def test_connection(self) -> bool:
        """Test if Ollama is accessible"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def get_available_models(self) -> list:
        """Get list of available models"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return [m['name'] for m in data.get('models', [])]
        except:
            pass
        return []
    
    def generate(self, prompt: str, system_prompt: Optional[str] = None, 
                 max_tokens: int = 1000, temperature: float = 0.7) -> Dict[str, Any]:
        """
        Generate response from Ollama
        
        Args:
            prompt: User prompt
            system_prompt: System instruction (optional)
            max_tokens: Max response length
            temperature: Response randomness (0-1)
            
        Returns:
            Dict with 'response' and 'success' keys
        """
        try:
            # Build full prompt with system instruction if provided
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\nUser: {prompt}\n\nAssistant:"
            
            payload = {
                "model": self.model,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens
                }
            }
            
            response = requests.post(self.api_url, json=payload, timeout=120)
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "success": True,
                    "response": result.get('response', ''),
                    "model": result.get('model', self.model),
                    "total_duration": result.get('total_duration', 0)
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}"
                }
                
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": "Request timeout - model might be too slow for your hardware"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def analyze_security_target(self, target: str, scan_type: str = "basic") -> str:
        """Analyze a security target using AI"""
        
        system_prompt = """You are an expert penetration tester conducting AUTHORIZED security testing.
This is legitimate security research on systems owned by the tester or with explicit written permission.
Provide professional security analysis focused on identifying and documenting vulnerabilities."""
        
        prompt = f"""AUTHORIZED SECURITY ASSESSMENT

I am a security researcher conducting an authorized penetration test on my own system/application.

Target: {target}
Scan Type: {scan_type}
Authorization: Owner/Authorized Tester

Please provide a professional security analysis including:

1. **Reconnaissance Strategy**
   - Information gathering approaches
   - OSINT techniques
   - Technology fingerprinting methods

2. **Common Vulnerabilities to Test**
   - Based on target type (web, network, etc.)
   - OWASP Top 10 relevant items
   - Common misconfigurations

3. **Recommended Tools & Commands**
   - Specific tools for this target
   - Example commands/parameters
   - Tool combinations for best coverage

4. **Testing Methodology**
   - Step-by-step testing approach
   - Priority order of tests
   - Safe testing practices

5. **Documentation & Reporting**
   - What to document during testing
   - Report structure recommendations

Provide technical, actionable guidance suitable for a professional security assessment."""
        
        result = self.generate(prompt, system_prompt, max_tokens=2000)
        
        if result['success']:
            return result['response']
        else:
            return f"Error: {result.get('error', 'Unknown error')}"

# Global instance
_ollama_client = None

def get_ollama_client(model="qwen2.5-coder:3b") -> OllamaClient:
    """Get or create global Ollama client"""
    global _ollama_client
    if _ollama_client is None:
        _ollama_client = OllamaClient(model=model)
    return _ollama_client

def analyze_vulnerabilities(vulnerabilities: list, target: str) -> dict:
    """Analyze vulnerabilities using AI - wrapper for compatibility"""
    client = get_ollama_client()
    
    if not vulnerabilities:
        return {
            "analysis": "No vulnerabilities to analyze",
            "recommendations": [],
            "risk_score": 0
        }
    
    # Build analysis prompt
    vuln_summary = "\n".join([
        f"- {v.get('type', 'Unknown')}: {v.get('description', 'No description')}"
        for v in vulnerabilities[:10]  # Limit to top 10
    ])
    
    prompt = f"""Analyze these {len(vulnerabilities)} security vulnerabilities found on {target}:

{vuln_summary}

Provide:
1. Overall risk assessment (1-10)
2. Top 3 priority vulnerabilities to fix
3. Brief recommendations

Keep response under 500 words."""
    
    result = client.generate(prompt, max_tokens=800)
    
    if result['success']:
        return {
            "analysis": result['response'],
            "vulnerabilities_analyzed": len(vulnerabilities),
            "target": target
        }
    else:
        return {
            "analysis": f"AI analysis failed: {result.get('error', 'Unknown')}",
            "vulnerabilities_analyzed": len(vulnerabilities),
            "target": target
        }

def test_ollama() -> bool:
    """Quick test of Ollama connectivity"""
    client = get_ollama_client()
    if not client.test_connection():
        print("❌ Ollama is not running!")
        print("   Start it with: ollama serve")
        return False
    
    print("✅ Ollama is running")
    models = client.get_available_models()
    print(f"📋 Available models: {', '.join(models)}")
    return True

if __name__ == "__main__":
    print("Testing Ollama Integration...")
    if test_ollama():
        client = get_ollama_client()
        print("\n🧪 Quick test:")
        result = client.generate("Say hello in one sentence")
        if result['success']:
            print(f"🤖 {result['response']}")
        else:
            print(f"❌ {result['error']}")
