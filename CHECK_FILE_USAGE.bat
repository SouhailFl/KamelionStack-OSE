@echo off
echo ========================================
echo  FILE USAGE AUDIT
echo ========================================
echo.
echo Checking which Python files are actually imported...
echo.

echo [Core Files]
findstr /S /C:"enhanced_workflow_manager" *.py >nul 2>&1 && echo [USED] enhanced_workflow_manager.py || echo [???] enhanced_workflow_manager.py
findstr /S /C:"tool_orchestrator" *.py >nul 2>&1 && echo [USED] tool_orchestrator.py || echo [???] tool_orchestrator.py
findstr /S /C:"reconnaissance_phase" *.py >nul 2>&1 && echo [USED] reconnaissance_phase.py || echo [???] reconnaissance_phase.py
findstr /S /C:"active_scanner" *.py >nul 2>&1 && echo [USED] active_scanner.py || echo [???] active_scanner.py
findstr /S /C:"session_scanner" *.py >nul 2>&1 && echo [USED] session_scanner.py || echo [???] session_scanner.py
findstr /S /C:"advanced_vuln_scanner" *.py >nul 2>&1 && echo [USED] advanced_vuln_scanner.py || echo [???] advanced_vuln_scanner.py
findstr /S /C:"waf_bypass" *.py >nul 2>&1 && echo [USED] waf_bypass.py || echo [???] waf_bypass.py
findstr /S /C:"exploit_generator" *.py >nul 2>&1 && echo [USED] exploit_generator.py || echo [???] exploit_generator.py
findstr /S /C:"ollama_integration" *.py >nul 2>&1 && echo [USED] ollama_integration.py || echo [???] ollama_integration.py
findstr /S /C:"owasp_payloads" *.py >nul 2>&1 && echo [USED] owasp_payloads.py || echo [???] owasp_payloads.py

echo.
echo [Executables]
echo [USED] kamelionstack_server.py - Main server
echo [USED] scan_enhanced.py - CLI scanner

echo.
echo ========================================
echo  Audit Complete
echo ========================================
pause
