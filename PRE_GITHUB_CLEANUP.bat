@echo off
echo ========================================
echo  Pre-GitHub Cleanup
echo ========================================
echo.
echo This will remove temporary files before pushing to GitHub:
echo - Old scan reports
echo - Temporary cleanup scripts  
echo - Temporary documentation
echo.
echo NOTE: Dashboard and Reports folders will be ignored by .gitignore
echo.
pause

echo.
echo Removing temporary files...

REM Old scan reports (already ignored by .gitignore but clean them up)
del "enhanced_scan_report_*.json" 2>nul
echo   - Removed old scan reports

REM Temporary cleanup scripts
del "CLEANUP_PROJECT.bat" 2>nul
del "REMOVE_LEGACY_FILES.bat" 2>nul
del "CHECK_FILE_USAGE.bat" 2>nul
echo   - Removed temporary BAT files

REM Temporary documentation
del "CLEANUP_SUMMARY.md" 2>nul
del "FILE_AUDIT_COMPLETE.md" 2>nul
del "GITHUB_READY.md" 2>nul
echo   - Removed temporary docs

echo.
echo ========================================
echo  Cleanup Complete!
echo ========================================
echo.
echo Files ready for GitHub:
echo   ✅ 12 Python files
echo   ✅ 2 BAT files (START_SERVER.bat, AUDIT_TOOLS.bat)
echo   ✅ README.md (professional)
echo   ✅ requirements.txt
echo   ✅ .gitignore (configured)
echo.
echo Ignored by .gitignore:
echo   🔒 Reports/ (your scan outputs)
echo   🔒 dashboard/ (work-in-progress)
echo   🔒 SESSION_HANDOFF.md (internal use)
echo   🔒 __pycache__/ (Python cache)
echo.
echo Next steps:
echo   1. git init
echo   2. git add .
echo   3. git commit -m "Initial commit: KameLionStack OSE"
echo   4. git remote add origin https://github.com/yourusername/repo.git
echo   5. git push -u origin main
echo.
pause

REM Self-delete this script
(goto) 2>nul & del "%~f0"
