"""
Clean GitHub Push Script
Removes unwanted files from repo and pushes only essential code
"""

import subprocess
import os
import sys

def run_command(cmd, ignore_error=False):
    """Run git command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=os.path.dirname(__file__))
        if result.returncode != 0 and not ignore_error:
            print(f"Warning: {result.stderr.strip()}")
        return result.stdout.strip()
    except Exception as e:
        if not ignore_error:
            print(f"Error: {e}")
        return ""

def main():
    print("="*60)
    print("  KameLionStack - Clean GitHub Push")
    print("="*60)
    print()
    
    # Step 1: Remove cached files
    print("[1/6] Removing cached files that shouldn't be tracked...")
    files_to_remove = [
        "Reports/",
        "dashboard/",
        "__pycache__/",
        "SESSION_HANDOFF.md",
        "*.log",
        ".env"
    ]
    
    for file in files_to_remove:
        run_command(f"git rm -r --cached {file}", ignore_error=True)
    
    print("[+] Cached files removed")
    print()
    
    # Step 2: Check status
    print("[2/6] Checking current status...")
    status = run_command("git status")
    print(status[:500])  # Show first 500 chars
    print()
    
    # Step 3: Stage essential files
    print("[3/6] Staging only essential files...")
    essential_files = [
        ".gitignore",
        "README.md",
        "requirements.txt",
        "*.py",
        "START_SERVER.bat"
    ]
    
    for file in essential_files:
        run_command(f"git add {file}")
    
    print("[+] Essential files staged")
    print()
    
    # Step 4: Show what will be committed
    print("[4/6] Current staged changes:")
    staged = run_command("git status --short")
    print(staged if staged else "No changes to commit")
    print()
    
    # Summary
    print("="*60)
    print("  Ready to commit and push!")
    print("="*60)
    print()
    print("Files that WILL be pushed:")
    print("  - All .py files (scanners, server, etc.)")
    print("  - README.md")
    print("  - requirements.txt")
    print("  - .gitignore")
    print("  - START_SERVER.bat")
    print()
    print("Files that will NOT be pushed:")
    print("  - Reports/ (scan outputs)")
    print("  - dashboard/ (work in progress)")
    print("  - SESSION_HANDOFF.md (internal notes)")
    print("  - __pycache__/ (Python cache)")
    print()
    
    # Get commit message
    commit_msg = input("Enter commit message (or press Enter for default): ").strip()
    if not commit_msg:
        commit_msg = "Update KameLionStack OSE - Clean codebase"
    
    print()
    
    # Step 5: Commit
    print("[5/6] Committing changes...")
    commit_result = run_command(f'git commit -m "{commit_msg}"')
    if "nothing to commit" in commit_result.lower():
        print("[!] No changes to commit")
        print()
        input("Press Enter to exit...")
        return
    print("[+] Changes committed")
    print()
    
    # Step 6: Push
    print("[6/6] Pushing to GitHub...")
    push_result = run_command("git push origin main")
    
    if "error" in push_result.lower() or "fatal" in push_result.lower():
        print("[-] Push failed!")
        print(push_result)
        print()
        print("Try: git push origin main --force-with-lease")
        print("(This is safer than --force)")
    else:
        print("[+] Push complete!")
        print()
        print("="*60)
        print("  Success!")
        print("="*60)
        print()
        print("Your GitHub repo now has:")
        print("  - Clean, professional codebase")
        print("  - No reports or temp files")
        print("  - Proper .gitignore in place")
        print()
    
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()
