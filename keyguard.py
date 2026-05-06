import os
import re
import sys
import argparse

VERSION = "1.0.0"

BANNER = """
 🛡️  KeyGuard Security Scanner
=================================
"""

# Define the patterns we are hunting for
SECRET_PATTERNS = {
    "AWS Access Key": r"(?i)AKIA[0-9A-Z]{16}",
    "Stripe Live Token": r"sk_live_[0-9a-zA-Z]{24}",
    "RSA Private Key": r"[-]{5}BEGIN RSA PRIVATE KEY[-]{5}",
    "Generic API Key / Password": r"(?i)(api_key|secret|password|pwd|token)[a-z0-9_ .\-,]{0,25}[:=]{1,2}\s*['\"]([a-zA-Z0-9\-_=]{16,64})['\"]"
}

IGNORE_DIRS = {".git", "__pycache__", "node_modules", "venv", "env"}

def scan_file(filepath):
    found_secrets = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                for secret_name, pattern in SECRET_PATTERNS.items():
                    if re.search(pattern, line):
                        snippet = line.strip()[:80] 
                        found_secrets.append((line_num, secret_name, snippet))
    except (UnicodeDecodeError, PermissionError):
        pass 
        
    return found_secrets

def scan_directory(directory):
    print(BANNER)
    print(f"[*] Initiating scan on: {os.path.abspath(directory)}...\n")
    total_secrets_found = 0

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for file in files:
            filepath = os.path.join(root, file)
            secrets = scan_file(filepath)
            
            if secrets:
                print(f"⚠️  [VULNERABILITY] {filepath}")
                for line_num, name, snippet in secrets:
                    print(f"   -> Line {line_num} | {name}: {snippet}")
                    total_secrets_found += 1
                print("-" * 50)

    if total_secrets_found == 0:
        print("✅ Scan complete. No secrets found! You are safe to commit.\n")
        sys.exit(0)
    else:
        print(f"❌ Scan complete. KeyGuard blocked the action! Found {total_secrets_found} potential secret(s).\n")
        sys.exit(1)

def main():
    # Setup the CLI Argument Parser
    parser = argparse.ArgumentParser(
        description="KeyGuard: A lightweight CLI tool to prevent committing secrets to GitHub.",
        usage="python keyguard.py <command> [options]"
    )
    
    # Define our CLI commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # The "scan" command
    scan_parser = subparsers.add_parser("scan", help="Scan a directory for secrets")
    scan_parser.add_argument("directory", nargs="?", default=".", help="The directory to scan (defaults to current directory)")
    
    # The "version" command
    subparsers.add_parser("version", help="Show the current version of KeyGuard")

    args = parser.parse_args()

    # Route the command to the right function
    if args.command == "scan":
        scan_directory(args.directory)
    elif args.command == "version":
        print(f"KeyGuard v{VERSION}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()