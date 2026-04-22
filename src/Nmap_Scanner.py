#!/usr/bin/env python3
# nmap_scanner.py
# Handles automated Nmap scanning and saving output to a text file.

import subprocess
import sys
import os
from datetime import datetime


def check_nmap_installed() -> bool:
    """Check if Nmap is available on the system."""
    try:
        subprocess.run(
            ["nmap", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except FileNotFoundError:
        return False


def run_nmap_scan(target: str) -> str:
    """
    Runs an Nmap -sV -A scan against the given target.
    Returns the scan output as a string.
    """
    if not check_nmap_installed():
        print("[-] Nmap is not installed or not found in PATH.")
        print("    Windows: Download from https://nmap.org/download.html")
        print("    Linux:   sudo apt install nmap")
        sys.exit(1)

    command = ["nmap", "-sV", "-A", target]

    print(f"[*] Starting Nmap scan on target: {target}")
    print(f"[*] Command: {' '.join(command)}")
    print("[*] This may take a minute...\n")

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300  # 5 minute timeout
        )
    except subprocess.TimeoutExpired:
        print("[-] Nmap scan timed out after 5 minutes.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error running Nmap: {e}")
        sys.exit(1)

    if result.returncode != 0 and result.stderr:
        print(f"[-] Nmap warning/error output:\n{result.stderr}")

    output = result.stdout
    if not output.strip():
        print("[-] Nmap returned no output. Check that the target is reachable.")
        sys.exit(1)

    print("[+] Nmap scan complete.\n")
    return output


def save_scan_output(scan_output: str, target: str) -> str:
    """
    Saves the raw Nmap output to a timestamped .txt file.
    Returns the filepath so it can be passed to the analyzer.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Sanitize target for use in filename (replace dots and colons)
    safe_target = target.replace(".", "_").replace(":", "_")
    filename = f"nmap_{safe_target}_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# Nmap Scan Results\n")
        f.write(f"# Target:    {target}\n")
        f.write(f"# Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Command:   nmap -sV -A {target}\n")
        f.write("#" * 60 + "\n\n")
        f.write(scan_output)

    print(f"[+] Scan output saved to: {filename}")
    return filename
