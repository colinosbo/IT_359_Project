#!/usr/bin/env python3
# gobuster_scanner.py
# Runs Gobuster directory brute force only if port 80 or 443 is open.
# Works on both Windows and Linux — requires gobuster in PATH.

import subprocess
import sys
import os
from datetime import datetime


def check_gobuster_installed() -> bool:
    """Check if gobuster is available on the system."""
    try:
        subprocess.run(
            ["gobuster", "version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except FileNotFoundError:
        return False


def check_web_ports_open(nmap_output: str) -> dict:
    """
    Parse Nmap output to check if port 80 or 443 is open.
    Returns a dict like: {"80": True, "443": False}
    """
    results = {"80": False, "443": False}
    for line in nmap_output.splitlines():
        line = line.lower()
        if "80/tcp" in line and "open" in line:
            results["80"] = True
        if "443/tcp" in line and "open" in line:
            results["443"] = True
    return results


def get_wordlist_path() -> str:
    """
    Finds the wordlists/common.txt file relative to this script's location.
    Works regardless of where the script is called from.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # src/ is one level below the project root, so go up one level
    project_root = os.path.dirname(script_dir)
    wordlist_path = os.path.join(project_root, "wordlists", "common.txt")

    if not os.path.exists(wordlist_path):
        print(f"[-] Wordlist not found at: {wordlist_path}")
        print("    Make sure wordlists/common.txt exists in the project root.")
        sys.exit(1)

    return wordlist_path


def run_gobuster(target: str, port: str, wordlist_path: str) -> str:
    """
    Runs gobuster dir scan against the target on the given port.
    Returns the output as a string.
    """
    protocol = "https" if port == "443" else "http"
    url = f"{protocol}://{target}"

    command = [
        "gobuster", "dir",
        "-u", url,
        "-w", wordlist_path,
        "-q",           # quiet mode, cleaner output
        "--no-error",   # suppress connection errors
        "-t", "20"      # 20 threads, fast but not aggressive
    ]

    print(f"[*] Running Gobuster on {url} (port {port})...")
    print(f"[*] Command: {' '.join(command)}")
    print("[*] This may take a moment...\n")

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180  # 3 minute timeout per scan
        )
    except subprocess.TimeoutExpired:
        print(f"[-] Gobuster timed out on port {port}.")
        return f"Gobuster scan on port {port} timed out after 3 minutes.\n"
    except Exception as e:
        print(f"[-] Error running Gobuster: {e}")
        return f"Gobuster scan on port {port} failed: {e}\n"

    output = result.stdout
    if not output.strip():
        output = f"No directories found on {url}\n"

    print(f"[+] Gobuster scan complete on port {port}.\n")
    return output


def run_gobuster_if_applicable(target: str, nmap_output: str) -> str:
    """
    Main entry point. Checks Nmap output for open web ports,
    runs Gobuster if found, and returns combined results as a string.
    If no web ports are open, returns an empty string.
    """
    open_ports = check_web_ports_open(nmap_output)

    if not open_ports["80"] and not open_ports["443"]:
        print("[*] No HTTP/HTTPS ports open. Skipping Gobuster scan.")
        return ""

    if not check_gobuster_installed():
        print("[-] Gobuster is not installed or not found in PATH.")
        print("    Windows: https://github.com/OJ/gobuster/releases")
        print("    Linux:   sudo apt install gobuster")
        print("[*] Skipping web directory scan.")
        return ""

    wordlist_path = get_wordlist_path()
    gobuster_results = []

    gobuster_results.append("=" * 60)
    gobuster_results.append("GOBUSTER WEB DIRECTORY SCAN RESULTS")
    gobuster_results.append("=" * 60 + "\n")

    if open_ports["80"]:
        output = run_gobuster(target, "80", wordlist_path)
        gobuster_results.append(f"--- Port 80 (HTTP) ---\n{output}")

    if open_ports["443"]:
        output = run_gobuster(target, "443", wordlist_path)
        gobuster_results.append(f"--- Port 443 (HTTPS) ---\n{output}")

    return "\n".join(gobuster_results)
