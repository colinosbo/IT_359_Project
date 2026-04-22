#!/usr/bin/env python3
# AI_recon_analyzer.py

import requests
import sys
import os
import json
from datetime import datetime

# --- Configuration ---
OPENWEBUI_BASE_URL = os.getenv("OPENWEBUI_URL", "http://sushi.it.ilstu.edu:8080")  # must be connected to ISU VPN
OPENWEBUI_API_KEY  = os.getenv("OPENWEBUI_API_KEY", "")
MODEL_NAME         = os.getenv("OPENWEBUI_MODEL", "llama3.2")

SYSTEM_PROMPT = """You are a senior penetration tester analyzing reconnaissance data.
Given raw findings from enumeration tools, provide a structured analysis including:
- Critical and high severity findings
- Identified attack paths
- Misconfigurations or weak configurations
- Recommended next steps

Format your entire response as clean Markdown with appropriate headers and code blocks."""


def fetch_models() -> list:
    headers = {
        "Authorization": f"Bearer {OPENWEBUI_API_KEY}",
        "Content-Type": "application/json"
    }
    response = requests.get(
        f"{OPENWEBUI_BASE_URL}/api/models",
        headers=headers,
        timeout=30
    )
    response.raise_for_status()
    data = response.json()
    # OpenWebUI returns {"data": [...]} compatible with OpenAI format
    models = data.get("data", data) if isinstance(data, dict) else data
    return [m["id"] for m in models]


def select_model() -> str:
    print("[*] Fetching available models from OpenWebUI...")
    try:
        models = fetch_models()
    except Exception as e:
        print(f"[-] Could not fetch models: {e}")
        print(f"[*] Falling back to default model: {MODEL_NAME}")
        return MODEL_NAME

    if not models:
        print(f"[*] No models returned. Falling back to default: {MODEL_NAME}")
        return MODEL_NAME

    print("\nAvailable models:")
    for i, name in enumerate(models, 1):
        print(f"  [{i}] {name}")

    while True:
        choice = input(f"\nSelect a model [1-{len(models)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(models):
            selected = models[int(choice) - 1]
            print(f"[+] Using model: {selected}\n")
            return selected
        print(f"[-] Invalid choice. Enter a number between 1 and {len(models)}.")


def read_findings(filepath: str) -> str:
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


def analyze(findings: str, model: str) -> str:
    headers = {
        "Authorization": f"Bearer {OPENWEBUI_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": f"Analyze the following recon findings:\n\n{findings}"}
        ],
        "stream": True
    }

    response = requests.post(
        f"{OPENWEBUI_BASE_URL}/api/chat/completions",
        headers=headers,
        json=payload,
        stream=True,
        timeout=300
    )
    response.raise_for_status()

    result = []
    for line in response.iter_lines():
        if not line:
            continue
        text = line.decode("utf-8") if isinstance(line, bytes) else line
        if text.startswith("data: "):
            text = text[6:]
        if text == "[DONE]":
            break
        try:
            chunk = json.loads(text)
            delta = chunk["choices"][0]["delta"].get("content", "")
            if delta:
                result.append(delta)
        except (json.JSONDecodeError, KeyError):
            continue

    return "".join(result)


def save_report(content: str, input_filepath: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.splitext(os.path.basename(input_filepath))[0]
    output_path = f"{base}_report_{timestamp}.md"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return output_path


def main():
    # --- Argument Parsing ---
    # Mode 1: python3 AI_recon_analyzer.py scan_results.txt
    # Mode 2: python3 AI_recon_analyzer.py --target 192.168.1.1

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 AI_recon_analyzer.py <findings_file>")
        print("  python3 AI_recon_analyzer.py --target <ip_or_hostname>")
        sys.exit(1)

    if sys.argv[1] == "--target":
        # Automated mode: run Nmap then analyze
        if len(sys.argv) < 3:
            print("[-] Please provide a target after --target.")
            print("    Example: python3 AI_recon_analyzer.py --target 192.168.1.1")
            sys.exit(1)

        target = sys.argv[2]

        # Import here so manual mode works even if nmap_scanner has an issue
        from nmap_scanner import run_nmap_scan, save_scan_output
        from gobuster_scanner import run_gobuster_if_applicable
        from cve_lookup import run_cve_lookup

        # Step 1: Run Nmap
        nmap_output = run_nmap_scan(target)
        filepath = save_scan_output(nmap_output, target)

        # Step 2: Run Gobuster only if port 80 or 443 is open
        gobuster_output = run_gobuster_if_applicable(target, nmap_output)

        # Step 3: Look up CVEs for detected service versions
        cve_output = run_cve_lookup(nmap_output)

        # Step 4: Combine all findings into one string for the AI
        combined_findings = f"=== NMAP SCAN RESULTS ===\n\n{nmap_output}"
        if gobuster_output:
            combined_findings += f"\n\n{gobuster_output}"
        if cve_output:
            combined_findings += f"\n\n{cve_output}"

        # Step 5: Select model and send to AI
        model = select_model()
        print(f"[*] Sending combined findings to AI ({model})...")
        report = analyze(combined_findings, model)

        output_path = save_report(report, filepath)
        print(f"[+] Report saved to: {output_path}")
        print("\n" + "=" * 60 + "\n")
        print(report)
        return

    else:
        # Manual mode: use existing findings file
        filepath = sys.argv[1]
        if not os.path.exists(filepath):
            print(f"[-] File not found: {filepath}")
            sys.exit(1)

        model = select_model()

        print(f"[*] Reading findings from: {filepath}")
        findings = read_findings(filepath)

        print(f"[*] Sending to AI ({model})...")
        report = analyze(findings, model)

        output_path = save_report(report, filepath)
        print(f"[+] Report saved to: {output_path}")
        print("\n" + "=" * 60 + "\n")
        print(report)


if __name__ == "__main__":
    main()
