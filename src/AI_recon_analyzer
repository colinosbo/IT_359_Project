#!/usr/bin/env python3
# recon_analyzer.py

import requests
import sys
import os
from datetime import datetime

# --- Configuration ---
OPENWEBUI_BASE_URL = os.getenv("OPENWEBUI_URL", "http://localhost:3000")
OPENWEBUI_API_KEY  = os.getenv("OPENWEBUI_API_KEY", "")
MODEL_NAME         = os.getenv("OPENWEBUI_MODEL", "llama3.2")

SYSTEM_PROMPT = """You are a senior penetration tester analyzing reconnaissance data.
Given raw findings from enumeration tools, provide a structured analysis including:
- Critical and high severity findings
- Identified attack paths
- Misconfigurations or weak configurations
- Recommended next steps

Format your entire response as clean Markdown with appropriate headers and code blocks."""


def read_findings(filepath: str) -> str:
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


def analyze(findings: str) -> str:
    headers = {
        "Authorization": f"Bearer {OPENWEBUI_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": f"Analyze the following recon findings:\n\n{findings}"}
        ],
        "stream": False
    }

    response = requests.post(
        f"{OPENWEBUI_BASE_URL}/api/chat/completions",
        headers=headers,
        json=payload,
        timeout=120
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def save_report(content: str, input_filepath: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.splitext(os.path.basename(input_filepath))[0]
    output_path = f"{base}_report_{timestamp}.md"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return output_path


def main():
    if len(sys.argv) != 2:
        print("Usage: python recon_analyzer.py <findings_file>")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)

    print(f"[*] Reading findings from: {filepath}")
    findings = read_findings(filepath)

    print(f"[*] Sending to AI ({MODEL_NAME})...")
    report = analyze(findings)

    output_path = save_report(report, filepath)
    print(f"[+] Report saved to: {output_path}")
    print("\n" + "="*60 + "\n")
    print(report)


if __name__ == "__main__":
    main()
