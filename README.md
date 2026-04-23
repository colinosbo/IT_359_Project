# AI Recon Analyzer

> 🎥 **Video Demo:** [Watch on YouTube](https://www.youtube.com/watch?v=YOUR_VIDEO_ID_HERE)

A command-line tool that sends reconnaissance output (e.g., Nmap scans) to an AI model via OpenWebUI for automated penetration testing analysis. The tool fetches available models, lets the user select one, and generates a structured Markdown security report covering vulnerabilities, attack paths, misconfigurations, and remediation steps.

> **Note:** You must be connected to the ISU VPN to reach the OpenWebUI server.

---

## Requirements

- Python 3.11+
- `requests` library (`pip install requests`)
- ISU VPN active
- A valid OpenWebUI API key

---

## Setup

Set your API key as an environment variable before running the script.

**PowerShell:**

    $env:OPENWEBUI_API_KEY = "your-api-key-here"

**Bash/Linux/macOS:**

    export OPENWEBUI_API_KEY="your-api-key-here"

**Optional overrides:**

    $env:OPENWEBUI_URL   = "http://sushi.it.ilstu.edu:8080"  # default
    $env:OPENWEBUI_MODEL = "llama3.2"                         # fallback model if fetch fails

---

## Usage

    python3 src/AI_recon_analyzer.py <findings_file>

**Example:**

    python3 src/AI_recon_analyzer.py NMAP_test.txt

### Steps after running:
1. The script fetches available models from OpenWebUI and displays a numbered list.
2. Enter the number corresponding to the model you want to use.
3. The script sends the findings file to the selected model for analysis.
4. A Markdown report is saved in the current directory as `<filename>_report_<timestamp>.md` and printed to the terminal.

---

## Output

Reports are saved as Markdown files and include:

- Executive summary of the target's security posture
- Identified services and version numbers
- Critical and high severity findings with CVE references
- Potential attack paths
- Misconfigurations and weak configurations
- Recommended remediation steps

See [docs/ExampleOutput.md](docs/ExampleOutput.md) for a sample report against scanme.nmap.org.

---

## Repository Structure

    IT_359_Project/
    ├── .gitignore
    ├── README.md
    ├── requirements.txt
    ├── src/
    │   └── AI_recon_analyzer.py
    └── docs/
        ├── ExampleOutput.md
        └── Final_Writeup_LastName.pdf

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `401 Unauthorized` | API key missing or wrong | Set `OPENWEBUI_API_KEY` correctly |
| `ReadTimeout` | Model took too long to respond | Choose a smaller/faster model (e.g., `llama3.2`) |
| `Could not fetch models` | VPN not connected or server unreachable | Connect to ISU VPN |
