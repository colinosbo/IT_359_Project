# AI Recon Analyzer

A command-line tool that sends reconnaissance output (e.g., Nmap scans) to an AI model via OpenWebUI for automated penetration testing analysis.

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
```powershell
$env:OPENWEBUI_API_KEY = "your-api-key-here"
```

**Optional overrides:**
```powershell
$env:OPENWEBUI_URL   = "http://sushi.it.ilstu.edu:8080"  # default
$env:OPENWEBUI_MODEL = "llama3.2"                         # fallback model if fetch fails
```

---

## Usage

```powershell
python3 .\AI_recon_analyzer.py <findings_file>
```

**Example:**
```powershell
python3 .\AI_recon_analyzer.py .\NMAP_test.txt
```

### Steps after running:

1. The script fetches available models from OpenWebUI and displays a numbered list.
2. Enter the number corresponding to the model you want to use.
3. The script sends the findings file to the selected model for analysis.
4. A Markdown report is saved in the current directory as `<filename>_report_<timestamp>.md` and printed to the terminal.

---

## Output

Reports are saved as Markdown files and include:

- Critical and high severity findings
- Identified attack paths
- Misconfigurations or weak configurations
- Recommended next steps

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `401 Unauthorized` | API key missing or wrong | Set `$env:OPENWEBUI_API_KEY` correctly |
| `ReadTimeout` | Model took too long to respond | Choose a smaller/faster model (e.g., `llama3.2`) |
| `Could not fetch models` | VPN not connected or server unreachable | Connect to ISU VPN |
