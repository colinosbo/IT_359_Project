#!/usr/bin/env python3
# cve_lookup.py
# Parses Nmap output for service versions and looks up known CVEs
# from the National Vulnerability Database (NVD) API.
# No API key required. Rate limited to 5 requests per 30 seconds.

import requests
import re
import time
from datetime import datetime


# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# How many CVEs to fetch per service (top results by severity)
MAX_CVES_PER_SERVICE = 5

# Delay between NVD requests to respect rate limit (5 requests per 30 seconds)
REQUEST_DELAY = 7  # seconds


def parse_services_from_nmap(nmap_output: str) -> list:
    """
    Parses Nmap output and extracts open port service name + version strings.
    Returns a list of dicts like:
    [
        {"port": "80", "protocol": "tcp", "service": "http", "product": "Apache httpd", "version": "2.4.49"},
        {"port": "22", "protocol": "tcp", "service": "ssh",  "product": "OpenSSH",      "version": "7.4"},
    ]

    Nmap -sV output lines look like:
    80/tcp   open  http    Apache httpd 2.4.49 ((Unix))
    22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
    3306/tcp open  mysql   MySQL 5.7.34
    """
    services = []

    # Regex to match open port lines with service info
    # Captures: port, protocol, service name, and everything after (product + version)
    pattern = re.compile(
        r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)"
    )

    for line in nmap_output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue

        port      = match.group(1)
        protocol  = match.group(2)
        service   = match.group(3)
        remainder = match.group(4).strip()

        # remainder looks like "Apache httpd 2.4.49 ((Unix))"
        # We want to extract product and version from it
        # Version is typically the first thing that looks like a number
        version_match = re.search(r"(\d+[\d\.]+)", remainder)
        if not version_match:
            # No version found, skip — NVD needs a version to be useful
            continue

        version = version_match.group(1)

        # Product is everything before the version number
        product = remainder[:version_match.start()].strip()
        # Clean up trailing parentheses artifacts like "((Unix))"
        product = re.sub(r"\(.*\)", "", product).strip()

        if not product:
            product = service  # fallback to service name if product is empty

        services.append({
            "port":     port,
            "protocol": protocol,
            "service":  service,
            "product":  product,
            "version":  version
        })

    return services


def query_nvd(product: str, version: str) -> list:
    """
    Queries the NVD API for CVEs matching the given product and version.
    Returns a list of CVE dicts with id, description, severity, and published date.
    """
    keyword = f"{product} {version}"

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": MAX_CVES_PER_SERVICE,
        "sortBy": "score",       # highest severity first
        "sortOrder": "dsc"
    }

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            timeout=15
        )
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.Timeout:
        print(f"    [-] NVD request timed out for: {keyword}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"    [-] NVD request failed for {keyword}: {e}")
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    results = []

    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "Unknown")

        # Get English description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        # Get CVSS severity score
        severity = "Unknown"
        score = "N/A"
        metrics = cve.get("metrics", {})

        # Try CVSS v3.1 first, then v3.0, then v2.0
        for cvss_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if cvss_key in metrics and metrics[cvss_key]:
                cvss_data = metrics[cvss_key][0].get("cvssData", {})
                score    = cvss_data.get("baseScore", "N/A")
                severity = metrics[cvss_key][0].get("baseSeverity", "Unknown")
                break

        # Get published date
        published = cve.get("published", "Unknown")
        if published != "Unknown":
            try:
                published = datetime.fromisoformat(
                    published.replace("Z", "+00:00")
                ).strftime("%Y-%m-%d")
            except ValueError:
                pass

        results.append({
            "id":          cve_id,
            "description": description,
            "severity":    severity,
            "score":       score,
            "published":   published
        })

    return results


def format_cve_results(services_with_cves: list) -> str:
    """
    Formats the CVE lookup results into a clean string
    for appending to the combined findings sent to the AI.
    """
    if not services_with_cves:
        return ""

    lines = []
    lines.append("=" * 60)
    lines.append("CVE LOOKUP RESULTS (via NVD)")
    lines.append("=" * 60)

    found_any = False

    for entry in services_with_cves:
        service = entry["service"]
        cves    = entry["cves"]

        if not cves:
            continue

        found_any = True
        lines.append(f"\n[Port {entry['port']}] {entry['product']} {entry['version']}")
        lines.append("-" * 40)

        for cve in cves:
            lines.append(f"  CVE ID:    {cve['id']}")
            lines.append(f"  Severity:  {cve['severity']} (Score: {cve['score']})")
            lines.append(f"  Published: {cve['published']}")
            lines.append(f"  Summary:   {cve['description'][:300]}...")
            lines.append("")

    if not found_any:
        lines.append("\nNo CVEs found for detected service versions.")

    return "\n".join(lines)


def run_cve_lookup(nmap_output: str) -> str:
    """
    Main entry point. Parses Nmap output, looks up CVEs for each
    detected service version, and returns formatted results as a string.
    """
    print("[*] Parsing Nmap output for service versions...")
    services = parse_services_from_nmap(nmap_output)

    if not services:
        print("[*] No versioned services found in Nmap output. Skipping CVE lookup.")
        return ""

    print(f"[+] Found {len(services)} service(s) with version info:")
    for s in services:
        print(f"    Port {s['port']}: {s['product']} {s['version']}")

    print(f"\n[*] Querying NVD for CVEs (this may take ~{len(services) * REQUEST_DELAY}s due to rate limiting)...")

    services_with_cves = []

    for i, service in enumerate(services):
        product = service["product"]
        version = service["version"]

        print(f"    [{i+1}/{len(services)}] Looking up: {product} {version}...")
        cves = query_nvd(product, version)
        print(f"    [+] Found {len(cves)} CVE(s).")

        services_with_cves.append({**service, "cves": cves})

        # Respect NVD rate limit — sleep between requests
        # Skip sleep after the last request
        if i < len(services) - 1:
            time.sleep(REQUEST_DELAY)

    print("[+] CVE lookup complete.\n")
    return format_cve_results(services_with_cves)
