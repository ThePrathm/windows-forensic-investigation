#!/usr/bin/env python3
"""
ioc_extractor.py — Indicators of Compromise Extractor
======================================================
Scans files and directories for Indicators of Compromise (IOCs)
including IPs, domains, file hashes, registry keys, and URLs.

Case: FIR-2026-0042 | Author: ThePrathm
"""

import argparse
import re
import os
import sys
import hashlib
import json
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# Regex patterns for IOC extraction
PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|io|co|uk|de|ru|cn|info|biz|ddns|duckdns|ngrok)\b"
    ),
    "url": re.compile(
        r"https?://[^\s\"'<>]+"
    ),
    "md5": re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    ),
    "sha1": re.compile(
        r"\b[a-fA-F0-9]{40}\b"
    ),
    "sha256": re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    ),
    "registry_key": re.compile(
        r"HK(?:EY_)?(?:LOCAL_MACHINE|CURRENT_USER|LM|CU)"
        r"\\[^\s\"'<>\n]+"
    ),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
    "filepath_windows": re.compile(
        r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
    ),
}

# Known IOCs from this investigation
KNOWN_IOCS = {
    "ips": ["185.220.101.47"],
    "domains": ["update-service.ddns.net", "company-updates.net"],
    "md5": ["a3f1d2c94b87e65f0123456789abcdef"],
    "sha256": ["e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855"],
    "files": ["svchost32.exe", "Invoice_Q2.docm"],
}

# Private/loopback IPs to exclude
EXCLUDE_IPS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "192.168.", "10.", "172.16.", "172.17.", "172.18.",
}


def cprint(text, level="INFO"):
    if not COLOR:
        print(text)
        return
    palette = {
        "INFO": Fore.CYAN,
        "WARN": Fore.YELLOW,
        "HIGH": Fore.RED,
        "CRITICAL": Fore.MAGENTA,
        "OK": Fore.GREEN,
        "HEADER": Fore.WHITE,
    }
    print(f"{palette.get(level, '')}{text}{Style.RESET_ALL}")


def is_excluded_ip(ip):
    return any(ip.startswith(excl) for excl in EXCLUDE_IPS)


def compute_file_hash(filepath):
    """Compute MD5 and SHA256 of a file."""
    try:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except Exception:
        return None, None


def extract_iocs_from_text(text):
    """Extract all IOCs from a block of text."""
    results = {}
    for ioc_type, pattern in PATTERNS.items():
        matches = set(pattern.findall(text))
        if ioc_type == "ipv4":
            matches = {ip for ip in matches if not is_excluded_ip(ip)}
        results[ioc_type] = sorted(matches)
    return results


def flag_known_iocs(extracted):
    """Cross-reference extracted IOCs against known malicious indicators."""
    flags = []
    for ip in extracted.get("ipv4", []):
        if ip in KNOWN_IOCS["ips"]:
            flags.append(("IP", ip, "Known C2 server — Case FIR-2026-0042"))
    for domain in extracted.get("domain", []):
        if domain in KNOWN_IOCS["domains"]:
            flags.append(("Domain", domain, "Known attacker-controlled domain"))
    for hash_val in extracted.get("md5", []):
        if hash_val in KNOWN_IOCS["md5"]:
            flags.append(("MD5", hash_val, "Known malware hash (Cobalt Strike Beacon)"))
    for hash_val in extracted.get("sha256", []):
        if hash_val in KNOWN_IOCS["sha256"]:
            flags.append(("SHA256", hash_val, "Known malware hash (Cobalt Strike Beacon)"))
    return flags


def scan_file(filepath):
    """Scan a single file for IOCs."""
    cprint(f"\n[*] Scanning: {filepath}", "INFO")

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except FileNotFoundError:
        cprint(f"    [ERROR] File not found.", "HIGH")
        return {}

    iocs = extract_iocs_from_text(text)
    flags = flag_known_iocs(iocs)

    # Print summary per file
    total = sum(len(v) for v in iocs.values())
    print(f"    Extracted {total} unique IOCs | {len(flags)} known malicious matches")

    return {"iocs": iocs, "flags": flags, "filepath": filepath}


def print_results(all_results):
    """Pretty-print all IOC results."""
    print(f"\n{'='*60}")
    print(f"  IOC EXTRACTION RESULTS")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    # Aggregate all IOCs
    aggregated = {}
    all_flags = []

    for result in all_results:
        for ioc_type, values in result.get("iocs", {}).items():
            if ioc_type not in aggregated:
                aggregated[ioc_type] = set()
            aggregated[ioc_type].update(values)
        all_flags.extend(result.get("flags", []))

    # Print known malicious first
    if all_flags:
        cprint("🚨 KNOWN MALICIOUS IOCs DETECTED:", "CRITICAL")
        print("-" * 60)
        for ioc_type, value, reason in all_flags:
            cprint(f"  [{ioc_type}] {value}", "CRITICAL")
            print(f"          └─ {reason}")
        print()

    # Print all extracted IOCs by type
    type_labels = {
        "ipv4": "IPv4 Addresses",
        "domain": "Domains",
        "url": "URLs",
        "md5": "MD5 Hashes",
        "sha1": "SHA1 Hashes",
        "sha256": "SHA256 Hashes",
        "registry_key": "Registry Keys",
        "email": "Email Addresses",
        "filepath_windows": "Windows File Paths",
    }

    for ioc_type, label in type_labels.items():
        values = aggregated.get(ioc_type, set())
        if not values:
            continue
        cprint(f"[+] {label} ({len(values)} found):", "INFO")
        for v in sorted(values):
            is_malicious = any(v == flag[1] for flag in all_flags)
            prefix = "  🚨" if is_malicious else "   •"
            level = "CRITICAL" if is_malicious else "INFO"
            cprint(f"{prefix} {v}", level)
        print()

    print(f"{'='*60}")
    total = sum(len(v) for v in aggregated.values())
    print(f"  Total unique IOCs extracted: {total}")
    print(f"  Known malicious matches:     {len(all_flags)}")
    print(f"{'='*60}\n")


def export_json(all_results, output_path):
    """Export IOCs to JSON format for SIEM ingestion."""
    export_data = {
        "case": "FIR-2026-0042",
        "export_time": datetime.now().isoformat(),
        "iocs": {}
    }
    for result in all_results:
        for ioc_type, values in result.get("iocs", {}).items():
            if ioc_type not in export_data["iocs"]:
                export_data["iocs"][ioc_type] = []
            export_data["iocs"][ioc_type].extend(values)

    # Deduplicate
    for k in export_data["iocs"]:
        export_data["iocs"][k] = sorted(set(export_data["iocs"][k]))

    with open(output_path, "w") as f:
        json.dump(export_data, f, indent=2)
    cprint(f"[✓] IOCs exported to: {output_path}", "OK")


def main():
    parser = argparse.ArgumentParser(
        description="IOC Extractor — Case FIR-2026-0042",
        epilog="""
Examples:
  python ioc_extractor.py --file artifacts/sample_logs/network_connections.txt
  python ioc_extractor.py --all
  python ioc_extractor.py --all --export iocs_export.json
        """
    )
    parser.add_argument("--file", help="Single file to scan")
    parser.add_argument("--all", action="store_true", help="Scan all sample logs")
    parser.add_argument("--export", help="Export results to JSON file")
    args = parser.parse_args()

    all_results = []

    if args.file:
        result = scan_file(args.file)
        if result:
            all_results.append(result)

    elif args.all:
        log_dir = os.path.join(os.path.dirname(__file__), "..", "artifacts", "sample_logs")
        if not os.path.isdir(log_dir):
            cprint(f"[ERROR] Sample logs directory not found: {log_dir}", "HIGH")
            sys.exit(1)
        for fname in os.listdir(log_dir):
            fpath = os.path.join(log_dir, fname)
            if os.path.isfile(fpath):
                result = scan_file(fpath)
                if result:
                    all_results.append(result)
    else:
        parser.print_help()
        sys.exit(0)

    if all_results:
        print_results(all_results)
        if args.export:
            export_json(all_results, args.export)


if __name__ == "__main__":
    main()
