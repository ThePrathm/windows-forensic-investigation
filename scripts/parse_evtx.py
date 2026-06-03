#!/usr/bin/env python3
"""
parse_evtx.py — Windows Event Log Parser
=========================================
Parses Windows Event Log (.evtx) files or text exports and
highlights forensically significant events.

Case: FIR-2026-0042 | Author: ThePrathm
"""

import argparse
import re
import sys
from datetime import datetime
from collections import defaultdict

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# High-value Event IDs for forensic investigation
FORENSIC_EVENT_IDS = {
    "4624": ("Logon", "INFO"),
    "4625": ("Failed Logon", "WARN"),
    "4648": ("Explicit Credential Logon", "HIGH"),
    "4672": ("Special Privileges Assigned", "HIGH"),
    "4688": ("Process Creation", "INFO"),
    "4689": ("Process Terminated", "INFO"),
    "4697": ("Service Installed", "HIGH"),
    "4698": ("Scheduled Task Created", "HIGH"),
    "4702": ("Scheduled Task Updated", "WARN"),
    "4720": ("User Account Created", "HIGH"),
    "4732": ("User Added to Group", "HIGH"),
    "4776": ("NTLM Authentication", "WARN"),
    "4771": ("Kerberos Pre-Auth Failed", "WARN"),
    "7045": ("New Service Installed", "HIGH"),
    "1102": ("Audit Log Cleared", "CRITICAL"),
    "4104": ("PowerShell Script Block", "HIGH"),
    "4103": ("PowerShell Pipeline Execution", "WARN"),
}

# Known malicious indicators from this investigation
KNOWN_MALICIOUS = {
    "ips": ["185.220.101.47"],
    "files": ["svchost32.exe", "Invoice_Q2.docm", "mimikatz"],
    "paths": ["AppData\\Local\\Temp\\svchost32"],
    "commands": ["-Enc", "-EncodedCommand", "DownloadString", "IEX", "Invoke-Expression"],
    "tasks": ["WindowsUpdateCheck"],
    "registry": ["WindowsUpdate"],
}


def color_print(text, level="INFO"):
    if not COLOR:
        print(text)
        return
    colors = {
        "INFO": Fore.CYAN,
        "WARN": Fore.YELLOW,
        "HIGH": Fore.RED,
        "CRITICAL": Fore.MAGENTA,
        "OK": Fore.GREEN,
    }
    print(f"{colors.get(level, '')}{text}{Style.RESET_ALL}")


def is_malicious(line):
    """Check if a log line contains known malicious indicators."""
    line_lower = line.lower()
    hits = []
    for ioc in KNOWN_MALICIOUS["files"]:
        if ioc.lower() in line_lower:
            hits.append(f"Malicious file: {ioc}")
    for ioc in KNOWN_MALICIOUS["ips"]:
        if ioc in line:
            hits.append(f"Malicious IP: {ioc}")
    for ioc in KNOWN_MALICIOUS["commands"]:
        if ioc.lower() in line_lower:
            hits.append(f"Suspicious command: {ioc}")
    for ioc in KNOWN_MALICIOUS["paths"]:
        if ioc.lower() in line_lower:
            hits.append(f"Malicious path: {ioc}")
    return hits


def parse_log_file(filepath):
    """Parse a text-based event log export."""
    print(f"\n{'='*60}")
    print(f"  Windows Event Log Parser — Forensic Mode")
    print(f"  File: {filepath}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    findings = defaultdict(list)
    total_lines = 0
    malicious_hits = 0

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        color_print(f"[ERROR] File not found: {filepath}", "HIGH")
        sys.exit(1)

    for i, line in enumerate(lines, 1):
        total_lines += 1
        line = line.strip()
        if not line:
            continue

        # Check for forensic event IDs
        for eid, (name, level) in FORENSIC_EVENT_IDS.items():
            if f"EventID={eid}" in line or f"Event ID: {eid}" in line or f"[{eid}]" in line:
                findings["events"].append((eid, name, level, i, line[:120]))
                break

        # Check for malicious indicators
        hits = is_malicious(line)
        if hits:
            malicious_hits += 1
            for hit in hits:
                findings["malicious"].append((i, hit, line[:120]))

    # Report Results
    print(f"[*] Total lines processed: {total_lines}")
    print(f"[*] Forensic events found: {len(findings['events'])}")
    print(f"[*] Malicious indicator hits: {malicious_hits}\n")

    if findings["events"]:
        color_print("[+] FORENSIC EVENTS DETECTED:", "INFO")
        print("-" * 60)
        for eid, name, level, lineno, snippet in findings["events"]:
            color_print(f"  Line {lineno:5d} | EventID {eid} | {name}", level)
            print(f"             └─ {snippet[:100]}")
        print()

    if findings["malicious"]:
        color_print("[!] MALICIOUS INDICATORS DETECTED:", "HIGH")
        print("-" * 60)
        for lineno, hit, snippet in findings["malicious"]:
            color_print(f"  Line {lineno:5d} | {hit}", "CRITICAL")
            print(f"             └─ {snippet[:100]}")
        print()

    if not findings["events"] and not findings["malicious"]:
        color_print("[✓] No suspicious events detected in this log.", "OK")

    print(f"\n{'='*60}")
    print(f"  Scan complete. Review findings above.")
    print(f"{'='*60}\n")

    return findings


def generate_timeline(findings):
    """Generate a simple forensic timeline from findings."""
    print("\n[*] FORENSIC TIMELINE (from log file):")
    print("-" * 60)
    if not findings.get("events"):
        print("  No timeline data available.")
        return
    for eid, name, level, lineno, snippet in sorted(findings["events"], key=lambda x: x[2]):
        print(f"  EventID {eid:5s} | {name:<35s} | Line {lineno}")


def main():
    parser = argparse.ArgumentParser(
        description="Windows Event Log Forensic Parser — Case FIR-2026-0042",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python parse_evtx.py --log artifacts/sample_logs/suspicious_processes.txt
  python parse_evtx.py --log mylog.txt --timeline
        """
    )
    parser.add_argument("--log", required=True, help="Path to event log file")
    parser.add_argument("--timeline", action="store_true", help="Generate forensic timeline")
    args = parser.parse_args()

    findings = parse_log_file(args.log)
    if args.timeline:
        generate_timeline(findings)


if __name__ == "__main__":
    main()
