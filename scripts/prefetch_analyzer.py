#!/usr/bin/env python3
"""
prefetch_analyzer.py — Windows Prefetch Execution Timeline
===========================================================
Analyzes Windows Prefetch file listings to reconstruct
program execution history on a compromised system.

Case: FIR-2026-0042 | Author: ThePrathm
"""

import argparse
import re
import sys
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# Known malicious executables from this investigation
MALICIOUS_EXES = {
    "SVCHOST32.EXE":  "Cobalt Strike Beacon (disguised svchost)",
    "MIMIKATZ.EXE":   "Credential harvesting tool",
    "INVOKE-MIMIKATZ.PS1": "In-memory Mimikatz loader",
    "MSHTA.EXE":      "Potentially used for LOL payload delivery",
    "REGSVR32.EXE":   "Potentially used for scriptlet execution",
}

# Suspicious but common LOLBins (Living Off the Land Binaries)
LOLBINS = {
    "POWERSHELL.EXE": "PowerShell — frequently abused",
    "CMD.EXE":        "Command Prompt — check arguments",
    "WSCRIPT.EXE":    "Windows Script Host — script execution",
    "CSCRIPT.EXE":    "Console Script Host",
    "MSHTA.EXE":      "HTML Application Host — script bypass",
    "REGSVR32.EXE":   "Register Server — DLL/scriptlet abuse",
    "RUNDLL32.EXE":   "Run DLL — arbitrary DLL execution",
    "CERTUTIL.EXE":   "Certificate utility — often used for downloads",
    "BITSADMIN.EXE":  "BITS admin — file transfer abuse",
    "WMIC.EXE":       "WMI — lateral movement and execution",
}

SAMPLE_PREFETCH_DATA = """
PREFETCH FILE LISTING — DESKTOP-HR7K2M1
Generated: 2026-05-16 10:23:00

WINWORD.EXE-XXXXXXXX.pf
  Last Run: 2026-05-10 08:46:51
  Run Count: 1
  Files Referenced: Invoice_Q2.docm

POWERSHELL.EXE-AAAAAAAA.pf
  Last Run: 2026-05-10 08:47:02
  Run Count: 3
  Files Referenced: svchost32.exe, payload

SVCHOST32.EXE-BBBBBBBB.pf
  Last Run: 2026-05-16 09:01:44
  Run Count: 187
  Files Referenced: C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost32.exe

CMD.EXE-CCCCCCCC.pf
  Last Run: 2026-05-10 11:13:55
  Run Count: 5
  Files Referenced: mimikatz

MIMIKATZ.EXE-DDDDDDDD.pf
  Last Run: 2026-05-10 11:14:43
  Run Count: 1
  Files Referenced: sekurlsa.dll

NET.EXE-EEEEEEEE.pf
  Last Run: 2026-05-10 11:20:12
  Run Count: 4
  Files Referenced: (none)

CHROME.EXE-FFFFFFFF.pf
  Last Run: 2026-05-16 08:55:00
  Run Count: 1042
  Files Referenced: (none)

NOTEPAD.EXE-GGGGGGGG.pf
  Last Run: 2026-05-14 14:30:00
  Run Count: 12
  Files Referenced: (none)
"""


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
    }
    print(f"{palette.get(level, '')}{text}{Style.RESET_ALL}")


def parse_prefetch(content):
    """Parse prefetch entries from text content."""
    entries = []
    current = None

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        # New prefetch entry
        if line.endswith(".pf"):
            if current:
                entries.append(current)
            exe_name = line.split("-")[0]
            current = {
                "pf_file": line,
                "exe": exe_name.upper(),
                "last_run": None,
                "run_count": 0,
                "files": "",
            }
        elif current:
            if "Last Run:" in line:
                current["last_run"] = line.split("Last Run:")[-1].strip()
            elif "Run Count:" in line:
                try:
                    current["run_count"] = int(line.split("Run Count:")[-1].strip())
                except ValueError:
                    pass
            elif "Files Referenced:" in line:
                current["files"] = line.split("Files Referenced:")[-1].strip()

    if current:
        entries.append(current)

    return entries


def analyze_prefetch(entries):
    """Analyze prefetch entries for suspicious execution patterns."""
    print(f"\n{'='*60}")
    print(f"  Prefetch Execution Timeline Analyzer")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    malicious = []
    lolbins_found = []
    normal = []

    for entry in entries:
        exe = entry["exe"]
        if exe in MALICIOUS_EXES:
            malicious.append(entry)
        elif exe in LOLBINS:
            lolbins_found.append(entry)
        else:
            normal.append(entry)

    print(f"[*] Total prefetch entries: {len(entries)}")
    print(f"[*] Known malicious executables: {len(malicious)}")
    print(f"[*] LOLBin executables:          {len(lolbins_found)}")
    print(f"[*] Normal executables:          {len(normal)}\n")

    # Malicious executables
    if malicious:
        cprint("🚨 MALICIOUS EXECUTABLES EXECUTED:", "CRITICAL")
        print("-" * 60)
        for e in malicious:
            cprint(f"  [{e['exe']}]", "CRITICAL")
            print(f"   Last Run:  {e['last_run']}")
            print(f"   Run Count: {e['run_count']}")
            print(f"   Files:     {e['files']}")
            print(f"   Reason:    {MALICIOUS_EXES.get(e['exe'], 'Unknown')}")
            print()

    # LOLBins
    if lolbins_found:
        cprint("⚠️  LOLBIN EXECUTABLES DETECTED:", "WARN")
        print("-" * 60)
        for e in lolbins_found:
            cprint(f"  [{e['exe']}]  (Run Count: {e['run_count']})", "WARN")
            print(f"   Last Run: {e['last_run']}")
            print(f"   Note:     {LOLBINS.get(e['exe'], '')}")
            if e["files"] and e["files"] != "(none)":
                print(f"   Files:    {e['files']}")
            print()

    # Sort all entries by date for timeline
    print("\n[*] EXECUTION TIMELINE (chronological):")
    print("-" * 60)
    sorted_entries = sorted(
        entries,
        key=lambda x: x["last_run"] if x["last_run"] else "0"
    )
    for e in sorted_entries:
        is_bad = e["exe"] in MALICIOUS_EXES
        is_lol = e["exe"] in LOLBINS
        if is_bad:
            prefix = "🚨"
            level = "CRITICAL"
        elif is_lol:
            prefix = "⚡"
            level = "WARN"
        else:
            prefix = "  "
            level = "INFO"
        cprint(f"  {prefix} {e['last_run'] or 'Unknown':25s} | {e['exe']:<30s} | Runs: {e['run_count']}", level)

    print(f"\n{'='*60}")
    print(f"  Analysis complete.")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Prefetch Execution Analyzer — Case FIR-2026-0042",
        epilog="""
Examples:
  python prefetch_analyzer.py --input prefetch_listing.txt
  python prefetch_analyzer.py --demo   (use built-in sample data)
        """
    )
    parser.add_argument("--input", help="Path to prefetch listing file")
    parser.add_argument("--demo", action="store_true", help="Run with built-in sample data")
    args = parser.parse_args()

    if args.demo:
        print("[*] Running with built-in sample prefetch data from Case FIR-2026-0042...")
        entries = parse_prefetch(SAMPLE_PREFETCH_DATA)
    elif args.input:
        try:
            with open(args.input, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            entries = parse_prefetch(content)
        except FileNotFoundError:
            cprint(f"[ERROR] File not found: {args.input}", "HIGH")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(0)

    if not entries:
        cprint("[!] No prefetch entries found. Check file format.", "WARN")
        sys.exit(1)

    analyze_prefetch(entries)


if __name__ == "__main__":
    main()
