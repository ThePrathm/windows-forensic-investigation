#!/usr/bin/env python3
"""
network_connections.py — Suspicious Network Connection Detector
===============================================================
Analyzes netstat output or network connection logs to identify
suspicious connections, C2 beacons, and data exfiltration traffic.

Case: FIR-2026-0042 | Author: ThePrathm
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# Known malicious IPs from this case
MALICIOUS_IPS = {
    "185.220.101.47": "Cobalt Strike C2 Server (Case FIR-2026-0042)",
    "10.10.10.99":    "Suspected staging server (internal)",
}

# Suspicious ports commonly used by malware
SUSPICIOUS_PORTS = {
    4444:  "Metasploit default listener",
    1337:  "Common hacker/CTF port",
    8888:  "Alternate HTTP — often malware",
    9001:  "Tor OR port",
    9050:  "Tor SOCKS proxy",
    6666:  "Common backdoor port",
    31337: "Elite/Back Orifice backdoor",
}

# Legitimate high-traffic processes
LEGITIMATE_PROCESSES = [
    "chrome.exe", "firefox.exe", "msedge.exe", "outlook.exe",
    "onedrive.exe", "teams.exe", "svchost.exe", "lsass.exe",
    "system", "wininit.exe", "services.exe",
]


def cprint(text, level="INFO"):
    if not COLOR:
        print(text)
        return
    palette = {
        "INFO":     Fore.CYAN,
        "WARN":     Fore.YELLOW,
        "HIGH":     Fore.RED,
        "CRITICAL": Fore.MAGENTA,
        "OK":       Fore.GREEN,
    }
    print(f"{palette.get(level, '')}{text}{Style.RESET_ALL}")


def parse_ip_port(addr_str):
    """Extract IP and port from address string like 185.220.101.47:443"""
    match = re.match(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", addr_str)
    if match:
        return match.group(1), int(match.group(2))
    match = re.match(r"\[?([0-9a-fA-F:]+)\]?:(\d+)", addr_str)
    if match:
        return match.group(1), int(match.group(2))
    return None, None


def is_private_ip(ip):
    """Check if IP is in a private RFC1918 range."""
    if ip is None:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10 or
            (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or
            a == 127
        )
    except ValueError:
        return False


def analyze_connections(filepath):
    """Parse and analyze network connections from a text file."""
    print(f"\n{'='*60}")
    print(f"  Network Connection Analyzer — Forensic Mode")
    print(f"  File: {filepath}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        cprint(f"[ERROR] File not found: {filepath}", "HIGH")
        sys.exit(1)

    connections = []
    malicious_hits = []
    suspicious_ports_found = []
    external_connections = []
    ip_frequency = Counter()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("Proto") or line.startswith("Active"):
            continue

        # Parse netstat-style lines
        parts = re.split(r"\s+", line)
        if len(parts) < 4:
            continue

        proto = parts[0] if parts[0] in ("TCP", "UDP", "tcp", "udp") else "UNK"
        local_addr = parts[1] if len(parts) > 1 else ""
        remote_addr = parts[2] if len(parts) > 2 else ""
        state = parts[3] if len(parts) > 3 else ""
        process = parts[4] if len(parts) > 4 else "unknown"

        remote_ip, remote_port = parse_ip_port(remote_addr)
        local_ip, local_port = parse_ip_port(local_addr)

        if remote_ip is None:
            continue

        ip_frequency[remote_ip] += 1
        conn = {
            "proto": proto,
            "local": local_addr,
            "remote": remote_addr,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": state,
            "process": process,
        }
        connections.append(conn)

        # Check against known malicious IPs
        if remote_ip in MALICIOUS_IPS:
            malicious_hits.append((conn, MALICIOUS_IPS[remote_ip]))

        # Check suspicious ports
        if remote_port and remote_port in SUSPICIOUS_PORTS:
            suspicious_ports_found.append((conn, SUSPICIOUS_PORTS[remote_port]))

        # Track external connections
        if not is_private_ip(remote_ip) and remote_ip != "0.0.0.0":
            external_connections.append(conn)

    # Summary
    print(f"[*] Total connections parsed:     {len(connections)}")
    print(f"[*] External connections:         {len(external_connections)}")
    print(f"[*] Malicious IP matches:         {len(malicious_hits)}")
    print(f"[*] Suspicious port connections:  {len(suspicious_ports_found)}\n")

    # Malicious IP hits
    if malicious_hits:
        cprint("[!] MALICIOUS IP CONNECTIONS DETECTED:", "CRITICAL")
        print("-" * 60)
        for conn, reason in malicious_hits:
            cprint(f"  🚨 {conn['proto']} | {conn['local']} → {conn['remote']}", "CRITICAL")
            print(f"     Reason:  {reason}")
            print(f"     State:   {conn['state']}")
            print(f"     Process: {conn['process']}")
            print()

    # Suspicious ports
    if suspicious_ports_found:
        cprint("[!] SUSPICIOUS PORT CONNECTIONS:", "HIGH")
        print("-" * 60)
        for conn, reason in suspicious_ports_found:
            cprint(f"  ⚠️  Port {conn['remote_port']} | {conn['local']} → {conn['remote']}", "HIGH")
            print(f"     Reason:  {reason}")
            print(f"     Process: {conn['process']}")
            print()

    # Top external IPs (beaconing pattern detection)
    if ip_frequency:
        top_ips = ip_frequency.most_common(5)
        external_top = [(ip, cnt) for ip, cnt in top_ips if not is_private_ip(ip)]
        if external_top:
            cprint("[*] TOP EXTERNAL IPs (possible C2 beaconing):", "WARN")
            print("-" * 60)
            for ip, count in external_top:
                flag = "🚨" if ip in MALICIOUS_IPS else "⚡"
                label = f" ← {MALICIOUS_IPS[ip]}" if ip in MALICIOUS_IPS else ""
                cprint(f"  {flag} {ip:20s}  {count:4d} connections{label}", "HIGH" if ip in MALICIOUS_IPS else "WARN")
            print()

    if not malicious_hits and not suspicious_ports_found:
        cprint("[✓] No obvious malicious connections detected.", "OK")
        cprint("    Manual review of external connections recommended.", "INFO")

    print(f"\n{'='*60}")
    print(f"  Analysis complete.")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Network Connection Analyzer — Case FIR-2026-0042",
        epilog="""
Examples:
  python network_connections.py --input artifacts/sample_logs/network_connections.txt
        """
    )
    parser.add_argument("--input", required=True, help="Path to netstat output or connection log")
    args = parser.parse_args()

    analyze_connections(args.input)


if __name__ == "__main__":
    main()
