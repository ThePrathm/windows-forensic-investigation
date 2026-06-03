# Indicators of Compromise (IOCs)
## Case FIR-2026-0042 — Windows Forensic Investigation

> These IOCs should be imported into your SIEM, EDR, and firewall blocklists immediately.

---

## 🌐 Network IOCs

| Type | Value | Description |
|------|-------|-------------|
| IP Address | `185.220.101.47` | Cobalt Strike C2 server — block at perimeter |
| IP Address | `10.10.10.99` | Suspected internal staging server |
| Domain | `update-service.ddns.net` | C2 domain used in TLS certificate |
| Domain | `company-updates.net` | Phishing domain (registered 2026-05-07) |
| URL | `https://185.220.101.47/payload` | Payload download URL |
| URL | `https://update-service.ddns.net/check` | C2 check-in URL |

---

## 📁 File IOCs

| Type | Value | Description |
|------|-------|-------------|
| Filename | `svchost32.exe` | Cobalt Strike Beacon dropper |
| Filename | `Invoice_Q2.docm` | Malicious macro-enabled Word doc (initial vector) |
| Filename | `mimikatz.exe` | Credential harvesting tool |
| MD5 Hash | `a3f1d2c94b87e65f0123456789abcdef` | svchost32.exe hash |
| SHA256 Hash | `e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855` | svchost32.exe hash |
| File Path | `C:\Users\jsmith\AppData\Local\Temp\svchost32.exe` | Drop location |
| File Path | `C:\Users\jsmith\AppData\Local\Temp\mimikatz.exe` | Mimikatz location |

---

## 🔑 Registry IOCs

| Type | Value | Description |
|------|-------|-------------|
| Registry Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate` | Malicious Run key persistence |
| Registry Value | `C:\Users\jsmith\AppData\Local\Temp\svchost32.exe` | Run key data |
| Service Key | `HKLM\SYSTEM\CurrentControlSet\Services\WindowsUpdateSvc` | Fake service for persistence |

---

## ⏰ Scheduled Task IOCs

| Type | Value | Description |
|------|-------|-------------|
| Task Name | `WindowsUpdateCheck` | Malicious scheduled task (hourly execution) |
| Task Action | `C:\Users\jsmith\AppData\Local\Temp\svchost32.exe` | Task command |

---

## 📧 Email IOCs

| Type | Value | Description |
|------|-------|-------------|
| Sender | `hr-payroll@company-updates.net` | Phishing email sender |
| Subject | `Q2 Invoice — Action Required` | Phishing email subject |
| Attachment | `Invoice_Q2.docm` | Malicious attachment name |
| Originating IP | `185.220.101.47` | Email sent from C2 server |

---

## 🔐 Credential IOCs

| Type | Value | Description |
|------|-------|-------------|
| Account | `jsmith` | Compromised primary account |
| Account | `administrator` | Credential harvested via Mimikatz |
| Auth Method | Pass-the-Hash | Lateral movement technique used |

---

## 📌 MITRE ATT&CK Techniques Referenced

| Technique ID | Name |
|---|---|
| T1566.001 | Spear-phishing Attachment |
| T1059.001 | PowerShell |
| T1204.002 | User Execution: Malicious File |
| T1547.001 | Registry Run Keys Persistence |
| T1053.005 | Scheduled Task |
| T1036 | Masquerading |
| T1027 | Obfuscated Files |
| T1003.001 | LSASS Memory Dump |
| T1550.002 | Pass the Hash |
| T1041 | Exfiltration Over C2 Channel |
| T1573.002 | Encrypted Channel |

---

*IOCs compiled by ThePrathm — Case FIR-2026-0042 | May 2026*
