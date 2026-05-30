# JackofAllHacks — DFIR Investigation

**Protocol SIFT** — AI-assisted Digital Forensics & Incident Response  
*Experimental. Not court-admissible without independent validation.*

---

## Case Overview

| Field | Value |
|---|---|
| Case ID | JackofAllHacks |
| Type | Intrusion + Ransomware Deployment |
| Threat Actor | Saiyan Spider |
| Incident Date | 2026-03-08 |
| Environment | Ludus cyber-range (QEMU/KVM, Windows Server 2022, LAF.local AD) |
| Tool | Claude Code + Protocol SIFT skills |

## What Happened

On 2026-03-08, threat actor **Saiyan Spider** exploited an OS command injection vulnerability in a public-facing IIS diagnostic page, escalated to SYSTEM via an unquoted SolarwindsTFTP service path, stole EC2 instance-role credentials via IMDS, pivoted to the Windows domain via Impacket, achieved Domain Admin in under 4 minutes, exfiltrated NTDS.dit + 164 S3 objects, and deployed `.bWqQUx` ransomware across the entire LAF.local domain. **Total time from first web request to domain compromise: ~25 minutes.**

## Evidence Summary

| Source | Records |
|---|---|
| CloudTrail (36,938 events) | Full parse |
| DC01/DC02 Security + System | 327k+ rows |
| SVR01 Memory dump (16 GB) | Volatility 3 full triage |
| WS01/WS02 all evtx | 1.75M+ rows incl. Sysmon |
| MFT (all 5 hosts) | Ransomware + tool timeline |
| IIS W3SVC logs | Full exploit chain |
| GuardDuty / S3 access logs | Cloud evidence |

## Repository Contents

```
├── render_casebook.py          # Self-contained HTML casebook generator (dark theme)
├── casebookJackofAllHacks.html # Pre-rendered casebook output
├── engagement/                 # Structured engagement data (YAML / MD / MMD)
│   ├── engagement.yaml         # Case metadata
│   ├── report.md               # Findings (F01–F05)
│   ├── timeline.md             # 30-event attack timeline
│   ├── hosts.csv               # Host/IP/role/verdict grid
│   ├── attack_graph.mmd        # Mermaid attack chain diagram
│   └── evidence/raw/           # Sanitised command transcripts
├── reports/                    # Per-domain DFIR reports
│   ├── INCIDENT_REPORT.md
│   ├── SVR01_memory_findings.md
│   ├── DC_findings.md
│   ├── WS_findings.md
│   ├── Cloud_findings.md
│   ├── GuardDuty_S3_findings.md
│   └── Jack_of_all_Hacks_Answers.txt  # CTF Q&A (34 independently verified)
├── analysis/                   # Python analysis scripts
│   ├── ct_build.py             # CloudTrail parser
│   ├── ct_real.py              # CloudTrail actor analysis
│   ├── verify_iis_cloud.txt    # IIS role credential abuse verification
│   ├── mft_verify.py           # MFT ransomware artifact verification
│   ├── ws_triage.py            # Workstation event log triage
│   └── …
└── CLAUDE.md                   # Protocol SIFT case instructions
```

## Key Findings

| ID | Title | Severity | Status |
|---|---|---|---|
| F01 | OS Command Injection — CheckStatus.aspx | CRITICAL | Pwn3d |
| F02 | Unquoted Service Path — SolarwindsTFTP | HIGH | Pwn3d |
| F03 | Impacket ADMIN$ + Domain Admin Backdoor | CRITICAL | Pwn3d |
| F04 | NTDS.dit Exfil + AWS Credential Theft | CRITICAL | Pwn3d |
| F05 | Ransomware Deployment (.bWqQUx) | CRITICAL | Pwn3d |

## IOCs

| Type | Value | Notes |
|---|---|---|
| C2 | `173.230.136.180:8443` | TLS beacon from rnSylwOz.exe + injected explorer |
| Attacker | `198.51.100.3` (RED1) | RDP to SVR01; WS01/WS02 logons |
| Attacker | `198.51.100.10` | DC01 LAFAdmin logon |
| Cloud | `212.8.249.213` | IIS role credential abuse (WorldStream) |
| Initial access | `172.236.127.251` | Web exploit + SFTP exfil |
| Implant | `rnSylwOz.exe` | `\\SVR01\ADMIN$` — PID 9112 — services.exe parent |
| Injected | `explorer.exe` PID 1332 | SHA256: `6ef6b52f…228c` |
| Ransomware | `IamBatman.exe` | ext `.bWqQUx` — note `README_bWqQUx.txt` |
| Backdoor DA | `LAF\serviceaccount` | Created 20:02 — Domain Admins 20:03 |

## Usage

```bash
# Regenerate the casebook HTML from reports
cd cases/JackofAllHacks
python3 render_casebook.py

# Output: casebookJackofAllHacks.html (self-contained, opens in any browser)
```

## MITRE ATT&CK Coverage

T1190 · T1574.009 · T1059.001/003 · T1569.002 · T1136.002 · T1098 · T1055 · T1003.001/003 · T1552.004 · T1046 · T1021.001/002 · T1053.005 · T1547.012 · T1546.013 · T1560.001 · T1048 · T1486 · T1490 · T1070.003 · T1112

---

*Generated with [Claude Code](https://claude.ai/code) · Protocol SIFT skill · Evidence is read-only KAPE triage (not included in repo)*
