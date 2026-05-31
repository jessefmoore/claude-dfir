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

## Interactive Casebook

`casebook_JackofAllHacks.html` is a self-contained interactive HTML report. Open it in any browser to get:

- **Kill-chain replay** — animated attack timeline with play/pause and 1×/60×/240×/900× speed
- **SVG attack graph** — color-coded forensic edges, host nodes that pulse as they fall
- **Scrubber bar** — 15-minute ticks, event markers, and phase separators
- **Event log** — real-time event card updating during replay
- **28 forensic sections** — executive summary, act-by-act narrative, TTPs, IOCs, Volatility output, IIS artifacts, NTDS exfil, cloud pivot, memory analysis, evidence ledger, and appendices

All content is grounded in collected KAPE triage artifacts and Volatility 3 output. C2 binary RE analysis (not performed in this engagement) is explicitly omitted.

## Reusable Casebook Generator

`generate_dfir_casebook.py` adapts the reference template to any DFIR case. To generate a casebook for a new case:

```bash
# 1. Copy the generator and template to your case directory
cp generate_dfir_casebook.py /path/to/new-case/
cp reference_casebook.html   /path/to/new-case/

# 2. Populate engagement/ with these four files:
#      engagement.yaml   — case metadata (engagement_id, client, headline, tooling, …)
#      timeline.md       — ## Phase N · Name headers + | YYYY-MM-DD HH:MM:SS | HOST | desc | source | rows
#      report.md         — findings narrative (F01–FXX)
#      hosts.csv         — host,ip,role,finding_id,proto,port,verdict

# 3. Run
python3 generate_dfir_casebook.py --case /path/to/new-case

# Output: casebook_<case_id>.html
```

The generator automatically:
- Removes the C2 RE-attribution section (requires separate binary analysis not in standard triage)
- Replaces all tool-specific attribution text with evidence-grounded language
- Redacts AWS key IDs and secret keys for safe publication
- Injects the case timeline into the interactive replay engine
- Reports an evidence integrity check (0 unsupported attribution claims)

## Repository Contents

```
├── generate_dfir_casebook.py    # Reusable interactive casebook generator
├── reference_casebook.html      # Base template (Aleemladha/lehack2024 format)
├── casebook_JackofAllHacks.html # Final interactive casebook — open in browser
├── engagement/
│   ├── engagement.yaml          # Case metadata
│   ├── report.md                # Findings (F01–F05)
│   ├── timeline.md              # 42-event UTC attack timeline
│   ├── hosts.csv                # Host/IP/role/verdict grid
│   ├── attack_graph.mmd         # Mermaid attack chain diagram
│   └── evidence/raw/            # Sanitised command transcripts
├── reports/
│   ├── INCIDENT_REPORT.md
│   ├── SVR01_memory_findings.md
│   ├── DC_findings.md
│   ├── WS_findings.md
│   ├── Cloud_findings.md
│   ├── GuardDuty_S3_findings.md
│   └── Jack_of_all_Hacks_Answers.txt  # CTF Q&A (34 independently verified)
├── analysis/                    # Python analysis scripts
│   ├── ct_build.py              # CloudTrail parser
│   ├── ct_real.py               # CloudTrail actor analysis
│   ├── mft_verify.py            # MFT ransomware artifact verification
│   ├── ws_triage.py             # Workstation event log triage
│   └── …
└── CLAUDE.md                    # Protocol SIFT case instructions
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
| C2 | `173.230.136.180:8443` | TLS beacon from rnSylwOz.exe + injected explorer.exe |
| Attacker | `198.51.100.3` (RED1) | RDP to SVR01; WS01/WS02 logons |
| Attacker | `198.51.100.10` | DC01 LAFAdmin logon |
| Cloud exfil | `212.8.249.213` | IIS role credential abuse (WorldStream NL) |
| Initial access | `172.236.127.251` | Web exploit + certutil drop |
| Implant | `rnSylwOz.exe` | `\\SVR01\ADMIN$` — PID 9112 — services.exe parent |
| Injected | `explorer.exe` PID 1332 | RWX PE at 0xa60000, SHA256: `6ef6b52f…228c` |
| Ransomware | `IamBatman.exe` | ext `.bWqQUx` — drops `README_bWqQUx.txt` |
| Backdoor DA | `LAF\serviceaccount` | Created 20:02 UTC — added to Domain Admins 20:03 UTC |

## MITRE ATT&CK Coverage

T1190 · T1574.009 · T1059.001/003 · T1569.002 · T1136.002 · T1098 · T1055 · T1003.001/003 · T1552.004 · T1046 · T1021.001/002 · T1053.005 · T1547.012 · T1546.013 · T1560.001 · T1048 · T1486 · T1490 · T1070.003 · T1112

## License

This project is released under the [MIT License](LICENSE). You are free to use, modify, and build on the generator, engagement schema, and casebook format for your own DFIR work — commercial or otherwise. Attribution appreciated but not required.

The interactive casebook template (`reference_casebook.html`) retains its original copyright by [aleemladha](https://github.com/aleemladha) — see Attribution below.

## Attribution

The interactive casebook format — phosphor-green CRT aesthetic, kill-chain replay engine, animated SVG attack graph, scrubber bar, and overall report structure — is based on the **LeHack 2024 DFIR casebook** by [aleemladha](https://github.com/aleemladha). `reference_casebook.html` is that original work, used here as the base template for `generate_dfir_casebook.py`.

---

*Generated with [Claude Code](https://claude.ai/code) · Protocol SIFT skill · Evidence is read-only KAPE triage (not included in repo)*
