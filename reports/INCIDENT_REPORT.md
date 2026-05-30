# JackofAllHacks — Consolidated Incident Report
**Protocol SIFT (AI-assisted DFIR — experimental; verify independently before court use)**
Analyst: DFIR Orchestrator | All timestamps UTC | Status: findings grounded in parsed tool output

---

## 1. Executive Summary
On **2026-03-08**, the LAF.local environment suffered a hands-on-keyboard intrusion. An external
actor on **198.51.100.0/24** gained access to **LAF-SVR01 (10.3.10.12)**, ran a named-randomly
implant from the host's ADMIN$ share, injected a C2 beacon into `explorer.exe` (C2
**173.230.136.180:8443**), then operated as Domain Admin **LAF\LAFAdmin** to compromise the domain:
creating a backdoor Domain Admin account on **DC01 (10.3.10.10)**, and moving laterally to DC02.
Separately, the red-team hosts **RED1 (198.51.100.3)** and **RED-KALI (198.51.100.5)** logged into
**WS01 as Donny** and **WS02 as Dalton** — including interactive **RDP** — using those compromised
user credentials. The attack thus spans the whole domain (servers, DCs, and both workstations).

**The AWS cloud account shows no related compromise** — CloudTrail/GuardDuty/S3 contain only
legitimate MFA-root administration and pre-incident lab noise. This is an **on-prem incident**.

Environment note: this is a **virtualized Ludus cyber-range / CTF build** (QEMU/KVM; KAPE+DumpIt
collection). Range-provisioning automation was carefully separated from attacker activity below.

---

## 2. Confirmed Attack Timeline (UTC, 2026-03-08)
| Time | Host | Event | Evidence |
|------|------|-------|----------|
| 19:57–19:59 | SVR01 | `rnSylwOz.exe` launched from `\\10.3.10.12\ADMIN$` by services.exe; C2 to 173.230.136.180:8443 | memory netscan/pstree |
| 20:01:16 | SVR01 | `explorer.exe` (PID 1332) beacons to same C2; injected PE (MZ) in RWX (malfind) | memory malfind |
| 20:02:14 | DC01 | LAFAdmin (network logon from 10.3.10.12) creates domain user `serviceaccount` | DC01 Security 4720/4624 |
| 20:02–20:13 | SVR01 | attacker cmd.exe / powershell.exe under explorer | memory pstree |
| 20:03:05 | DC01 | `serviceaccount` added to **Domain Admins** | DC01 Security 4728 |
| 20:08:34 | DC01 | LAFAdmin network logon from **198.51.100.10** | DC01 Security 4624 |
| 20:08:44–20:09:04 | DC01 | 5× Impacket-style service exec (random names, `%COMSPEC% /Q /c echo … ADMIN$`) | DC01 Security 4697 |
| 20:16:23 | WS01 | LAFAdmin Type-3 logon from SVR01 (10.3.10.12) | WS01 Security 4624 |
| 20:16:46 | WS02 | LAFAdmin Type-3 logon from SVR01 (10.3.10.12) | WS02 Security 4624 |
| 22:06:35 | SVR01→DC02 | outbound RDP to 10.3.10.11 | memory netscan |
| (03-08) | WS01 | RED1 (198.51.100.3) & RED-KALI (.5) logon as `LAF\Donny` incl. RDP (Type 10); SVR01 as Administrator | WS01 4624 RemoteHost |
| (03-08) | WS02 | RED1 (198.51.100.3) logon as `LAF\Dalton` incl. RDP; SVR01 as Administrator | WS02 4624 RemoteHost |
| 22:30:21 | SVR01 | inbound RDP from **198.51.100.3 (RED1)** | memory netscan |
| 22:46:45 | SVR01 | memory captured (KAPE/DumpIt) | windows.info |

---

## 3. Attack Narrative (kill chain)
1. **Initial access / staging — SVR01 (10.3.10.12).** Implant `rnSylwOz.exe` executed from ADMIN$
   as a service (PsExec/Impacket pattern); beacon injected into `explorer.exe`. C2 173.230.136.180:8443.
   Inbound RDP from attacker net 198.51.100.3 (22:30).
2. **Privilege context.** Operated as **LAF\LAFAdmin** (Domain Admin); network logons to DC01
   originate from SVR01 (112×) and once from external 198.51.100.10.
3. **Domain dominance — DC01 (10.3.10.10).** Created `LAF\serviceaccount` → added to **Domain Admins**;
   ran Impacket-style remote commands (5× 4697 random-name services).
4. **Lateral movement.** SVR01 → DC02 (RDP), WS01 & WS02 (SMB/network logon as LAFAdmin, 20:16),
   Kerberos to DC01, SMB to .13/.14.
5. **Impact/persistence.** Backdoor Domain Admin account `serviceaccount` provides durable domain access.
6. **Cloud.** No attacker activity in AWS (see §5).

---

## 4. Scope / Affected Systems
| Host | IP | Role | Status |
|------|----|------|--------|
| LAF-SVR01 | 10.3.10.12 | Server | **Compromised** — implant, C2, attacker shells (primary pivot) |
| LAF-DC01 | 10.3.10.10 | Domain Controller | **Compromised** — DA backdoor created, remote exec |
| LAF-DC02 | 10.3.10.11 | Domain Controller | **Targeted** — inbound RDP from SVR01 |
| LAF-WS01 | 10.3.10.13 | Workstation (Donny) | **Targeted** — LAFAdmin network logon from SVR01 |
| LAF-WS02 | 10.3.10.14 | Workstation (Dalton) | **Targeted** — LAFAdmin network logon from SVR01 |
| IIS-SERV-PROD | 10.3.10.15 | Web server | No attacker activity confirmed (transcripts benign) |
| AWS 464381121764 | — | Cloud | **No compromise** evident |

---

## 5. Cloud Assessment (negative finding)
- **CloudTrail** (36,938 events): only legitimate ConsoleLogins = root + MFA from 216.82.9.162;
  no attacker IP; no IAM backdoor; no trail tampering (0 StopLogging/DeleteTrail).
- **GuardDuty** (1,808 findings): all 2026-02-23→28 (pre-incident), low-sev, zero IOC linkage.
- **S3 access logs** (8,324 reqs, 03-08): bulk GETs from hosting IPs; no attacker-IOC linkage.
- Conclusion: cloud is **not** part of this intrusion. Case-intake "2026-03-01 CloudTrail" premise
  is unsupported by evidence.

---

## 6. MITRE ATT&CK (observed)
- **Execution:** T1569.002 Service Execution (Impacket/PsExec); T1059.001 PowerShell, T1059.003 cmd.
- **Lateral Movement:** T1021.002 SMB/Admin Shares; T1021.001 RDP.
- **Persistence/PrivEsc:** T1136.002 Create Account (domain); T1098 Account Manipulation (Domain Admins).
- **Defense Evasion:** T1055 Process Injection (explorer.exe); T1070.001 (DC log clears — see caveat §8).
- **C2:** T1071 / T1571 (173.230.136.180:8443).
- **Credential Access (context):** privileged LAFAdmin reuse from SVR01.

---

## 7. IOC List
**Network**
- C2: `173.230.136.180:8443`
- Attacker subnet: `198.51.100.0/24` (TEST-NET-3 lab WAN). Hosts: **RED1 = 198.51.100.3**
  (→ SVR01 RDP; WS01 as Donny; WS02 as Dalton, incl. RDP), **RED-KALI = 198.51.100.5** (WS logons),
  **198.51.100.10** (→ DC01 LAFAdmin logon; WS Administrator logons).
  NOTE: `198.51.100.0` / `203.0.113.7` in GuardDuty are unrelated sample-finding canned addresses.

**Host / files**
- Implant: `rnSylwOz.exe` at `\\10.3.10.12\ADMIN$\rnSylwOz.exe` (random 8-char name; parent services.exe)
- Injected process: `explorer.exe` PID 1332 on SVR01 (RWX PE at 0xa60000)
- DC01 Impacket service names (random): `UnmfmnOL, QsYyAARL, XCCVTGUb, SOUwKZNf, PovLjNTr`
  with `%COMSPEC% /Q /c echo %COMSPEC% /C ... > \\...\ADMIN$\...`

**Accounts**
- Compromised privileged: `LAF\LAFAdmin` (Domain Admin, used from SVR01); `LAF\Administrator` (used from SVR01 to WS01/WS02)
- Compromised user accounts: `LAF\Donny` (WS01), `LAF\Dalton` (WS02) — used by RED1/RED-KALI
- Attacker-created backdoor Domain Admin: `LAF\serviceaccount` (created DC01 2026-03-08 20:02; added DA 20:03)

**Detection events**
- DC01 4720+4728 (serviceaccount→Domain Admins) 2026-03-08 20:02–20:03
- DC01 4697 random-name services 20:08–20:09
- WS01/WS02 4624 Type 3 LAFAdmin from 10.3.10.12 at 20:16

---

## 8. Caveats / Analyst Notes
- **DC log clears (1102)** on DC01 (03-04 04:22) and DC02 (03-03 04:36) were by the `localuser`
  *builder* account during the range-build window — flagged but most consistent with **Ludus
  provisioning**, not necessarily attacker anti-forensics. DC Security logs therefore only retain
  events from those clears onward.
- High-volume root/216.82.9.162 CloudTrail and DC02 per-session services were assessed **benign**
  (lab automation/normal Windows) and excluded from attacker findings.
- Tooling correction: Volatility 3 = `vol` (/opt/volatility3/bin/vol), NOT the path in CLAUDE.md.
  Workstation evtx live under lowercase `winevt/logs/`.

## 9. Supporting Reports
- reports/SVR01_memory_findings.md · reports/DC_findings.md · reports/WS_findings.md
- reports/Cloud_findings.md · reports/GuardDuty_S3_findings.md
- Evidence/exports under ./analysis/ and ./exports/.

## 10. Recommendations
1. Disable/delete `LAF\serviceaccount`; force-reset `LAF\LAFAdmin` and all Domain Admins; rotate krbtgt (×2).
2. Isolate & rebuild SVR01 (10.3.10.12); hunt `rnSylwOz.exe` and 173.230.136.180 across the estate.
3. Block 173.230.136.180 and 198.51.100.0/24 at perimeter; review RDP exposure.
4. Restrict ADMIN$/service-creation; enable LSASS protection; deploy/verify Sysmon on all DCs/servers.
5. Verify whether the DC 1102 clears were build vs. attacker; ensure central log forwarding (WEF/SIEM).
