# SVR01 Memory Analysis — VERIFIED findings

Source: SVR01-memdump.dmp (16 GB). Tool: Volatility 3 v2.28.0 (`vol`).
All items below were seen in rendered plugin output (analysis/svr01_{info,pslist,pstree,cmdline,netscan}.txt).

## Host / capture
- Windows Server 2022 (build 20348, NtProductServer), x64, 6 CPUs.
- Hostname/IP: SVR01 = **10.3.10.12**; domain **LAF.local**; local users seen: LAFAdmin, donny.
- Last boot: 2026-03-03 05:20 UTC. **Memory captured 2026-03-08 22:46:45 UTC.**
- Virtualization: qemu-ga.exe + blnsvr.exe (QEMU/KVM guest). `C:\ludus\background\set-bg.ps1`
  runs repeatedly = **Ludus cyber-range automation**. Evidence collected by **kape.exe** (PID 9656,
  `C:\Kape\kape\kape.exe ... --module DumpIt_Memory`, zip `null_ctf`) at 22:45–22:47 — i.e. this is a
  built training/CTF scenario, and KAPE's own outbound 443 connections (52.149.199.118 etc.) are
  collection traffic, NOT attacker activity.

## CONFIRMED malicious activity on SVR01

### Initial execution on SVR01 = PsExec/Impacket-style remote SMB service exec (CONFIRMED)
- **`rnSylwOz.exe` (PID 9112)**, image path **`\\10.3.10.12\ADMIN$\rnSylwOz.exe`**, **parent PID 672 = services.exe**,
  started 2026-03-08 19:59:00 UTC. Randomly-named binary launched as a service from the host's own ADMIN$
  share = classic PsExec / Impacket `psexec`/`smbexec` / C2 "jump psexec" lateral-movement signature.
  => SVR01 was compromised via remote SMB execution (lateral movement INTO 10.3.10.12).

### Implant + C2
- **`rnSylwOz.exe` (PID 9112)** held an **ESTABLISHED TCP connection to 173.230.136.180:8443 at
  2026-03-08 19:59:00 UTC** (netscan, offset 0xa88f527ec9a0).
- **`explorer.exe` (PID 1332)** connected to the **same C2 (173.230.136.180:8443) at 20:01:16** (offset 0xa88f4a4f37f0).
- **malfind CONFIRMS injection**: explorer.exe (1332) has an injected **PE image (MZ header) in
  PAGE_EXECUTE_READWRITE memory at 0xa60000** — i.e. the beacon was injected into explorer.
- => **C2 IOC: 173.230.136.180:8443**; implant file IOC: rnSylwOz.exe (random name) in ADMIN$.

### Hands-on-keyboard (children of explorer.exe PID 1332)
- powershell.exe PID 4896 — started 2026-03-08 20:03:05
- cmd.exe PID 15116 — started 2026-03-08 20:02:14
- cmd.exe PID 15080 — started 2026-03-08 20:13:26
- powershell.exe PID 5628 — started 2026-03-08 21:08:24
  (set-bg.ps1 powershell instances are Ludus background noise, excluded.)

### Lateral movement / internal network (10.3.10.0/24)
- explorer.exe (1332) -> **10.3.10.11:3389 (RDP)** ESTABLISHED 2026-03-08 22:06:35 (outbound RDP / lateral)
- Inbound **RDP from 198.51.100.3 -> SVR01:3389** ESTABLISHED 2026-03-08 22:30:21 (svchost 1084)
- lsass -> **10.3.10.10:88** (Kerberos; 10.3.10.10 = a DC)
- System(4) SMB(445) to **10.3.10.13** and **10.3.10.14** (03-04 and 03-08)
- Internal hosts inferred: DC 10.3.10.10; RDP target 10.3.10.11; SMB peers 10.3.10.13, 10.3.10.14

## Multiple interactive/RDP logon sessions (pstree)
- Distinct winlogon/userinit/explorer trees at session IDs 2,3,5,6,7 created 2026-03-07 14:47,
  2026-03-08 20:14:08, 22:12:39, 22:30:21 — repeated interactive/RDP logons during the intrusion window.
- LAFAdmin session 2: explorer 1332 (injected) -> spawned the attacker cmd/powershell + beaconed to C2.
- donny session 3: explorer 880 -> chrome.exe (user browsing).

## Pending / supporting
- Map 10.3.10.10/.11/.13/.14 to DC01/DC02/WS01/WS02/IIS via registry/event logs (10.3.10.10 = DC, Kerberos).
- dlllist/handles for PID 9112; dump rnSylwOz.exe (vol windows.dumpfiles / pslist --dump) for hash + YARA.
- Decode the cmd/powershell (PIDs 15116/15080/4896/5628) activity via console history / Sysmon (Sysmon64.exe IS running -> Microsoft-Windows-Sysmon/Operational evtx on disk).

## Note on prior cloud claims
The CloudTrail/GuardDuty narrative drafted earlier (specific IAM users, secrets, buckets, the IP
91.92.243.110) was NOT grounded and has been discarded. Cloud re-analysis is pending and will be
rebuilt from analysis/cloudtrail_all_events.json (36,938 real events) only.
