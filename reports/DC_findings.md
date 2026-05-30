# DC01 / DC02 Security Log Findings (evidence-grounded)

Source: EvtxECmd parse of Security.evtx → exports/DC01_security.csv (110,306 rows),
exports/DC02_security.csv (217,091 rows). Digest: analysis/dc_security_digest.txt. UTC.
Hosts: LAF-dc01.LAF.local, LAF-DC02 (domain LAF.local).

## CONFIRMED attacker activity on DC01 — 2026-03-08 (matches SVR01 intrusion window)
Performed under the **LAF\LAFAdmin** account (RID 1112) — the same privileged identity whose
SVR01 session was beacon-injected (see SVR01 report):
- **20:02:14  4720 UserCreated → `LAF\serviceaccount`** (then 4722 enabled, 4724 password set).
- **20:03:05  4728 AddToGlobalGroup → `serviceaccount` added to `Domain Admins`**
  (Member: CN=serviceaccount,CN=Users,DC=LAF,DC=local). => domain-dominance backdoor account.
- **20:08:44–20:09:04  five 4697 ServiceInstalled** with random names
  (UnmfmnOL, QsYyAARL, XCCVTGUb, SOUwKZNf, PovLjNTr), ServiceFileName
  `%COMSPEC% /Q /c echo %COMSPEC% /C ... > \\...\ADMIN$\...` — the classic **Impacket
  smbexec/psexec** remote-execution signature. Same tradecraft as the ADMIN$ service exec
  (`rnSylwOz.exe`) seen on SVR01. => attacker ran remote commands on DC01.
- 21:01:00  4738 UserChanged on `serviceaccount` by NT AUTHORITY\ANONYMOUS LOGON.

## Anti-forensics — log clears (EID 1102) — flagged, but timing is ambiguous
- DC01: **1102 SecurityLogCleared 2026-03-04 04:22:41 by LAF\localuser** (SID …-1000).
- DC02: **1102 SecurityLogCleared 2026-03-03 04:36:26 by LAF-DC02\localuser**.
CAUTION: both clears occurred during the **2026-03-03/04 range-build window**, performed by the
`localuser` builder account, and on DC01 were immediately followed (04:22–04:27) by a batch of
4724 password-resets across many lab accounts (domainuser, domainadmin, Dalton, Ryan, Donny,
LAFAdmin, Jason, Gilles, srv_LAF). This pattern is consistent with **Ludus range provisioning**,
not necessarily attacker anti-forensics. A side effect: DC Security logs only retain events from
the clear onward (DC01 from 03-04 04:22; DC02 from 03-03 04:36).

## Assessed BENIGN (lab build / normal Windows) — explicitly excluded as attack artifacts
- DC02 03-03 to 03-06: machine-account enable/pwreset for IIS-SERV-PROD$, LAF-SVR01$, LAF-WS01$
  (domain join); WIN-0T8587HRAFN$ / WDAGUtilityAccount / Guest changes (Windows Sandbox build).
- DC02 ~40 × 4697 "ServiceInstalled" named CaptureService_/cbdhsvc_/CDPUserSvc_/UnistoreSvc_ etc.
  with random hex suffixes = **normal Windows per-logon-session user services**, not malicious.
- MozillaMaintenance service (03-06) = Firefox updater, benign.

## Newly confirmed facts for correlation
- Compromised privileged account driving on-prem attack: **LAF\LAFAdmin**.
- Attacker-created domain backdoor: **LAF\serviceaccount** → **Domain Admins** (2026-03-08 20:03).
- Tooling: Impacket-style ADMIN$ service execution on both DC01 and SVR01.
- DC IPs (to confirm): DC01/DC02 in 10.3.10.0/24; SVR01 memory showed Kerberos to 10.3.10.10.

## Lateral-movement source CONFIRMED (4624/4672)
- LAFAdmin logons to DC01 during the attack are **LogonType 3 (network)**, overwhelmingly
  **from 10.3.10.12 = SVR01** (112 of ~120 LAFAdmin logons). => the DC01 compromise was driven
  **from SVR01** (Impacket over SMB), consistent with SVR01 being the staging host.
- One LAFAdmin network logon to DC01 **from external 198.51.100.10 at 2026-03-08 20:08:34**
  (immediately before the Impacket service installs) — direct attacker-network access too.
- Each 4720/4728/4697 action is preceded by SeSecurityPrivilege 4672 admin logons for LAFAdmin (RID 1112).

## DCSync — NOT observed
- 114 × EID 4662 on DC01 are routine hourly "Operation performed on an object" by the DC machine
  account (LAF-dc01$, lsass PID 740). **Zero** 4662 with DS-Replication-Get-Changes GUIDs tied to
  serviceaccount/LAFAdmin => no DCSync evidence.

## Attacker network IOC
- **198.51.100.0/24** (TEST-NET-3 lab "internet"): 198.51.100.10 (LAFAdmin→DC01), 198.51.100.3
  (inbound RDP→SVR01 22:30, per memory). 

## Internal host/IP map (CONFIRMED via machine-account 4624/4768/4769 on DCs)
- 10.3.10.10 = LAF-DC01   (7091 machine-acct auths)
- 10.3.10.11 = LAF-DC02   (8720)
- 10.3.10.12 = LAF-SVR01  (1447; also matches memory)
- 10.3.10.13 = LAF-WS01   (Donny, 1449)
- 10.3.10.14 = LAF-WS02   (Dalton, 1422)
- IIS-SERV-PROD: **IP NOT resolved** (RECmd run failed; no CSV produced). Unknown — do not assume.
Source data: analysis/ip_host_final.txt.

## SVR01 network activity re-interpreted with the map
- SVR01 -> 10.3.10.11:3389 (RDP, 22:06) = SVR01 -> DC02 RDP (lateral movement to DC02).
- SVR01 lsass -> 10.3.10.10:88 (Kerberos) = to DC01. SVR01 -> 10.3.10.13/.14 SMB = to WS01/WS02.
- DC01 attack logons (LAFAdmin, Type 3) from 10.3.10.12 = from SVR01. => SVR01 = primary pivot.
