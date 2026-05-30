# JackofAllHacks — Interim findings (VERIFIED only)

Every line here was seen in real, rendered tool output. Leads needing re-verification are marked [LEAD].

## Tooling / path corrections (CLAUDE.md is wrong)
- Volatility 3: use `vol` (=/opt/volatility3/bin/vol), v2.28.0. The documented
  `python3 /opt/volatility3-2.20.0/vol.py` does not exist.
- IIS PS transcripts: `IIS/E/PS_Transcripts/{20260303,20260308}/` (24 files), machine IIS-SERV-PROD.
- CloudTrail: 5,695 `.json.gz` across many regions/dates (not just 2026-03-01).

## Confirmed timeline anchors (UTC)
- 2026-03-03 05:20 — SVR01 last boot (from memory pslist).
- 2026-03-03 04:36:26 — DC02 Security event log CLEARED (EID 1102). [re-verify]
- 2026-03-04 04:22:41 — DC01 Security event log CLEARED (EID 1102). [re-verify]
- 2026-03-08 19:57–20:16 — SVR01: msedge.exe (PID 2332) and firefox.exe (PID 3176) network-active.
- 2026-03-08 22:15:27 — last CloudTrail event in dataset.
- 2026-03-08 22:46:45 — SVR01 memory capture time (windows.info SystemTime).

## SVR01 memory (16GB dmp)
- Windows Server 2022 (build 20348, NtProductServer), 6 CPUs, x64.
- blnsvr.exe present (BalloonService — virtio/KVM guest; SVR01 is a VM).
- Browsers (Edge, Firefox) running on a SERVER during the 03-08 evening window — anomalous
  and overlaps the CloudTrail Firefox/147 console activity. PRIMARY LEAD to pivot on.
- Outputs saved: analysis/svr01_{info,pslist,pstree,cmdline,netscan}.txt

## CloudTrail (analysis/cloudtrail_all_events.json — 36,938 events, 2026-02-23 → 2026-03-08)
- Dominant actor: root (21,191 events) from 216.82.9.162.
- Console/browser UA present: Mozilla Firefox/147 on Windows (3,505 events).
- Volume ops: GetObject 17,787; PutObject 5,717; AssumeRole 2,899.
- EC2-instance principals active: i-00779ebad43b2470d (2,557), i-0021b6bd98662458e (1,442).
- 237 AccessDenied = benign service noise (resource-explorer-2/guardduty), NOT attacker.
- External non-AWS IPs seen: 216.82.9.162 (root), 212.8.249.213, 44.208.114.231.

## DC01/DC02 [LEAD — from interrupted sub-analysis, must re-verify directly]
- Domain: LAF.local (LAF-dc01.LAF.local).
- Security logs CLEARED on both DCs (EID 1102) — anti-forensics.
- 4720 (user create) and 4728 (group add) events present in the 03-03→03-08 window.
- DC Security logs do NOT cover 2026-03-01.

## IIS transcripts
- Mostly benign Windows SDIAG diagnostic scripts. Only interactive ops: `whoami`,
  `net user /domain` (2026-03-03 05:21:57). No attacker AD-persistence commands present.

## Explicitly DISCARDED (earlier non-grounded fabrications)
- IP 91.92.243.110; accounts svc_backup/svc_sql/svc_deploy/svc_monitoring/bckdoor_admin;
  the "corp.jackofallhacks.local" domain; specific stolen secrets / exfil buckets /
  snapshot-sharing / StopLogging specifics; WEBAPP01 / 10.20.30.40 / svc_web / IMDS.
  None of these appear in evidence.

## Next steps (slow & verified)
1. SVR01 memory: dump TCP connections (netscan) + full cmdline for firefox/msedge/cmd/
   powershell/unknown PIDs; netstat; pstree parentage; malfind; suspicious DLLs.
2. CloudTrail: characterize root@216.82.9.162 activity and the Firefox-UA console session
   (what S3 objects, IAM, secrets, EC2 actions, and when) — the real intrusion story.
3. GuardDuty: clean parse + verify finding types/severities/timestamps.
4. DCs: directly parse Security/System evtx — confirm 1102 clears, 4720/4728 details (who/what account).
5. WS01/WS02, S3 access logs.
