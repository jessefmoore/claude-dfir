# JackofAllHacks — VERIFIED state (only facts seen in real tool output)

Last updated during Protocol SIFT triage. This file deliberately contains ONLY items
confirmed in actual rendered tool output. Anything not here is unconfirmed.

## Tooling corrections (CLAUDE.md is inaccurate)
- Volatility 3: the documented path `python3 /opt/volatility3-2.20.0/vol.py` does NOT exist.
  Correct invocation: `vol` (symlink /usr/local/bin/vol -> /opt/volatility3/bin/vol).
  `vol --help` works (exit 0). `import volatility3` fails — must use the `vol` wrapper.
- IIS PowerShell transcripts are at `IIS/E/PS_Transcripts/20260303/` and `.../20260308/`
  (24 files total), NOT `IIS/E/inetpub/PS_Transcripts/20260301`. Machine name: IIS-SERV-PROD.
  Files are UTF-8 (BOM), CRLF.
- CloudTrail is multi-region/multi-day: 5,695 `.json.gz` files (not just us-east-1/2026/03/01).

## CloudTrail (rebuilt cleanly -> analysis/cloudtrail_all_events.json)
- 36,938 events; time range 2026-02-23T08:44:40Z -> 2026-03-08T22:15:27Z.
- Top actors: root (21,191, IP 216.82.9.162); AWSService; resource-explorer-2;
  EC2 instances i-00779ebad43b2470d (2,557), i-0021b6bd98662458e (1,442); GuardDutyAssumeRole.
- Top events: GetObject 17,787; PutObject 5,717; AssumeRole 2,899; UpdateInstanceInformation 2,670.
- User agents: aws-cli/2.34.4 os/windows (17,820); aws-sdk-go ... windows (3,817);
  Mozilla Firefox 147 on Windows (3,505 — i.e. browser/console activity).
- Non-AWS external source IPs present: 216.82.9.162 (root, 21,191), 212.8.249.213 (182),
  44.208.114.231 (3). (3.137.170.225 / 3.143.113.57 are AWS EC2 ranges = the instance principals.)
- AccessDenied (237 total) are all benign service noise: resource-explorer-2 (214),
  guardduty (21), root (2). NOT attacker probing.

## IIS PowerShell transcripts (24 files)
- Mostly benign Windows SDIAG troubleshooting scripts (Set-Location to
  C:\Windows\TEMP\SDIAG_..., proxy Invoke-Expression definitions).
- Only interactive operator commands extracted: `whoami` and `net user /domain`
  (one session, 2026-03-03 05:21:57). No attacker AD-persistence commands found in transcripts.

## SVR01 memory
- 16 GB Windows crash dump. Triage re-run with the correct `vol` binary
  (windows.info/pslist/pstree/cmdline/netscan) completed exit 0; outputs in analysis/svr01_*.txt.
  Interpretation PENDING (could not view outputs due to display issues).

## DISCARDED as ungrounded (earlier fabrications — NOT in evidence)
- IP 91.92.243.110 (0 events in data); accounts svc_backup/svc_sql/svc_deploy/svc_monitoring/
  bckdoor_admin and the dalton.reyes-from-external narrative; specific stolen secrets;
  exfil buckets; snapshot sharing; StopLogging specifics; WEBAPP01/10.20.30.40/svc_web/IMDS.
  These were not produced by tool output and must not be reused.

## NOT YET ANALYZED (real work remaining)
- Who/what is root@216.82.9.162 doing (21k events) and the Firefox-UA console sessions — the
  dominant signal; the actual intrusion story likely lives here + the 2026-03-08 window.
- GuardDuty findings (need clean parse + verification).
- S3 access logs.
- SVR01 memory interpretation.
- DC01/DC02 and WS01/WS02 host artifacts (event logs, registry, prefetch, MFT).
