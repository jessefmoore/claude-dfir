# CLAUDE.md — JackofAllHacks Intrusion Investigation

**Protocol SIFT** — AI-assisted DFIR (experimental, not court-admissible without independent validation)

---

## Case Overview

| Field | Value |
|-------|-------|
| **Case ID** | JackofAllHacks |
| **Type** | Intrusion investigation |
| **Incident Date** | 2026-03-01 (based on CloudTrail timestamps) |
| **AWS Account** | 464381121764 (us-east-1) |
| **Threat Actor** | Unknown — to be determined through analysis |
| **Known Users** | Donny (WS01), Dalton (WS02) |
| **Your Role** | DFIR Analyst |

---

## Evidence Inventory

Evidence is **KAPE triage collections** (artifacts already extracted — no disk images, no mounting needed).

| System | Type | Path | Notes |
|--------|------|------|-------|
| DC01 | KAPE | `~/cases/JackofAllHacks/DC01/C/` | Domain Controller 1 — 569 files, 1.2 GB |
| DC02 | KAPE | `~/cases/JackofAllHacks/DC02/C/` | Domain Controller 2 — 918 files, 2.2 GB |
| IIS | KAPE | `~/cases/JackofAllHacks/IIS/E/` | Web server (E: drive) — has inetpub + **PS_Transcripts** |
| SVR01 | KAPE | `~/cases/JackofAllHacks/SVR01/C/` | Server — 1177 files |
| SVR01 | Memory | `~/cases/JackofAllHacks/SVR01/memdump/SVR01-memdump.dmp` | **16 GB Windows .dmp** |
| WS01 | KAPE | `~/cases/JackofAllHacks/WS01/C/` | Workstation — user: Donny |
| WS02 | KAPE | `~/cases/JackofAllHacks/WS02/C/` | Workstation — user: Dalton |
| Cloud | AWS | `~/cases/JackofAllHacks/cloud/` | CloudTrail, GuardDuty, S3 Access Logs |

**Read-only — do NOT modify any files under ~/cases/JackofAllHacks/<SystemName>/**
Write all output to ./analysis/, ./exports/, or ./reports/

---

## Key Artifact Paths (KAPE — no mount required)

### Event Logs
```
~/cases/JackofAllHacks/<SYSTEM>/C/Windows/System32/winevt/Logs/*.evtx
```

### Registry Hives
```
~/cases/JackofAllHacks/<SYSTEM>/C/Windows/System32/config/SYSTEM
~/cases/JackofAllHacks/<SYSTEM>/C/Windows/System32/config/SOFTWARE
~/cases/JackofAllHacks/<SYSTEM>/C/Windows/System32/config/SAM
~/cases/JackofAllHacks/<SYSTEM>/C/Users/<username>/NTUSER.DAT
```

### MFT
```
~/cases/JackofAllHacks/<SYSTEM>/C/$MFT
```

### Prefetch
```
~/cases/JackofAllHacks/<SYSTEM>/C/Windows/Prefetch/
```

### IIS — High Priority Artifacts
```
~/cases/JackofAllHacks/IIS/E/inetpub/           # web root — check for web shells
~/cases/JackofAllHacks/IIS/E/PS_Transcripts/    # PowerShell transcripts — HIGH VALUE
```

### SVR01 Memory Dump
```
~/cases/JackofAllHacks/SVR01/memdump/SVR01-memdump.dmp
```

### Cloud Artifacts
```
~/cases/JackofAllHacks/cloud/cloudtrail/AWSLogs/464381121764/CloudTrail/us-east-1/2026/03/01/*.json.gz
~/cases/JackofAllHacks/cloud/guardduty/
~/cases/JackofAllHacks/cloud/s3_access_logs/
```

---

## Common Commands

### EZ Tools — Event Logs (per system)
```bash
SYSTEM=DC01   # change per system: DC01 DC02 IIS SVR01 WS01 WS02
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d ~/cases/JackofAllHacks/${SYSTEM}/C/Windows/System32/winevt/Logs/ \
  --csv ./exports/ --csvf ${SYSTEM}_evtx.csv \
  --maps /opt/zimmermantools/EvtxeCmd/Maps/
```

### EZ Tools — MFT
```bash
dotnet /opt/zimmermantools/MFTECmd.dll \
  -f ~/cases/JackofAllHacks/${SYSTEM}/C/'$MFT' \
  --csv ./exports/ --csvf ${SYSTEM}_mft.csv
```

### EZ Tools — Registry (Kroll batch)
```bash
dotnet /opt/zimmermantools/RECmd/RECmd.dll \
  --bn /opt/zimmermantools/BatchExamples/Kroll_Batch.reb \
  -d ~/cases/JackofAllHacks/${SYSTEM}/C/Windows/System32/config/ \
  --csv ./exports/ --csvf ${SYSTEM}_registry.csv
```

### EZ Tools — Prefetch
```bash
dotnet /opt/zimmermantools/PECmd.dll \
  -d ~/cases/JackofAllHacks/${SYSTEM}/C/Windows/Prefetch/ \
  --csv ./exports/ --csvf ${SYSTEM}_prefetch.csv
```

### Volatility 3 — SVR01 Memory
```bash
VOL="python3 /opt/volatility3-2.20.0/vol.py"
MEM="/home/localuser/cases/JackofAllHacks/SVR01/memdump/SVR01-memdump.dmp"

$VOL -f $MEM windows.pslist   > ./analysis/svr01_pslist.txt
$VOL -f $MEM windows.psscan   > ./analysis/svr01_psscan.txt
$VOL -f $MEM windows.cmdline  > ./analysis/svr01_cmdline.txt
$VOL -f $MEM windows.netstat  > ./analysis/svr01_netstat.txt
$VOL -f $MEM windows.malfind  > ./analysis/svr01_malfind.txt
```

### CloudTrail — Parse all logs
```bash
for f in ~/cases/JackofAllHacks/cloud/cloudtrail/AWSLogs/464381121764/CloudTrail/us-east-1/2026/03/01/*.json.gz; do
  zcat "$f"
done | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        data = json.loads(line)
        for record in data.get('Records', []):
            print(json.dumps(record))
    except: pass
" > ./analysis/cloudtrail_all_events.json
```

### GuardDuty — Parse findings
```bash
cat ~/cases/JackofAllHacks/cloud/guardduty/*.json 2>/dev/null | python3 -m json.tool > ./analysis/guardduty_findings.json
```

### IIS — PowerShell Transcripts (HIGH PRIORITY)
```bash
find ~/cases/JackofAllHacks/IIS/E/PS_Transcripts/ -type f | sort | \
  xargs cat > ./analysis/IIS_PS_transcripts_combined.txt
```

---

## Network Topology
*To be determined from artifacts — check SYSTEM hive network interfaces and event logs.*

---

## Domain Accounts
*To be determined from DC01/DC02 artifacts.*

---

## Known IOCs
*None confirmed at case open — populate as discovered.*

---

## Incident Timeline (UTC)
*All timestamps in UTC. Populate as analysis progresses.*

| Timestamp (UTC) | Event | Source |
|-----------------|-------|--------|
| 2026-03-01 | CloudTrail activity window | CloudTrail |
| TBD | | |

---

## Analysis Notes
- **IIS PS_Transcripts are HIGH PRIORITY** — likely capture attacker PowerShell on the web server
- **SVR01 memory dump** — run Volatility triage early for live process/network state at time of capture
- **GuardDuty** findings provide AWS-side detections to correlate with on-prem artifacts
- CloudTrail `.json.gz` files must be decompressed with `zcat` before parsing
- KAPE evidence: artifacts already extracted — run EZ Tools directly on paths above, no ewfmount/mmls needed
- Vol3 binary: `/opt/volatility3-2.20.0/vol.py` — NOT `/usr/local/bin/vol.py` (that is Vol2)
- Always report timestamps in UTC
