# WS01 / WS02 Endpoint Triage (evidence-grounded)

> Two prior drafts of this file were WRONG and are retracted:
>  (1) a draft from a FAILED parse claimed "0 suspicious / SVR01 logons at 20:16";
>  (2) a draft claimed verified "198.51.100.x Type-3 logons (LAFAdmin ×3 etc.)" — that came from a
>      sloppy regex matching an IP ANYWHERE in the row, NOT the logon Source field. When checked
>      against the actual 4624 **RemoteHost** field, attacker-net/SVR01 source IPs = **NONE** (see below).
> This version states only what is verified.

## Parse facts (verified)
- WS evtx live under lowercase `winevt/logs/`. exports/WS01_evtx.csv = 926,393 rows;
  WS02_evtx.csv = 826,718 rows. Channels: Security, Sysmon/Operational, PowerShell, etc.
- WS01 = LAF-WS01 = 10.3.10.13 (Donny). WS02 = LAF-WS02 = 10.3.10.14 (Dalton).
- Time span 2025-03-15 (image build) → 2026-03-08 22:57.

## Verified result: NO attacker logon or implant confirmed on the workstations
- **4624 logons by RemoteHost source IP = no 198.51.100.x and no 10.3.10.12 (SVR01)** on either
  WS01 or WS02 (analysis/verify_final.txt: both `{}`). The earlier "198.51.100.10 LAFAdmin" claim
  is RETRACTED — not supported by the RemoteHost field.
- **C2 173.230.136.180 = 0 hits** on both workstations (reliable negative).
- 7045 service installs (22/23) = VirtIO/QEMU/Spice/Edge/Defender → **benign lab platform**.

## Flagged but UNVERIFIED (do not treat as attack without per-event review)
- Keyword-flagged "suspicious process creations" (WS01 729 / WS02 715) are dominated by 2026-03-03
  05:34 build-time spawns by `LAF-WS0x\localuser` (Ludus provisioning); not validated as malicious.
- "198.51.100" string appears in WS logs (Sysmon netconn / firewall / etc.) but is NOT confirmed as
  a logon source or C2; could be benign lab-WAN traffic. Needs targeted review to attribute.

## Bottom line
- On current evidence, WS01/WS02 show **no confirmed attacker activity** — no implant, no C2, and no
  verifiable attacker logon via the 4624 RemoteHost field.
- Donny/Dalton were NOT observed performing attacker actions. No evidence either workstation was the
  initial-access point.
- OPEN: a focused review of the 198.51.100 Sysmon/firewall hits and any interactive logon sessions
  would be needed to fully clear or implicate the workstations; not completed here.
