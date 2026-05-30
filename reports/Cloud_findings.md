# AWS CloudTrail Findings (evidence-grounded)

Source: analysis/cloudtrail_all_events.json (36,938 events, 2026-02-23 → 2026-03-08),
rebuilt from 5,695 .json.gz across all regions. AWS account 464381121764. UTC.
Scripts: analysis/ct_ext.py, ct_real.py, ct_stoplog.py, ct_root_break.txt. Grep: ct_grep_ioc.txt.

## CORRECTION (supersedes the "no cloud compromise" headline below)
There IS a cloud component, confirmed via GuardDuty + CloudTrail (analysis/verify_iis_cloud.txt):
the **IIS EC2 instance-role credentials (iam_role_iisserver / instance i-00779ebad43b2470d) were
exfiltrated and used from 212.8.249.213 (WorldStream hosting, OutsideAWS)** on 2026-03-08
21:42:53–21:51 for AWS recon: GetCallerIdentity, ListUsers/Roles/Policies/AttachedUserPolicies,
ListBuckets/ListObjects/GetObject (x60), DescribeInstances/Snapshots/Vpcs/Volumes, AssumeRole(2),
GetSessionToken(1). GuardDuty corroborates: InstanceCredentialExfiltration.OutsideAWS (sev8) +
AttackSequence:IAM/CompromisedCredentials (sev9). No AWS *persistence* (CreateUser/AccessKey) seen.
The "no compromise" text below was WRONG for instance-role abuse; it remains correct that the AWS
ROOT account was not compromised and there was no IAM-backdoor/trail-tampering.

---

## (original) Headline: no ROOT-account compromise (still valid); instance-role abuse: see correction above
Direct grep of the full CloudTrail dataset:
- `198.51.100` (on-prem attacker net) → **0 hits**
- `173.230.136` (SVR01 C2) → **0 hits**
- `cloud_admin` → **0 hits**
The on-prem attacker IPs, C2, and any backdoor IAM user simply **do not appear** in CloudTrail.

## ConsoleLogin — all legitimate (grounded)
- Exactly **4 ConsoleLogin events**, ALL: actor=**root**, **MFA=Yes**, result=Success, source
  **216.82.9.162** — on 2026-03-01 14:55, 03-03 05:00, 03-03 23:44, 03-08 19:04.
- Single IP + MFA across multiple days = legitimate range owner/admin. No takeover indicator.

## Source IPs (grounded) — no attacker IP present
- 216.82.9.162 → root (21,191 events)
- 3.137.170.225 / 3.143.113.57 / 212.8.249.213 → EC2 instance principals (i-…), SSM
  UpdateInstanceInformation traffic. No external/human attacker IP in the data.

## root activity is overwhelmingly read-only console noise (BENIGN)
- root total 21,191 events, dominated by READ-ONLY APIs: GetObject (17,623),
  ListManagedNotificationEvents (1,758), DescribeMetricFilters (939), DescribeInstanceTypes (108),
  ListObjects (38) — i.e. S3 reads + AWS console browsing, not attack actions.
- Only **23** root events are write/sensitive across the whole window (03-01: 11, 03-03: 5,
  03-08: 7) and they are mundane: TestDNSAnswer (5), SendMessage (5), ChangeResourceRecordSets (2),
  CreateOAuth2Token (2), RunInstances (1), AssociateIamInstanceProfile (1), StopInstances (1), etc.
- **No** CreateUser / CreateAccessKey / AttachUserPolicy / PutUserPolicy bursts by root in the data
  (an earlier draft claimed ~1,163 each — that was a bug in actor-matching and is RETRACTED).

## Anti-forensics / trail tampering — NONE found
- 0 StopLogging, 0 DeleteTrail, 0 UpdateTrail, 0 PutEventSelectors, 0 DeleteUser,
  0 DeactivateMFADevice, 0 PutBucketPolicy/PutBucketAcl writes (ct_stoplog.txt = NONE).
  (An earlier draft claimed a StopLogging on "jackpot-trail" — RETRACTED; no such event exists.)

## Cloud conclusion
The confirmed 2026-03-08 intrusion is **on-prem only** (SVR01 → DC01; attacker net 198.51.100.0/24;
C2 173.230.136.180:8443). This AWS account's CloudTrail shows **no corresponding attacker activity**
— only legitimate MFA-root console use. The case-intake assumption "incident date 2026-03-01 (based
on CloudTrail)" is **not supported** by the cloud evidence; the real intrusion is 2026-03-08 on-prem.

## Pending (optional, lower priority given no cloud compromise)
- GuardDuty (1,808 findings): verify high-sev types/timestamps (analysis/guardduty_summary.txt) —
  but treat as lab-seeded unless a finding ties to 198.51.100.0/24 or the 03-08 window.
- S3 access logs (4 files): confirm no object reads tie to the attack (no CloudTrail linkage found).
