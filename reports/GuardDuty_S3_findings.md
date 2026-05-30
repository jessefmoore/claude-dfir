# GuardDuty + S3 Access Log Findings (evidence-grounded, corrected)

> CORRECTION: earlier drafts of this file had wrong counts (GuardDuty "1,808"; S3 "8,324 reqs").
> Verified numbers below from analysis/gd_sample_check.txt and analysis/s3_summary.txt.

## GuardDuty — SAMPLE findings, not real telemetry
- **401 findings total; 383 explicitly flagged `service.additionalInfo.sample=true`.** Dates span
  2026-02-23 (387) → 03-08 (3), but the few later ones are ALSO sample: the **3 findings on 2026-03-08**
  carry `GeneratedFindingUserName` / `GeneratedFindingAPIName` / `GeneratedFindingCityName` placeholders
  and `sample=True` (verified, analysis/verify_final.txt).
- Findings enumerate ~one-of-every GuardDuty type (AttackSequence, CryptoCurrency, Kubernetes,
  Backdoor, etc.) — the signature of `guardduty:CreateSampleFindings`.
- Remote IPs are GuardDuty's canned sample addresses: 198.51.100.0 (133), 1.2.3.4 (18), 10.0.0.23 (8),
  127.0.0.1 (5) — NOT the real simulated attacker (198.51.100.3/.10) or C2 (173.230.136.180).
- IOC linkage to the real intrusion: 0 (no 173.230.136, rnSylwOz, LAFAdmin, serviceaccount, 10.3.10.x).
- **ASSESSMENT: GuardDuty content is seeded SAMPLE data (CreateSampleFindings) — disregard for this case.**

## S3 access logs — minimal, benign
- **38 requests total** across 4 files; dates 2026-03-05 (2) and 2026-03-08 (36).
- Requester IPs: **212.8.249.213 (34)**, 216.82.9.162 (2). Operations: REST.GET.OBJECT (34),
  plus single OPTIONS/HEAD/GET.LOGGING/GET.ENCRYPTION.
- No attacker-IOC linkage (0 hits for 198.51.100 / 173.230.136); no sensitive-data key names.
- ASSESSMENT: small volume of object reads from 212.8.249.213 (an EC2-associated IP also seen in
  CloudTrail) + admin IP 216.82.9.162. **No tie to the on-prem intrusion.**

## Combined cloud assessment
GuardDuty (sample data) + CloudTrail (legit MFA-root only) + S3 (38 benign reads) =
**no cloud-side compromise tied to the 2026-03-08 intrusion.** The incident is on-prem.
