#!/usr/bin/env python3
import csv, collections, sys, os
HOSTS = ['DC01','DC02','SVR01','WS01','WS02']
BASE = os.path.expanduser('~/cases/JackofAllHacks/exports')

def search_mft(host, terms, field='FileName', case_insensitive=True, extra_fields=None):
    """Search a host MFT CSV for rows where field contains any term."""
    fp = os.path.join(BASE, f'{host}_mft.csv')
    results = []
    try:
        with open(fp, encoding='utf-8', errors='replace') as f:
            for row in csv.DictReader(f):
                val = (row.get(field) or '').lower() if case_insensitive else (row.get(field) or '')
                for t in terms:
                    chk = t.lower() if case_insensitive else t
                    if chk in val:
                        r = {
                            'host': host,
                            'name': row.get('FileName',''),
                            'path': row.get('ParentPath',''),
                            'created': row.get('Created0x10',''),
                            'modified': row.get('LastModified0x10',''),
                            'deleted': row.get('IsDeleted',''),
                            'size': row.get('FileSize',''),
                        }
                        if extra_fields:
                            for ef in extra_fields:
                                r[ef] = row.get(ef,'')
                        results.append(r)
                        break
    except Exception as e:
        results.append({'host': host, 'error': str(e)})
    return results

out = []
out.append('=== MFT VERIFICATION ===')

# 1. Ransomware extension .bWqQUx
out.append('\n--- 1. Files with .bWqQUx extension (per host) ---')
for h in HOSTS:
    hits = search_mft(h, ['.bWqQUx'])
    out.append(f'{h}: {len(hits)} hits')
    for r in hits[:2]:
        out.append(f'  {r["created"]} | {r["path"]}\\{r["name"]}')

# 2. Ransom note README_bWqQUx.txt
out.append('\n--- 2. Ransom note README_bWqQUx.txt (per host) ---')
for h in HOSTS:
    hits = search_mft(h, ['README_bWqQUx'])
    out.append(f'{h}: {len(hits)} hits')
    for r in hits[:1]:
        out.append(f'  {r["created"]} | {r["path"]}\\{r["name"]}')

# 3. Earliest .bWqQUx per host (first encryption)
out.append('\n--- 3. Earliest .bWqQUx created timestamp per host ---')
for h in HOSTS:
    hits = search_mft(h, ['.bWqQUx'])
    times = sorted([r['created'] for r in hits if r.get('created')], reverse=False)
    out.append(f'{h}: earliest={times[0] if times else "NONE"}  total={len(hits)}')

# 4. IAmBatman.exe / lamBatman.exe
out.append('\n--- 4. IAmBatman.exe / lamBatman.exe ---')
for h in HOSTS:
    hits = search_mft(h, ['iambatman','lambatman'])
    for r in hits:
        out.append(f'{h}: {r["created"]} | {r["path"]}\\{r["name"]}')
    if not hits:
        out.append(f'{h}: NOT FOUND')

# 5. aws_backup.exe on WS01
out.append('\n--- 5. aws_backup.exe (WS01) ---')
hits = search_mft('WS01', ['aws_backup'])
for r in hits:
    out.append(f'WS01: {r["created"]} | {r["path"]}\\{r["name"]}')
if not hits:
    out.append('WS01: NOT FOUND')

# 6. abedgdaa.dmp on SVR01
out.append('\n--- 6. abedgdaa.dmp (SVR01) ---')
hits = search_mft('SVR01', ['abedgdaa'])
for r in hits:
    out.append(f'SVR01: {r["created"]} | {r["path"]}\\{r["name"]} size={r["size"]}')
if not hits:
    out.append('SVR01: NOT FOUND')

# 7. Data.cab and msupdate.exe on SVR01
out.append('\n--- 7. Data.cab and msupdate.exe (SVR01) ---')
for term in ['data.cab','msupdate']:
    hits = search_mft('SVR01', [term])
    for r in hits:
        out.append(f'SVR01 [{term}]: {r["created"]} | {r["path"]}\\{r["name"]}')
    if not hits:
        out.append(f'SVR01 [{term}]: NOT FOUND')

# 8. ZIFylmKF.tmp on DC01
out.append('\n--- 8. ZIFylmKF.tmp (DC01) ---')
hits = search_mft('DC01', ['ZIFylmKF'])
for r in hits:
    out.append(f'DC01: {r["created"]} | {r["path"]}\\{r["name"]}')
if not hits:
    out.append('DC01: NOT FOUND')

# 9. Recon tool on DC02 around 2026-03-08 20:46
out.append('\n--- 9. Recon tool on DC02 (Advanced IP Scanner / ipscan) ~20:46 ---')
hits = search_mft('DC02', ['ipscan','advanced_ip','advanced ip','ipr','nmap','masscan'])
for r in hits:
    out.append(f'DC02: {r["created"]} | {r["path"]}\\{r["name"]}')
# also look by time window
out.append('  (time-window scan 20:45-20:47 UTC on DC02):')
fp = os.path.join(BASE, 'DC02_mft.csv')
try:
    with open(fp, encoding='utf-8', errors='replace') as f:
        for row in csv.DictReader(f):
            t = row.get('Created0x10','')
            if '2026-03-08 20:4' in t:
                fn = row.get('FileName','')
                if any(x in fn.lower() for x in ['.exe','.msi','.zip','.7z']):
                    out.append(f'  {t} | {row.get("ParentPath","")}\\{fn}')
except Exception as e:
    out.append(f'  ERROR: {e}')

# 10. so.aspx and lis.exe on IIS (E: drive — use IIS MFT if parsed, else search wwwroot directly)
out.append('\n--- 10. so.aspx and lis.exe (IIS host) ---')
iis_mft = os.path.join(BASE, 'IIS_mft.csv')
if os.path.exists(iis_mft):
    for term in ['so.aspx','lis.exe']:
        hits = search_mft('IIS', [term])
        for r in hits:
            out.append(f'IIS [{term}]: {r["created"]} | {r["path"]}\\{r["name"]}')
        if not hits:
            out.append(f'IIS [{term}]: NOT IN MFT CSV')
else:
    out.append('IIS_mft.csv not parsed — checking wwwroot directly')
import glob
for pattern in ['so.aspx','lis.exe','*.aspx']:
    found = glob.glob(f'/home/localuser/cases/JackofAllHacks/IIS/E/inetpub/**/{pattern}', recursive=True)
    found += glob.glob(f'/home/localuser/cases/JackofAllHacks/IIS/E/**/{pattern}', recursive=True)
    if found:
        for f in found:
            out.append(f'  FOUND: {f}')
    else:
        out.append(f'  {pattern}: not found in wwwroot tree')

with open('/home/localuser/cases/JackofAllHacks/analysis/mft_verify.txt','w') as f:
    f.write('\n'.join(out))
print(f'wrote {len(out)} lines')
