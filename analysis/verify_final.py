import gzip,json,glob,csv,re,collections
# (A) the 3 GuardDuty 03-08 findings: sample? ip? account?
F=[]
for fp in glob.glob('cloud/guardduty/**/*.jsonl.gz',recursive=True):
    try:
        with gzip.open(fp,'rt',errors='replace') as fh:
            for line in fh:
                if line.strip(): F.append(json.loads(line))
    except: pass
o=["=== GuardDuty 03-08 findings detail ==="]
for f in F:
    if (f.get('updatedAt') or f.get('createdAt') or '')[:10]!='2026-03-08': continue
    ai=(f.get('service') or {}).get('additionalInfo') or {}
    samp=ai.get('sample')
    res=f.get('resource') or {}
    ak=(res.get('accessKeyDetails') or {})
    o.append("sev%s %s | sample=%s | user=%s | ip(remote)=%s"%(
        f.get('severity'),f.get('type'),samp,ak.get('userName'),
        json.dumps((f.get('service') or {}).get('action') or {})[:120]))
# (B) WS 4624 logon-type breakdown, robust: dump raw fields of a couple 4624 rows w/ 198/SVR ip
o.append("\n=== WS 4624 column probe (first 3 rows mentioning 198.51.100 anywhere) ===")
for S in ['WS01']:
    f=open('exports/%s_evtx.csv'%S,encoding='utf-8',errors='replace')
    seen=0
    for row in csv.DictReader(f):
        if row.get('EventId')!='4624': continue
        joined=','.join((row.get(c) or '') for c in row)
        if '198.51.100' not in joined: continue
        o.append("RemoteHost=[%s] PD1=[%s] PD2=[%s] PD3=[%s]"%(row.get('RemoteHost'),(row.get('PayloadData1') or '')[:60],(row.get('PayloadData2') or '')[:60],(row.get('PayloadData3') or '')[:40]))
        seen+=1
        if seen>=3: break
# (C) WS 4624 counts by RemoteHost containing 198/10.3.10.12
o.append("\n=== WS 4624 RemoteHost IP counts (attacker-net / SVR01) ===")
for S in ['WS01','WS02']:
    c=collections.Counter()
    f=open('exports/%s_evtx.csv'%S,encoding='utf-8',errors='replace')
    for row in csv.DictReader(f):
        if row.get('EventId')!='4624': continue
        rh=row.get('RemoteHost') or ''
        m=re.search(r'(198\.51\.100\.\d+|10\.3\.10\.\d+)',rh)
        if m: c[m.group(1)]+=1
    o.append("%s: %s"%(S,dict(c.most_common(12))))
open('analysis/verify_final.txt','w').write('\n'.join(o))
print('\n'.join(o))
