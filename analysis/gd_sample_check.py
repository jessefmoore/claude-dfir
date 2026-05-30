import gzip,json,glob,collections
F=[]
for fp in glob.glob('cloud/guardduty/**/*.jsonl.gz',recursive=True):
    try:
        with gzip.open(fp,'rt',errors='replace') as fh:
            for line in fh:
                if line.strip(): F.append(json.loads(line))
    except: pass
out=[]
out.append("total findings: %d"%len(F))
# sample flag in service.additionalInfo
def is_sample(f):
    ai=(f.get('service') or {}).get('additionalInfo') or {}
    if ai.get('sample') is True: return True
    if 'sample' in json.dumps(ai).lower(): return True
    if 'sample' in (f.get('title') or '').lower(): return True
    return False
out.append("flagged sample: %d"%sum(1 for f in F if is_sample(f)))
ips=collections.Counter()
days=collections.Counter()
for f in F:
    days[(f.get('updatedAt') or f.get('createdAt') or '')[:10]]+=1
    svc=f.get('service') or {}; act=svc.get('action') or {}
    for k,a in act.items():
        if isinstance(a,dict):
            rd=a.get('remoteIpDetails') or {}
            ip=rd.get('ipAddressV4') or rd.get('ipAddressV2')
            if ip: ips[ip]+=1
out.append("distinct remote IPs: %s"%dict(ips.most_common(10)))
out.append("findings per day: %s"%dict(sorted(days.items())))
# 03-08 findings only
f08=[f for f in F if (f.get('updatedAt') or f.get('createdAt') or '')[:10]=='2026-03-08']
out.append("03-08 findings: %d"%len(f08))
for f in f08[:15]:
    out.append("  sev%s %s"%(f.get('severity'),f.get('type')))
open('analysis/gd_sample_check.txt','w').write('\n'.join(out))
print('\n'.join(out))
