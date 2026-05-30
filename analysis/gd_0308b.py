import gzip,json,glob
F=[]
for fp in glob.glob('cloud/guardduty/**/*.jsonl.gz',recursive=True):
    try:
        with gzip.open(fp,'rt',errors='replace') as fh:
            for line in fh:
                if line.strip(): F.append(json.loads(line))
    except: pass
rows=[]
for f in F:
    t=(f.get('updatedAt') or f.get('createdAt') or '')
    if t[:10]!='2026-03-08': continue
    svc=f.get('service') or {}; ai=svc.get('additionalInfo') or {}; act=svc.get('action') or {}
    ak=(f.get('resource') or {}).get('accessKeyDetails') or {}
    a=act.get('awsApiCallAction') or {}
    rd=a.get('remoteIpDetails') or {}
    ip=rd.get('ipAddressV4') or rd.get('ipAddressV2') or '-'
    rows.append("sev%s sample=%s user=%s api=%s ip=%s type=%s"%(
        f.get('severity'),ai.get('sample'),ak.get('userName'),a.get('api'),ip,f.get('type').split('/')[-1]))
open('analysis/gd_0308b.txt','w').write('\n'.join('%d) %s'%(i+1,r) for i,r in enumerate(rows)))
