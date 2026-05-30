import gzip,json,glob
F=[]
for fp in glob.glob('cloud/guardduty/**/*.jsonl.gz',recursive=True):
    try:
        with gzip.open(fp,'rt',errors='replace') as fh:
            for line in fh:
                if line.strip(): F.append(json.loads(line))
    except: pass
o=[]
for f in F:
    t=(f.get('updatedAt') or f.get('createdAt') or '')
    if t[:10]!='2026-03-08': continue
    svc=f.get('service') or {}; ai=svc.get('additionalInfo') or {}; act=svc.get('action') or {}
    res=f.get('resource') or {}; ak=res.get('accessKeyDetails') or {}
    api=''; ip=''; caller=''
    a=act.get('awsApiCallAction') or {}
    api=a.get('api'); 
    rd=a.get('remoteIpDetails') or {}; ip=rd.get('ipAddressV4') or rd.get('ipAddressV2')
    org=rd.get('organization') or {}
    o.append("type=%s sev=%s"%(f.get('type'),f.get('severity')))
    o.append("  time=%s sample=%s count=%s"%(t[:19], ai.get('sample'), svc.get('count')))
    o.append("  user=%s api=%s remoteIP=%s org=%s"%(ak.get('userName'),api,ip,org.get('org')))
    o.append("  title=%s"%(f.get('title') or '')[:100])
open('analysis/gd_0308.txt','w').write('\n'.join(o))
print('\n'.join(o))
