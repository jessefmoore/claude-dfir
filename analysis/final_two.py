import gzip,json,glob,csv,re,collections
o=[]
# ---- (A) the 3 non-sample GuardDuty 03-08 findings, FULL detail ----
F=[]
for fp in glob.glob('cloud/guardduty/**/*.jsonl.gz',recursive=True):
    try:
        with gzip.open(fp,'rt',errors='replace') as fh:
            for line in fh:
                if line.strip(): F.append(json.loads(line))
    except: pass
o.append("===== GuardDuty findings NOT flagged sample =====")
for f in F:
    ai=(f.get('service') or {}).get('additionalInfo') or {}
    if ai.get('sample') is True: continue
    svc=f.get('service') or {}; act=svc.get('action') or {}
    ip=''
    for k,a in act.items():
        if isinstance(a,dict):
            rd=a.get('remoteIpDetails') or {}
            ip=ip or rd.get('ipAddressV4') or rd.get('ipAddressV2') or ''
    res=f.get('resource') or {}
    ak=res.get('accessKeyDetails') or {}
    o.append("%s | sev%s | %s"%((f.get('updatedAt') or f.get('createdAt') or '')[:19],f.get('severity'),f.get('type')))
    o.append("   user=%s  remoteIP=%s  first=%s last=%s count=%s"%(
        ak.get('userName'),ip,(svc.get('eventFirstSeen') or '')[:19],(svc.get('eventLastSeen') or '')[:19],svc.get('count')))
o.append("(total non-sample findings: %d)"%sum(1 for f in F if not ((f.get('service') or {}).get('additionalInfo') or {}).get('sample')))

# ---- (B) WS 4624 authoritative: per (srcIP, hostname, user, logontype) ----
for S in ['WS01','WS02']:
    o.append("\n===== %s 4624 logons from attacker-net/SVR01 (host|user|type = count) ====="%S)
    c=collections.Counter()
    f=open('exports/%s_evtx.csv'%S,encoding='utf-8',errors='replace')
    for row in csv.DictReader(f):
        if row.get('EventId')!='4624': continue
        rh=row.get('RemoteHost') or ''
        m=re.search(r'(198\.51\.100\.\d+|10\.3\.10\.12)',rh)
        if not m: continue
        host=rh.split('(')[0].strip()
        user=(row.get('PayloadData1') or '')
        ty=(row.get('PayloadData2') or '')
        c[(m.group(1),host,user.replace('Target: ',''),ty)]+=1
    for k,n in c.most_common(20):
        o.append("  %s | %s | %s | %s = %d"%(k[0],k[1],k[2],k[3],n))
open('analysis/final_two.txt','w').write('\n'.join(o))
print('\n'.join(o))
