import json, collections
E=[json.loads(l) for l in open('analysis/cloudtrail_all_events.json') if l.strip()]
E.sort(key=lambda r:r.get('eventTime',''))
def actor(r):
    ui=r.get('userIdentity',{})
    if ui.get('userName'): return ui['userName']
    if ui.get('type')=='Root': return 'root'
    a=ui.get('arn') or ui.get('type') or '?'
    return str(a).split('/')[-1] if '/' in str(a) else str(a)
o=[]
o.append("===== ALL 10 ConsoleLogin events =====")
for r in E:
    if r.get('eventName')=='ConsoleLogin':
        ad=r.get('additionalEventData') or {}
        re_=(r.get('responseElements') or {}).get('ConsoleLogin')
        o.append("%s | %-10s | ip=%s | mfa=%s | result=%s"%(r['eventTime'],actor(r),r.get('sourceIPAddress'),ad.get('MFAUsed'),re_))
RO=('Describe','List','Get','Lookup','Head','BatchGet','Search','Estimate','Preview','Check','Generate','Decrypt')
roots=[r for r in E if actor(r)=='root']
rw=[r for r in roots if not r.get('eventName','').startswith(RO)]
o.append("\n===== root: %d total events, %d write/sensitive ====="%(len(roots),len(rw)))
byday=collections.Counter(r['eventTime'][:10] for r in rw)
for d,n in sorted(byday.items()): o.append("  day %s : %d"%(d,n))
o.append("-- root write eventName counts --")
for en,n in collections.Counter(r.get('eventName') for r in rw).most_common(15):
    o.append("  %5d %s"%(n,en))
open('analysis/ct_real.txt','w').write('\n'.join(o))
print("logins+root written")
