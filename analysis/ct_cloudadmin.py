import json, collections
E=[json.loads(l) for l in open('analysis/cloudtrail_all_events.json') if l.strip()]
E.sort(key=lambda r:r.get('eventTime',''))
def actor(r):
    ui=r.get('userIdentity',{}); a=ui.get('userName') or ui.get('arn') or ui.get('type') or '?'
    return str(a).split('/')[-1]
o=[]
# 1) Everything done BY cloud_admin (any IP)
o.append("===== actor=cloud_admin — all events =====")
for r in E:
    if actor(r)=='cloud_admin':
        o.append("%s | %s | ip=%s | err=%s"%(r['eventTime'],r.get('eventName'),r.get('sourceIPAddress'),r.get('errorCode')))
# 2) root write activity per DAY (to test automation vs attack)
o.append("\n===== root WRITE events per day (UploadServerCertificate/CreateAccessKey/PutUserPolicy) =====")
RO=('Describe','List','Get','Lookup','Head','BatchGet','Search','Estimate','Preview','Check','Generate','Decrypt')
byday=collections.Counter()
for r in E:
    if actor(r)!='root': continue
    if r.get('eventName','').startswith(RO): continue
    byday[r['eventTime'][:10]]+=1
for d,n in sorted(byday.items()):
    o.append("%s  %d"%(d,n))
# 3) all events on 2026-03-08 from 19:00-23:00 that are writes, any actor, summarised
o.append("\n===== 2026-03-08 19:00-23:00 WRITE events (non-root-noise), any actor =====")
for r in E:
    t=r.get('eventTime','')
    if not (t>='2026-03-08T19:00' and t<='2026-03-08T23:00'): continue
    en=r.get('eventName','')
    if en.startswith(RO): continue
    a=actor(r)
    o.append("%s | %-22s | %-14s | %s"%(t[11:19],en,a,r.get('sourceIPAddress')))
open('analysis/ct_cloudadmin.txt','w').write('\n'.join(o))
print("lines",len(o))
