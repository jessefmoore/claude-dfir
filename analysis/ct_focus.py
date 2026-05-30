import json
E=[json.loads(l) for l in open('analysis/cloudtrail_all_events.json') if l.strip()]
E.sort(key=lambda r:r.get('eventTime',''))
def actor(r):
    ui=r.get('userIdentity',{}); a=ui.get('userName') or ui.get('arn') or ui.get('type') or '?'
    return str(a).split('/')[-1]
o=[]
o.append("===== 198.51.100.77 (attacker-net) — ALL events =====")
for r in E:
    if r.get('sourceIPAddress')=='198.51.100.77':
        p=r.get('requestParameters')
        o.append("%s | %s | %s | err=%s | params=%s"%(r['eventTime'],r.get('eventName'),actor(r),r.get('errorCode'),json.dumps(p)[:200] if p else '-'))
# Any other 198.51.100.* or known attacker IPs
o.append("\n===== other 198.51.100.* / 173.230.136.180 =====")
for r in E:
    ip=r.get('sourceIPAddress','')
    if ip.startswith('198.51.100.') and ip!='198.51.100.77' or ip=='173.230.136.180':
        o.append("%s | %s | %s | %s"%(r['eventTime'],r.get('eventName'),actor(r),ip))
# root sensitive/write actions (non read-only)
o.append("\n===== root@216.82.9.162 — WRITE/sensitive eventNames (counts) =====")
import collections
RO=('Describe','List','Get','Lookup','Head','BatchGet','Search','Estimate','Preview','Check','Generate','Decrypt')
wc=collections.Counter()
for r in E:
    if actor(r)!='root': continue
    en=r.get('eventName','')
    if en.startswith(RO): continue
    wc[en]+=1
for en,n in wc.most_common(40):
    o.append("%5d  %s"%(n,en))
open('analysis/ct_focus.txt','w').write('\n'.join(o))
print("lines",len(o))
