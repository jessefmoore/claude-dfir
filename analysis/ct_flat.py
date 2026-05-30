import json, collections
E=[json.loads(l) for l in open('analysis/cloudtrail_all_events.json') if l.strip()]
def actor(r):
    ui=r.get('userIdentity',{}); a=ui.get('userName') or ui.get('arn') or ui.get('type') or '?'
    return str(a).split('/')[-1]
RO=('Describe','List','Get','Lookup','Head','BatchGet','Search','Estimate','Preview','Check','Generate','Decrypt')
rootw=[r for r in E if actor(r)=='root' and not r.get('eventName','').startswith(RO) and r['eventTime'][:10]=='2026-03-08']
L=[]
ipc=collections.Counter(r.get('sourceIPAddress') for r in rootw)
for ip,n in ipc.most_common(6): L.append("IP %s %d"%(ip,n))
hr=collections.Counter(r['eventTime'][11:13] for r in rootw)
for h,n in sorted(hr.items()): L.append("HR %s %d"%(h,n))
enc=collections.Counter(r.get('eventName') for r in rootw)
for en,n in enc.most_common(8): L.append("EV %s %d"%(en,n))
open('analysis/ct_flat.txt','w').write('\n'.join(L))
print("done")
