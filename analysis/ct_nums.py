import json, collections
E=[json.loads(l) for l in open('analysis/cloudtrail_all_events.json') if l.strip()]
def actor(r):
    ui=r.get('userIdentity',{}); a=ui.get('userName') or ui.get('arn') or ui.get('type') or '?'
    return str(a).split('/')[-1]
RO=('Describe','List','Get','Lookup','Head','BatchGet','Search','Estimate','Preview','Check','Generate','Decrypt')
res={}
res['cloud_admin_events']=sum(1 for r in E if actor(r)=='cloud_admin')
# root writes on 03-08, and their source IPs
rootw=[r for r in E if actor(r)=='root' and not r.get('eventName','').startswith(RO)]
res['root_writes_total']=len(rootw)
res['root_writes_0308']=sum(1 for r in rootw if r['eventTime'][:10]=='2026-03-08')
ips=collections.Counter(r.get('sourceIPAddress') for r in rootw if r['eventTime'][:10]=='2026-03-08')
res['root_write_0308_ips']=dict(ips.most_common(5))
# root writes on 03-08 by hour
hr=collections.Counter(r['eventTime'][11:13] for r in rootw if r['eventTime'][:10]=='2026-03-08')
res['root_write_0308_byhour']=dict(sorted(hr.items()))
# top root write event names on 03-08
en=collections.Counter(r.get('eventName') for r in rootw if r['eventTime'][:10]=='2026-03-08')
res['root_write_0308_top']=dict(en.most_common(8))
open('analysis/ct_nums.txt','w').write(json.dumps(res,indent=1))
print("ok")
