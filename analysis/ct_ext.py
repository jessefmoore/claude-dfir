import json, collections
E=[json.loads(l) for l in open('analysis/cloudtrail_all_events.json') if l.strip()]
def ext(ip):
    if not ip or ip.endswith('.amazonaws.com') or ip=='AWS Internal': return False
    if ip.startswith(('10.','172.16.','172.17.','172.18.','172.19.','172.2','172.30.','172.31.','192.168.')): return False
    return True
def actor(r):
    ui=r.get('userIdentity',{}); a=ui.get('userName') or ui.get('arn') or ui.get('type') or '?'
    return str(a).split('/')[-1]
byip=collections.defaultdict(lambda:{'n':0,'act':collections.Counter(),'t0':'~','t1':''})
for r in E:
    ip=r.get('sourceIPAddress')
    if not ext(ip): continue
    d=byip[ip]; d['n']+=1; d['act'][actor(r)]+=1
    t=r.get('eventTime','')
    if d['t0']=='~' or t<d['t0']: d['t0']=t
    if t>d['t1']: d['t1']=t
out=[]
for ip,d in sorted(byip.items(), key=lambda x:-x[1]['n']):
    out.append('%-16s n=%-5d %s..%s acts=%s'%(ip,d['n'],d['t0'][5:16],d['t1'][5:16],dict(d['act'].most_common(4))))
open('analysis/ct_ext_ips.txt','w').write('\n'.join(out))
print('\n'.join(out))
