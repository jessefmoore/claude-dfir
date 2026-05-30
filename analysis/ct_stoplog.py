import json
E=[json.loads(l) for l in open('analysis/cloudtrail_all_events.json') if l.strip()]
E.sort(key=lambda r:r.get('eventTime',''))
def actor(r):
    ui=r.get('userIdentity',{})
    if ui.get('userName'): return ui['userName']
    if ui.get('type')=='Root': return 'root'
    a=ui.get('arn') or ui.get('type') or '?'
    return str(a).split('/')[-1] if '/' in str(a) else str(a)
o=[]
for r in E:
    en=r.get('eventName')
    if en in ('StopLogging','DeleteTrail','UpdateTrail','PutEventSelectors','DeleteUser','DeactivateMFADevice','PutBucketPolicy','PutBucketAcl'):
        o.append("%s | %s | actor=%s | ip=%s | mfa? | params=%s"%(
            r['eventTime'],en,actor(r),r.get('sourceIPAddress'),
            json.dumps(r.get('requestParameters'))[:220]))
open('analysis/ct_stoplog.txt','w').write('\n'.join(o) if o else 'NONE')
print("rows",len(o))
