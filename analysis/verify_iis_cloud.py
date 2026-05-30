import json, collections
E=[json.loads(l) for l in open('analysis/cloudtrail_all_events.json') if l.strip()]
E.sort(key=lambda r:r.get('eventTime',''))
o=[]
# everything from 212.8.249.213
sub=[r for r in E if r.get('sourceIPAddress')=='212.8.249.213']
o.append("=== CloudTrail events from 212.8.249.213: %d ==="%len(sub))
for r in sub:
    ui=r.get('userIdentity',{})
    arn=ui.get('arn') or ui.get('type') or ''
    o.append("%s | %s | %s | %s"%(r['eventTime'][:19], r.get('eventName'), arn.split('/')[-1] if '/' in arn else arn, r.get('errorCode') or ''))
# what identity/role? show first full userIdentity
if sub:
    o.append("\nfull userIdentity[0]: %s"%json.dumps(sub[0].get('userIdentity'))[:400])
# distinct event names from that IP
o.append("\nevent name counts: %s"%dict(collections.Counter(r.get('eventName') for r in sub)))
# Was there an AssumeRole / GetSessionToken for iisserver role anywhere?
o.append("\n=== events mentioning iisserver / iis role (any IP) ===")
for r in E:
    blob=json.dumps(r.get('userIdentity',{}))+json.dumps(r.get('requestParameters') or {})
    if 'iisserver' in blob.lower() or 'iis_server' in blob.lower() or 'iam_role_iis' in blob.lower():
        o.append("%s | %s | ip=%s"%(r['eventTime'][:19], r.get('eventName'), r.get('sourceIPAddress')))
        if len([x for x in o if x.startswith('20')])>40: break
open('analysis/verify_iis_cloud.txt','w').write('\n'.join(o))
print('\n'.join(o[:60]))
