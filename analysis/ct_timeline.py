#!/usr/bin/env python3
import json
events=[]
with open('analysis/cloudtrail_all_events.json') as f:
    for line in f:
        line=line.strip()
        if line: events.append(json.loads(line))
events.sort(key=lambda r: r.get('eventTime',''))
def actor(r):
    ui=r.get('userIdentity',{})
    a=ui.get('arn') or ui.get('userName') or ui.get('type') or '?'
    return a.split('/')[-1][:14]
SKIP={'DescribeInstances','GetCallerIdentity','DescribeSecurityGroups','DescribeVpcs',
'DescribeSnapshots','DescribeVolumes','DescribeInstanceAttribute','ListUsers','ListBuckets',
'ListSecrets','ListAccessKeys','GetBucketAcl','DescribeRegions','DescribeAvailabilityZones',
'DescribeNetworkInterfaces','DescribeSubnets','DescribeImages','DescribeAddresses'}
lines=[]
for r in events:
    en=r.get('eventName','')
    if en in SKIP and not r.get('errorCode'): continue
    t=r.get('eventTime','')[11:19]
    ip=r.get('sourceIPAddress','')[:15]
    p=r.get('requestParameters') or {}
    extra=''
    if isinstance(p,dict):
        for k in ['userName','policyArn','policyName','roleName','bucketName','key','secretId','instanceType','groupName','snapshotId']:
            if k in p:
                v=str(p[k])
                if 'arn' in str(p[k]): v=str(p[k]).split('/')[-1]
                extra+=' %s=%s'%(k[:3],v[:22])
    err='!'+r.get('errorCode','') if r.get('errorCode') else ''
    lines.append('%s %-20s %-14s %-15s%s%s'%(t,en[:20],actor(r),ip,err,extra))
print('\n'.join(lines))
print('\n--- %d high-signal events ---'%len(lines))
