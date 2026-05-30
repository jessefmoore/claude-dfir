#!/usr/bin/env python3
import json, collections

events=[]
with open('analysis/cloudtrail_all_events.json') as f:
    for line in f:
        line=line.strip()
        if line:
            events.append(json.loads(line))

events.sort(key=lambda r: r.get('eventTime',''))

def actor(r):
    ui=r.get('userIdentity',{})
    return ui.get('arn') or ui.get('userName') or ui.get('type') or ui.get('accountId') or '?'

by_event=collections.Counter()
by_actor=collections.Counter()
by_ip=collections.Counter()
by_ua=collections.Counter()
errors=collections.Counter()
for r in events:
    by_event[r.get('eventName')]+=1
    by_actor[actor(r)]+=1
    by_ip[r.get('sourceIPAddress')]+=1
    by_ua[r.get('userAgent','')[:60]]+=1
    if r.get('errorCode'):
        errors[r.get('errorCode')]+=1

def dump(title, counter, n=40):
    print('\n### %s'%title)
    for k,v in counter.most_common(n):
        print('%5d  %s'%(v,k))

print('TOTAL EVENTS: %d'%len(events))
print('TIME RANGE: %s -> %s'%(events[0].get('eventTime'), events[-1].get('eventTime')))
dump('EVENT NAMES', by_event)
dump('ACTORS (userIdentity)', by_actor)
dump('SOURCE IPs', by_ip)
dump('USER AGENTS', by_ua)
dump('ERROR CODES', errors)

# Interesting / high-signal API calls
HIGH=['CreateUser','CreateAccessKey','AttachUserPolicy','AttachRolePolicy','PutUserPolicy','PutRolePolicy',
'CreateLoginProfile','UpdateLoginProfile','CreateRole','AssumeRole','PutBucketPolicy','PutBucketAcl',
'GetObject','PutObject','DeleteObject','ListBuckets','CreatePolicyVersion','CreatePolicy',
'ConsoleLogin','GetCallerIdentity','RunInstances','CreateKeyPair','AuthorizeSecurityGroupIngress',
'DeleteTrail','StopLogging','PutEventSelectors','CreateAccessKey','ModifyImageAttribute','ModifySnapshotAttribute',
'CreateSnapshot','SharedSnapshot','UpdateAssumeRolePolicy','AddUserToGroup','DeactivateMFADevice',
'CreateFunction','UpdateFunctionCode','GetSecretValue','BatchGetSecretValue','ListSecrets','Decrypt',
'DeleteBucket','PutBucketVersioning','GetBucketAcl','CreateBucket']
print('\n\n========== HIGH-SIGNAL EVENT TIMELINE (UTC) ==========')
for r in events:
    en=r.get('eventName')
    if en in HIGH or r.get('errorCode'):
        params=r.get('requestParameters') or {}
        # compact key params
        ps=''
        if isinstance(params,dict):
            keys=['userName','policyArn','policyName','roleName','bucketName','key','accessKeyId','instanceType','functionName','secretId','groupName']
            kv=[(k,params[k]) for k in keys if k in params]
            ps='; '.join('%s=%s'%(k,v) for k,v in kv)
        err=(' ERROR=%s'%r.get('errorCode')) if r.get('errorCode') else ''
        print('%s | %-22s | %s | %s%s %s'%(
            r.get('eventTime'), en, r.get('sourceIPAddress'), actor(r)[:55], err, ps))
