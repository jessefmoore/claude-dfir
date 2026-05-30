#!/usr/bin/env python3
import json
E=[]
for line in open('analysis/cloudtrail_all_events.json'):
    line=line.strip()
    if line: E.append(json.loads(line))
E.sort(key=lambda r:r.get('eventTime',''))
def act(r):
    ui=r.get('userIdentity',{});a=ui.get('arn') or ui.get('userName') or ui.get('type') or '?'
    return a.split('/')[-1]
def first(name):
    for r in E:
        if r.get('eventName')==name: return r.get('eventTime'),act(r),r.get('sourceIPAddress')
    return None
out=[]
# first activity per actor
seen={}
for r in E:
    a=act(r)
    if a not in seen: seen[a]=(r.get('eventTime'),r.get('sourceIPAddress'),r.get('eventName'))
out.append('=== FIRST SEEN PER ACTOR ===')
for a,(t,ip,en) in sorted(seen.items(),key=lambda x:x[1][0]):
    out.append('%s %s %s %s'%(t,a,ip,en))
# users created
out.append('=== CreateUser ===')
for r in E:
    if r.get('eventName')=='CreateUser':
        p=r.get('requestParameters') or {}
        out.append('%s by %s -> %s'%(r.get('eventTime'),act(r),p.get('userName')))
# access keys created
out.append('=== CreateAccessKey ===')
for r in E:
    if r.get('eventName')=='CreateAccessKey':
        p=r.get('requestParameters') or {}
        resp=r.get('responseElements') or {}
        ak=(resp.get('accessKey') or {})
        out.append('%s by %s -> for=%s keyid=%s'%(r.get('eventTime'),act(r),p.get('userName'),ak.get('accessKeyId')))
# login profiles
out.append('=== CreateLoginProfile ===')
for r in E:
    if r.get('eventName')=='CreateLoginProfile':
        p=r.get('requestParameters') or {}
        out.append('%s by %s -> %s'%(r.get('eventTime'),act(r),p.get('userName')))
# policy attach
out.append('=== AttachUserPolicy ===')
for r in E:
    if r.get('eventName')=='AttachUserPolicy':
        p=r.get('requestParameters') or {}
        out.append('%s by %s -> u=%s pol=%s'%(r.get('eventTime'),act(r),p.get('userName'),str(p.get('policyArn','')).split('/')[-1]))
open('analysis/ct_facts1.txt','w').write('\n'.join(out))
print('ok',len(out))
