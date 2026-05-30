#!/usr/bin/env python3
import json, collections
E=[]
for line in open('analysis/cloudtrail_all_events.json'):
    line=line.strip()
    if line: E.append(json.loads(line))
E.sort(key=lambda r:r.get('eventTime',''))

def actor(r):
    ui=r.get('userIdentity',{})
    a=ui.get('userName') or ui.get('arn') or ui.get('type') or '?'
    if a and 'arn' in str(a): a=str(a).split('/')[-1]
    return a

# Read-only / noisy events to suppress for the "write" timeline
READONLY_PREFIX=('Describe','List','Get','Lookup','Head','BatchGet','Search','Estimate','Preview','Check','Decrypt','Generate')

by_event=collections.Counter(r.get('eventName') for r in E)
by_actor=collections.Counter(actor(r) for r in E)
by_ip=collections.Counter(r.get('sourceIPAddress') for r in E)
by_ua=collections.Counter((r.get('userAgent','') or '')[:50] for r in E)
errs=collections.Counter(r.get('errorCode') for r in E if r.get('errorCode'))

def top(c,n): return '\n'.join('%6d  %s'%(v,k) for k,v in c.most_common(n))

with open('analysis/cloudtrail_summary.txt','w') as o:
    o.write('TOTAL EVENTS: %d\n'%len(E))
    o.write('TIME RANGE: %s -> %s\n'%(E[0]['eventTime'],E[-1]['eventTime']))
    o.write('\n=== TOP ACTORS ===\n'+top(by_actor,25))
    o.write('\n\n=== TOP SOURCE IPs ===\n'+top(by_ip,25))
    o.write('\n\n=== TOP USER AGENTS ===\n'+top(by_ua,20))
    o.write('\n\n=== ERROR CODES ===\n'+top(errs,20))
    o.write('\n\n=== TOP EVENT NAMES ===\n'+top(by_event,40))
print('summary written')
