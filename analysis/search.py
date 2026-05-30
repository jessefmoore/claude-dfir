#!/usr/bin/env python3
import csv, sys, re
csv.field_size_limit(10**9)
# args: csvpath  EID(comma list or 'any')  regex(case-insensitive, optional)  maxrows(optional)
path=sys.argv[1]
eids=sys.argv[2]
rx=sys.argv[3] if len(sys.argv)>3 and sys.argv[3]!='-' else None
mx=int(sys.argv[4]) if len(sys.argv)>4 else 200
eidset=None
if eids!='any':
    eidset=set(eids.split(','))
pat=re.compile(rx,re.I) if rx else None
n=0
with open(path,newline='') as f:
    r=csv.reader(f)
    h=next(r)
    idx={c:i for i,c in enumerate(h)}
    # locate columns
    def g(row,name):
        i=idx.get(name)
        return row[i] if i is not None and i<len(row) else ''
    for row in r:
        eid=g(row,'EventId')
        if eidset is not None and eid not in eidset:
            continue
        payload=g(row,'Payload')
        md=g(row,'MapDescription')
        pd=' | '.join(g(row,'PayloadData%d'%k) for k in range(1,7))
        blob=payload+' '+md+' '+pd
        if pat and not pat.search(blob):
            continue
        n+=1
        print('---REC',n)
        print('TIME',g(row,'TimeCreated'),'EID',eid,'CH',g(row,'ChannelName'),'COMP',g(row,'Computer'))
        print('MAP',md)
        print('USER',g(row,'UserName'),'REMOTE',g(row,'RemoteHost'))
        print('PD',pd)
        if pat:
            # show payload context around match
            m=pat.search(payload)
            if m:
                s=max(0,m.start()-200); e=min(len(payload),m.end()+200)
                print('PAYCTX', payload[s:e])
        if n>=mx:
            print('...MAXROWS hit')
            break
print('TOTAL_MATCHES',n)
