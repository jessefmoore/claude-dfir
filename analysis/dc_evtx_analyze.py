#!/usr/bin/env python3
import csv, collections, sys, glob, io

FILES = {'DC01':'exports/DC01_security.csv','DC02':'exports/DC02_security.csv'}
INTEREST = {'1102':'SecurityLogCleared','4720':'UserCreated','4722':'UserEnabled','4724':'PwReset',
'4725':'UserDisabled','4726':'UserDeleted','4738':'UserChanged','4728':'AddToGlobalGroup',
'4732':'AddToLocalGroup','4756':'AddToUniversalGroup','4727':'GlobalGroupCreated',
'4672':'SpecialPrivs','4673':'PrivUse','4768':'TGT','4769':'TGS','4771':'PreAuthFail',
'4625':'LogonFail','4648':'ExplicitCreds','4697':'ServiceInstalled','7045':'ServiceInstalled',
'4776':'NTLMAuth','5140':'ShareAccess','5145':'ShareDetail'}

def col(row, *names):
    for n in names:
        if n in row and row[n]: return row[n]
    return ''

out=[]
for host,fp in FILES.items():
    try:
        f=open(fp, encoding='utf-8', errors='replace')
    except Exception as e:
        out.append('%s: CANNOT OPEN %s'%(host,e)); continue
    r=csv.DictReader(f)
    eid_count=collections.Counter()
    rows=[]
    tmin=tmax=None
    for row in r:
        eid=col(row,'EventId')
        eid_count[eid]+=1
        t=col(row,'TimeCreated')
        if t:
            tmin=t if tmin is None or t<tmin else tmin
            tmax=t if tmax is None or t>tmax else tmax
        if eid in INTEREST:
            rows.append((t,eid,col(row,'MapDescription'),col(row,'UserName'),
                         col(row,'RemoteHost'),col(row,'PayloadData1'),col(row,'PayloadData2'),
                         col(row,'PayloadData3')))
    out.append('\n===== %s : %s total rows, %s -> %s ====='%(host,sum(eid_count.values()),tmin,tmax))
    out.append('-- interesting EID counts --')
    for e,n in sorted(eid_count.items(), key=lambda x:-x[1]):
        if e in INTEREST:
            out.append('  %5d  %s %s'%(n,e,INTEREST[e]))
    # detail for the highest-signal IDs
    rows.sort(key=lambda x:(x[0] or ''))
    out.append('-- detail (1102/4720/4722/4724/4728/4732/4756/4726/7045/4697) --')
    HOT={'1102','4720','4722','4724','4728','4732','4756','4726','4725','7045','4697','4738'}
    for t,eid,md,un,rh,p1,p2,p3 in rows:
        if eid in HOT:
            out.append('  %s | %s %s | user=%s | %s | %s | %s'%(t,eid,INTEREST.get(eid,''),un,(p1 or '')[:60],(p2 or '')[:50],(p3 or '')[:40]))

open('analysis/dc_security_digest.txt','w').write('\n'.join(out))
print('done; wrote analysis/dc_security_digest.txt (%d lines)'%len(out))
